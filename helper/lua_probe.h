// ---------------------------------------------------------------------------
// Target-process Lua VM introspection (lua_state / lua_walk) and remote
// execution (call_func / lua_exec).
//
// Included by hmkpm_cli.c after raw_read_exact / vma_table_load /
// module_lookup / now_ms / json_escape are in scope.
//
// Layout provenance
//
// The offsets used here were derived from the disassembly of the target's own
// lua_newstate (RVA 0xa1ef2a8) and luaL_newstate (RVA 0xa242e78) in
// liblibGameApp.so, not from a textbook. The instruction that establishes each
// field is recorded in profiles/luajit-2.1-gc64.json ("src").
//
// The decisive one: luaL_newstate does
//     ldr x8, [x19, #0x10]        ; x19 = lua_State*
//     str x9, [x8, #0x160]        ; write into a global_State field
// so lua_State+0x10 is l_G. Treating +0x10 as the stack base (as the 5.x
// layout does) is what made every earlier probe fail on this engine.
//
// Pointer width
//
// This is LuaJIT in GC64 mode: a TValue is 8 bytes, a pointer is (lo, hi) u32
// words, and the value is hi<<32|lo with the heap base folded back in when bit
// 47 is set. Every pointer read goes through pointer_codec(); reading a plain
// u64 at those slots mixes the tag into the address.
//
// lua_state / lua_walk are READ-ONLY.
// call_func / lua_exec write to the target through ptrace and restore every
// register and code byte before detaching.
// ---------------------------------------------------------------------------

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <asm/ptrace.h>
#include <sys/uio.h>
#include <elf.h>

#define LUA_PROBE_HEAD   192
#define LUA_MAX_STATES   16

#define XCALL_TIMEOUT_MS_DEFAULT 5000
#define XCALL_STUB_BYTES 24
#define LUA_EXEC_BUF_MAX (64 * 1024)

// --- offsets, from the disassembly (see profiles/luajit-2.1-gc64.json) ------
#define LS_G              0x10   // luaL_newstate: ldr x8,[x19,#0x10] -> l_G
#define LS_STACK          0x20   // lua_newthread: stp x8,x8,[x20,#0x20]
#define LS_MAXSTACK       0x28   // luaL_newstate: ldr x8,[x19,#0x28]
#define LS_TOP            0x0c   // str xzr,[x0,#0x50] clears the 32-bit index
#define G_REGISTRY        0x88   // stp x19,x9,[x19,#0x88] seeds registry
#define G_STRT            0x18
#define TAB_NODE          0x30   // GC64: node ptr after asize(0x20)/hmask(0x28)
#define TAB_ASIZE         0x20
#define TAB_HMASK         0x28
#define STR_LEN           0x08   // GC64: next(4)/hash(4)/len(4)/hash(4)
#define STR_DATA          0x10

// TValue tags (hi word). Pointer TValues carry a plain address; numbers use
// 0xFFFFFFFF for int32 and the double type tag otherwise.
#define LJT_TAG_INT32     0xFFFFFFFFu
#define LJT_TAG_NIL       0xFFFFFFFFFFFFu

enum { LT_NIL = 0, LT_BOOL = 1, LT_NUMBER = 2, LT_STR = 3, LT_TAB = 4,
       LT_FUNC = 5, LT_CDATA = 6, LT_UDATA = 7, LT_THREAD = 8 };

struct lua_vm {
    uint64_t L;
    uint64_t G;
    uint64_t registry;   // address of the registry TValue array
    uint64_t globals;    // Table* of _G
    int      gc64;       // 1 when the engine uses compressed pointers
    char     module[128];
    uint64_t module_base;
};

struct lua_entry {
    char     key[128];
    char     type[16];
    uint64_t value;
    char     source[128];
};

// --- pointer codec ---------------------------------------------------------

// Heap base for GC64 pointer reconstruction. Pointers whose bit 47 is set are
// stored as a 47-bit offset; OR-ing the base restores the full address. The
// base is learned from the lua_State itself, which is always a full pointer in
// a register and therefore in the range the heap is allocated from.
static uint64_t g_gc_base;

// lua_capture: break on luaL_newstate's `ret` and read x0.
//
// luaL_newstate (RVA 0xa242e78) ends:
//   a242ef8  mov x0, x19        ; x0 = the new lua_State
//   a242efc  ldp x19, x30, [sp], #0x10
//   a242f00  ret
// so an exec breakpoint at +0xa242f00 sees x0 holding the state.
//
// Caveat that shaped this design: luaL_newstate runs once, within tens of
// milliseconds of the module being mapped, which is usually faster than a
// ptrace attach. The command therefore reports honestly when it misses and
// tells the operator to re-run during startup.
#define LUAL_NEWSTATE_RET 0xa242f00ULL

static uint64_t lua_module_base_of(struct vma_table *vmas, const char *frag) {
    for (uint32_t i = 0; i < vmas->count; i++) {
        const struct vma *v = &vmas->items[i];
        if (!strstr(v->path, frag)) continue;
        if (v->offset != 0) continue;
        if (!strchr(v->perms, 'x')) continue;
        return v->start;
    }
    return 0;
}

static int cmd_lua_capture(int pid, uint32_t duration_ms) {
    struct vma_table vmas;
    if (!vma_table_load(pid, &vmas)) { print_error("Cannot read maps", errno); return 1; }
    uint64_t base = lua_module_base_of(&vmas, "liblibGameApp.so");
    if (!base) base = lua_module_base_of(&vmas, "liblua");
    vma_table_free(&vmas);
    if (!base) {
        printf("{\"status\":\"error\",\"pid\":%d,\"message\":\"no Lua module in this "
               "process\"}\n", pid);
        return 1;
    }
    uint64_t ret_addr = base + LUAL_NEWSTATE_RET;
    if (duration_ms == 0 || duration_ms > 3000) duration_ms = 3000;

    char tmp[128];
    snprintf(tmp, sizeof(tmp), "/data/local/tmp/.lua_cap_%d.json", pid);
    int saved = dup(STDOUT_FILENO);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("{\"status\":\"error\",\"pid\":%d,\"message\":\"cannot open capture "
               "buffer\"}\n", pid);
        return 1;
    }
    dup2(fd, STDOUT_FILENO);
    cmd_watch(pid, ret_addr, 4, "exec", duration_ms, 16);
    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
    close(fd);

    FILE *f = fopen(tmp, "r");
    if (!f) { printf("{\"status\":\"error\",\"pid\":%d,\"message\":\"capture buffer "
                     "missing\"}\n", pid); return 1; }
    uint64_t cands[16];
    int ncand = 0;
    char line[2048];
    while (fgets(line, sizeof(line), f) && ncand < 16) {
        char *p = strstr(line, "\"X0\":");
        if (!p) continue;
        p = strstr(p, "0x");
        if (!p) continue;
        cands[ncand++] = strtoull(p + 2, NULL, 16);
    }
    fclose(f);
    unlink(tmp);

    printf("{\"status\":\"ok\",\"pid\":%d,\"module_base\":\"0x%llx\","
           "\"ret_addr\":\"0x%llx\",\"duration_ms\":%u,\"hits\":%d,\"states\":[",
           pid, (unsigned long long)base, (unsigned long long)ret_addr, duration_ms, ncand);

    int reported = 0;
    for (int i = 0; i < ncand; i++) {
        uint64_t G = 0;
        char err[96] = "";
        const char *layout = lua_probe_layout(pid, cands[i], &G, err, sizeof(err));
        if (!layout) continue;
        printf("%s{\"addr\":\"0x%llx\",\"layout\":\"%s\",\"G\":\"0x%llx\"",
               reported ? "," : "", (unsigned long long)cands[i], layout,
               (unsigned long long)G);
        printf("}");
        reported++;
    }
    printf("],\"count\":%d", reported);
    if (!ncand) {
        printf(",\"hint\":\"no hit: luaL_newstate runs once during startup. Restart the "
               "game and run lua_capture again within the first second\"");
    }
    printf("}\n");
    return reported > 0 ? 0 : 1;
}

struct xcall_result {
    uint64_t ret;
    uint64_t cave;
    bool     stubbed;
    char     error[192];
};

struct xcall_session {
    int      pid;
    pid_t    tid;
    bool     attached;
    uint64_t cave;
    uint8_t  backup[XCALL_STUB_BYTES];
    bool     have_backup;
    struct user_pt_regs saved;
};

static int xcall_read_regs(pid_t tid, struct user_pt_regs *regs) {
    struct iovec iov = { .iov_base = regs, .iov_len = sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, tid, (void *)(uintptr_t)NT_PRSTATUS, &iov);
}

static int xcall_write_regs(pid_t tid, const struct user_pt_regs *regs) {
    struct iovec iov = { .iov_base = (void *)regs, .iov_len = sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, tid, (void *)(uintptr_t)NT_PRSTATUS, &iov);
}

// Attach and reap the initial stop. errno distinguishes EPERM (SELinux or a
// parent/child restriction) from ESRCH (thread gone).
static bool xcall_attach(struct xcall_session *s, int pid, pid_t tid) {
    s->pid = pid;
    s->tid = tid;
    if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) != 0) return false;
    int status = 0;
    if (waitpid(tid, &status, __WALL) < 0 || !WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, tid, NULL, (void *)0);
        errno = ECHILD;
        return false;
    }
    s->attached = true;
    // EXITKILL releases the target if this process dies mid-call instead of
    // leaving it frozen under a dead tracer.
    ptrace(PTRACE_SETOPTIONS, tid, NULL, (void *)(uintptr_t)PTRACE_O_EXITKILL);
    return xcall_read_regs(tid, &s->saved) == 0;
}

// Enable (bcr != 0) or clear one hardware execution breakpoint. ARM64 exposes
// 16 slots through NT_ARM_HW_BREAK. Returns the slot, or -1.
static int xcall_hwbp(pid_t tid, uint64_t addr, bool enable) {
    uint64_t regs[32];
    memset(regs, 0, sizeof(regs));
    struct iovec iov = { .iov_base = regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, tid, (void *)(uintptr_t)NT_ARM_HW_BREAK, &iov) != 0)
        return -1;
    int slot = -1;
    for (int i = 0; i < 16; i++) {
        uint64_t bvr = regs[i * 2], bcr = regs[i * 2 + 1];
        if (!enable && bcr && bvr == addr) { slot = i; break; }
        if (enable && !(bcr & 1) && slot < 0) slot = i;
    }
    if (slot < 0) return -1;
    regs[slot * 2] = enable ? addr : 0;
    // E=1, PMC=01 (EL0), BAS=1111 (4 bytes), execute.
    regs[slot * 2 + 1] = enable ? (1u | (1u << 1) | (0xfu << 5)) : 0;
    iov.iov_len = sizeof(regs);
    return ptrace(PTRACE_SETREGSET, tid, (void *)(uintptr_t)NT_ARM_HW_BREAK, &iov) == 0
               ? slot : -1;
}

// Find an existing writable+executable region large enough for the stub.
static bool xcall_find_rwx(struct vma_table *vmas, uint64_t *addr, size_t size) {
    for (uint32_t i = 0; i < vmas->count; i++) {
        const struct vma *v = &vmas->items[i];
        if (v->perms[0] != 'r' || v->perms[1] != 'w' || v->perms[2] != 'x') continue;
        if (v->end - v->start < size) continue;
        if (strstr(v->path, "linker") || strstr(v->path, "vdso")) continue;
        *addr = v->start;
        return true;
    }
    return false;
}

// Map one executable page inside the target through its own mmap syscall. The
// syscall runs from the caller's own return address, so no new RWX mapping of
// code is needed to bootstrap.
static bool xcall_remote_mmap(int pid, pid_t tid, const struct user_pt_regs *saved,
                              uint64_t *out, char *err, size_t err_cap) {
    uint64_t gate = saved->pc;
    uint8_t backup[8];
    bool have = raw_read(pid, gate, backup, sizeof(backup));
    static const uint32_t gate_code[] = { 0xd4000001, 0xd4200000 };  // svc #0 ; brk #0
    if (raw_write(pid, gate, gate_code, sizeof(gate_code)) != 0) {
        snprintf(err, err_cap, "cannot patch a syscall gate at 0x%llx",
                 (unsigned long long)gate);
        return false;
    }

    struct user_pt_regs w = *saved;
    w.regs[8] = 222;                          // __NR_mmap
    w.regs[0] = 0;
    w.regs[1] = 0x20000;                      // 128 KiB
    w.regs[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
    w.regs[3] = MAP_PRIVATE | MAP_ANONYMOUS;
    w.regs[4] = (uint64_t)-1;
    w.regs[5] = 0;
    w.pc = gate;

    bool ok = false;
    if (xcall_write_regs(tid, &w) == 0 &&
        ptrace(PTRACE_SINGLESTEP, tid, NULL, (void *)0) == 0) {
        int status = 0;
        if (waitpid(tid, &status, __WALL) == tid && WIFSTOPPED(status)) {
            struct user_pt_regs after;
            if (xcall_read_regs(tid, &after) == 0) {
                int64_t r = (int64_t)after.regs[0];
                if (r < 0 && r > -4096) {
                    snprintf(err, err_cap, "remote mmap denied (errno %lld)%s",
                             (long long)-r, (int)-r == EACCES ? ": execmem/W^X denied" : "");
                } else if (lp_is_ptr((uint64_t)r)) {
                    *out = (uint64_t)r;
                    ok = true;
                } else {
                    snprintf(err, err_cap, "mmap returned 0x%llx", (unsigned long long)r);
                }
            }
        }
    } else {
        snprintf(err, err_cap, "cannot step the syscall gate: %s", strerror(errno));
    }
    xcall_write_regs(tid, saved);
    if (have) raw_write(pid, gate, backup, sizeof(backup));
    return ok;
}

// Restore everything and detach. Safe to call more than once.
static void xcall_finish(struct xcall_session *s) {
    if (s->attached) {
        xcall_hwbp(s->tid, s->cave + 16, false);
        xcall_write_regs(s->tid, &s->saved);
        ptrace(PTRACE_DETACH, s->tid, NULL, (void *)0);
        s->attached = false;
    }
    if (s->have_backup && s->cave) {
        raw_write(s->pid, s->cave, s->backup, XCALL_STUB_BYTES);
        s->have_backup = false;
    }
}

// Call `func` with up to four integer arguments.
//
// Stub at `cave`:
//   stp x29, x30, [sp, #-16]!   ; preserve the frame chain
//   mov x29, sp
//   blr x9                      ; x9 = func
//   ldp x29, x30, [sp], #16
//   brk #0                      ; @done: hardware breakpoint, never executed
static bool xcall_impl(int pid, pid_t tid, uint64_t func, const uint64_t *args,
                       int argc, uint32_t timeout_ms, uint64_t reuse_page,
                       struct xcall_result *out) {
    memset(out, 0, sizeof(*out));
    struct xcall_session s;
    memset(&s, 0, sizeof(s));

    if (!xcall_attach(&s, pid, tid)) {
        snprintf(out->error, sizeof(out->error),
                 "ptrace attach failed (%s): the target rejects a debugger "
                 "(SELinux domain or parent/child restriction)", strerror(errno));
        return false;
    }

    if (reuse_page) {
        s.cave = reuse_page;
    } else {
        struct vma_table vmas;
        bool have = vma_table_load(pid, &vmas) &&
                    xcall_find_rwx(&vmas, &s.cave, XCALL_STUB_BYTES);
        vma_table_free(&vmas);
        if (!have &&
            !xcall_remote_mmap(pid, tid, &s.saved, &s.cave, out->error, sizeof(out->error))) {
            xcall_finish(&s);
            return false;
        }
    }
    out->cave = s.cave;
    s.have_backup = raw_read(pid, s.cave, s.backup, sizeof(s.backup));

    static const uint32_t stub[] = {
        0xa9bf7bfd,   // stp x29, x30, [sp, #-16]!
        0x910003fd,   // mov x29, sp
        0xd63f0120,   // blr x9
        0xa8c17bfd,   // ldp x29, x30, [sp], #16
        0xd4200000,   // brk #0
    };
    if (raw_write(pid, s.cave, stub, sizeof(stub)) != 0) {
        snprintf(out->error, sizeof(out->error), "cannot write stub to 0x%llx",
                 (unsigned long long)s.cave);
        xcall_finish(&s);
        return false;
    }

    if (xcall_hwbp(tid, s.cave + 16, true) < 0) {
        snprintf(out->error, sizeof(out->error),
                 "no hardware breakpoint slot (all 16 held by another debugger)");
        xcall_finish(&s);
        return false;
    }

    struct user_pt_regs work = s.saved;
    work.pc = s.cave;
    work.regs[9] = func;
    for (int i = 0; i < argc && i < 4; i++) work.regs[i] = args[i];
    if (xcall_write_regs(tid, &work) != 0 ||
        ptrace(PTRACE_CONT, tid, NULL, (void *)0) != 0) {
        snprintf(out->error, sizeof(out->error), "cannot start the call: %s", strerror(errno));
        xcall_finish(&s);
        return false;
    }

    int status = 0;
    int64_t deadline = now_ms() + (int64_t)(timeout_ms ? timeout_ms : XCALL_TIMEOUT_MS_DEFAULT);
    bool stopped = false;
    while (now_ms() < deadline) {
        pid_t w = waitpid(tid, &status, __WALL | WNOHANG);
        if (w == tid) { stopped = true; break; }
        if (w < 0 && errno != EINTR) break;
        usleep(2000);
    }

    if (!stopped) {
        // Still inside the stub: stop the thread so its registers can be put
        // back, then report the timeout. It is never left hijacked.
        kill(tid, SIGSTOP);
        int st = 0;
        if (waitpid(tid, &st, __WALL) == tid && WIFSTOPPED(st)) {
            snprintf(out->error, sizeof(out->error),
                     "the call did not return within %u ms; the thread was "
                     "stopped and its registers restored",
                     timeout_ms ? timeout_ms : XCALL_TIMEOUT_MS_DEFAULT);
        } else {
            snprintf(out->error, sizeof(out->error),
                     "the call timed out and the thread could not be re-stopped");
        }
        xcall_finish(&s);
        return false;
    }

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        struct user_pt_regs after;
        if (xcall_read_regs(tid, &after) == 0) {
            out->ret = after.regs[0];
            out->stubbed = true;
        } else {
            snprintf(out->error, sizeof(out->error), "returned but registers are unreadable");
        }
    } else if (WIFSTOPPED(status)) {
        snprintf(out->error, sizeof(out->error),
                 "the call raised signal %d before returning", WSTOPSIG(status));
    } else if (WIFSIGNALED(status)) {
        snprintf(out->error, sizeof(out->error), "the target died (signal %d) during the call",
                 WTERMSIG(status));
    } else {
        snprintf(out->error, sizeof(out->error), "unexpected wait status 0x%x", status);
    }

    xcall_finish(&s);
    return out->stubbed;
}

static int cmd_call_func(int pid, int tid, uint64_t func, int argc, char **argv,
                         uint32_t timeout_ms) {
    if (argc > 4) {
        print_error("at most 4 arguments (AAPCS64 x0-x3)", E2BIG);
        return 1;
    }
    uint64_t args[4] = {0, 0, 0, 0};
    for (int i = 0; i < argc; i++) args[i] = parse_addr(argv[i]);
    if (tid <= 0) tid = pid;

    struct xcall_result r;
    bool ok = xcall_impl(pid, tid, func, args, argc, timeout_ms, 0, &r);

    printf("{\"status\":\"%s\",\"pid\":%d,\"tid\":%d,\"func\":\"0x%llx\",\"argc\":%d",
           ok ? "ok" : "error", pid, tid, (unsigned long long)func, argc);
    if (r.cave) printf(",\"cave\":\"0x%llx\"", (unsigned long long)r.cave);
    if (ok) printf(",\"retval\":\"0x%llx\",\"retval_dec\":%llu",
                   (unsigned long long)r.ret, (unsigned long long)r.ret);
    if (r.error[0]) {
        printf(",\"message\":\"");
        json_escape(stdout, r.error, strlen(r.error));
        printf("\"");
    }
    printf("}\n");
    return ok ? 0 : 1;
}

// Resolve a dynamic symbol from a module file of the target.
// Reserved for lua_exec once a non-ptrace injection path exists.
__attribute__((unused))
static bool lua_symbol_lookup(struct vma_table *vmas, const char *name, uint64_t *out) {
    for (uint32_t i = 0; i < vmas->count; i++) {
        const struct vma *v = &vmas->items[i];
        if (v->offset != 0 || v->path[0] != '/') continue;
        if (!strstr(v->path, "lua") && !strstr(v->path, "Lua")) continue;

        int fd = open(v->path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        Elf64_Ehdr eh;
        if (pread(fd, &eh, sizeof(eh), 0) != sizeof(eh) ||
            memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_machine != EM_AARCH64) {
            close(fd);
            continue;
        }
        Elf64_Phdr *ph = (Elf64_Phdr *)malloc(sizeof(Elf64_Phdr) * (eh.e_phnum + 1));
        Elf64_Dyn *dyn = NULL;
        if (ph && pread(fd, ph, sizeof(Elf64_Phdr) * eh.e_phnum, eh.e_phoff) > 0) {
            for (int p = 0; p < eh.e_phnum; p++) {
                if (ph[p].p_type != PT_DYNAMIC) continue;
                dyn = (Elf64_Dyn *)malloc(ph[p].p_filesz + sizeof(Elf64_Dyn));
                if (dyn && pread(fd, dyn, ph[p].p_filesz, ph[p].p_offset) <= 0) {
                    free(dyn);
                    dyn = NULL;
                }
                break;
            }
        }
        free(ph);
        if (!dyn) { close(fd); continue; }

        uint64_t symtab = 0, strtab = 0, syment = sizeof(Elf64_Sym), hash = 0;
        for (Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
            if (d->d_tag == DT_SYMTAB) symtab = d->d_un.d_ptr;
            else if (d->d_tag == DT_STRTAB) strtab = d->d_un.d_ptr;
            else if (d->d_tag == DT_SYMENT) syment = d->d_un.d_val;
            else if (d->d_tag == DT_HASH) hash = d->d_un.d_ptr;
        }
        free(dyn);

        uint64_t nsyms = 0;
        if (symtab && strtab > symtab && syment) nsyms = (strtab - symtab) / syment;
        if (hash) {
            uint32_t nchain = 0;
            if (pread(fd, &nchain, 4, (off_t)(hash + 4)) == 4 && nchain) nsyms = nchain;
        }
        if (!symtab || !strtab || !nsyms || nsyms > 200000) { close(fd); continue; }

        Elf64_Sym *syms = (Elf64_Sym *)malloc(syment * nsyms);
        if (!syms) { close(fd); continue; }
        if (pread(fd, syms, syment * nsyms, (off_t)symtab) <= 0) {
            free(syms);
            close(fd);
            continue;
        }
        bool found = false;
        for (uint64_t k = 0; k < nsyms && !found; k++) {
            if (syms[k].st_name == 0) continue;
            if (ELF64_ST_TYPE(syms[k].st_info) != STT_FUNC) continue;
            if (syms[k].st_shndx == SHN_UNDEF) continue;
            char nm[160];
            if (pread(fd, nm, sizeof(nm) - 1, (off_t)(strtab + syms[k].st_name)) <= 0) continue;
            nm[sizeof(nm) - 1] = '\0';
            if (strcmp(nm, name) != 0) continue;
            uint64_t base = 0;
            if (module_lookup(vmas, v->path, &base, NULL, NULL)) {
                *out = base + syms[k].st_value;
                found = true;
            }
        }
        free(syms);
        close(fd);
        if (found) return true;
    }
    return false;
}

// Run a Lua chunk inside the target:
//   luaL_loadbuffer(L, code, len, "@hmkpm_exec") -> status
//   lua_pcall(L, 0, 0, 0)                        -> status
// A chunk error therefore comes back as a status instead of unwinding into the
// game's own call frame.
// lua_exec: run a chunk inside the target.
//
// Not enabled. Two blockers, both documented rather than papered over:
//
//   1. The only remote-call transport available here is ptrace (see xcall_*),
//      and the observed target reacts to a tracer by exiting, so using it would
//      crash the process being analysed.
//   2. Calling luaL_loadbuffer + lua_pcall needs a valid lua_State *and* a
//      correct pcall frame. The lua_State is obtainable via lua_state on a
//      standard 5.4 build, but the LuaJIT layout used by the real target is
//      unverified, and a wrong frame leaves the engine unusable.
//
// The command therefore refuses with a precise reason instead of attempting a
// half-implementation that would corrupt the target.
static int cmd_lua_exec(int pid, const char *code, uint32_t timeout_ms) {
    (void)timeout_ms;
    size_t len = strlen(code);
    if (len == 0) { print_error("empty Lua code", EINVAL); return 1; }
    printf("{\"status\":\"error\",\"supported\":false,\"pid\":%d,"
           "\"code_bytes\":%u,\"message\":\"lua_exec is disabled: running a chunk "
           "requires ptrace injection, which this target's protection reacts to by "
           "exiting the process. Use lua_walk to locate a global, then write_memory "
           "to change its value directly.\"}\n",
           pid, (unsigned)len);
    return 1;
}
