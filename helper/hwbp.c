#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <elf.h>
#include <linux/elf.h>
#include "hwbp.h"

#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x402
#endif
#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH 0x403
#endif
#ifndef TRAP_HWBKPT
#define TRAP_HWBKPT 4
#endif
#ifndef SYS_GETRESGID
#define SYS_GETRESGID 150
#endif
#ifndef SYS_tgkill
#define SYS_tgkill 131
#endif

// ARM64 hardware debug state structure (for ptrace NT_ARM_HW_WATCH / NT_ARM_HW_BREAK)
struct user_hwdebug_state_local {
    uint32_t dbg_info;
    uint32_t pad;
    struct {
        uint64_t addr;
        uint32_t ctrl;
        uint32_t pad;
    } dbg_regs[16];
};

static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static const char *hwbp_reg_name(int r, int is_64) {
    static char buf[16][8];
    static int idx = 0;
    idx = (idx + 1) % 16;
    if (r == 31) return is_64 ? "XZR" : "WZR";
    snprintf(buf[idx], sizeof(buf[idx]), "%c%d", is_64 ? 'X' : 'W', r);
    return buf[idx];
}

static const char *hwbp_base_reg_name(int r) {
    static char buf[16][8];
    static int idx = 0;
    idx = (idx + 1) % 16;
    if (r == 31) return "SP";
    snprintf(buf[idx], sizeof(buf[idx]), "X%d", r);
    return buf[idx];
}

// AArch64 load/store instruction decoder for hardware watchpoint hit reporting
static bool hwbp_decode_insn(uint32_t insn, char *out, size_t out_sz,
                             int *rt_out, int *rn_out, bool *is_store, int *size_bytes) {
    if (rt_out) *rt_out = -1;
    if (rn_out) *rn_out = -1;
    if (is_store) *is_store = false;
    if (size_bytes) *size_bytes = 4;

    // 1. Load/Store Register (unsigned immediate)
    if ((insn & 0x3b200000) == 0x39000000) {
        int size = (insn >> 30) & 3;
        bool l = (insn >> 22) & 1;
        int imm12 = (insn >> 10) & 0xfff;
        int rn = (insn >> 5) & 0x1f;
        int rt = insn & 0x1f;
        int scale = size;
        int offset = imm12 << scale;
        int bytes = 1 << scale;

        if (rt_out) *rt_out = rt;
        if (rn_out) *rn_out = rn;
        if (is_store) *is_store = !l;
        if (size_bytes) *size_bytes = bytes;

        const char *op = l ? "LDR" : "STR";
        int is_64 = (size == 3);
        const char *rt_s = hwbp_reg_name(rt, is_64);
        const char *rn_s = hwbp_base_reg_name(rn);

        if (size == 0) op = l ? "LDRB" : "STRB";
        else if (size == 1) op = l ? "LDRH" : "STRH";

        if (offset == 0) {
            snprintf(out, out_sz, "%s %s, [%s]", op, rt_s, rn_s);
        } else {
            snprintf(out, out_sz, "%s %s, [%s, #0x%x]", op, rt_s, rn_s, offset);
        }
        return true;
    }

    // 2. Load/Store Register (unscaled immediate / pre-post index: LDUR / STUR)
    if ((insn & 0x3b200000) == 0x38000000) {
        int size = (insn >> 30) & 3;
        bool l = (insn >> 22) & 1;
        int simm9 = (insn >> 12) & 0x1ff;
        if (simm9 & 0x100) simm9 |= ~0x1ff;
        int rn = (insn >> 5) & 0x1f;
        int rt = insn & 0x1f;
        int bytes = 1 << size;

        if (rt_out) *rt_out = rt;
        if (rn_out) *rn_out = rn;
        if (is_store) *is_store = !l;
        if (size_bytes) *size_bytes = bytes;

        const char *op = l ? "LDUR" : "STUR";
        int is_64 = (size == 3);
        if (size == 0) op = l ? "LDURB" : "STURB";
        else if (size == 1) op = l ? "LDURH" : "STURH";

        if (simm9 == 0) {
            snprintf(out, out_sz, "%s %s, [%s]", op, hwbp_reg_name(rt, is_64), hwbp_base_reg_name(rn));
        } else {
            snprintf(out, out_sz, "%s %s, [%s, #%d]", op, hwbp_reg_name(rt, is_64), hwbp_base_reg_name(rn), simm9);
        }
        return true;
    }

    // 3. Load/Store Register Pair (LDP / STP)
    if ((insn & 0x7e400000) == 0x28000000 || (insn & 0x7e400000) == 0x29000000) {
        int opc = (insn >> 30) & 3;
        bool l = (insn >> 22) & 1;
        int imm7 = (insn >> 15) & 0x7f;
        if (imm7 & 0x40) imm7 |= ~0x7f;
        int rt2 = (insn >> 10) & 0x1f;
        int rn = (insn >> 5) & 0x1f;
        int rt = insn & 0x1f;
        int is_64 = (opc & 2) != 0;
        int scale = is_64 ? 3 : 2;
        int offset = imm7 << scale;

        if (rt_out) *rt_out = rt;
        if (rn_out) *rn_out = rn;
        if (is_store) *is_store = !l;
        if (size_bytes) *size_bytes = is_64 ? 8 : 4;

        const char *op = l ? "LDP" : "STP";
        const char *rt_s = hwbp_reg_name(rt, is_64);
        const char *rt2_s = hwbp_reg_name(rt2, is_64);
        const char *rn_s = hwbp_base_reg_name(rn);

        if (offset == 0) {
            snprintf(out, out_sz, "%s %s, %s, [%s]", op, rt_s, rt2_s, rn_s);
        } else {
            snprintf(out, out_sz, "%s %s, %s, [%s, #%d]", op, rt_s, rt2_s, rn_s, offset);
        }
        return true;
    }

    // 4. Load/Store Register (register offset)
    if ((insn & 0x3b200c00) == 0x38200800) {
        int size = (insn >> 30) & 3;
        bool l = (insn >> 22) & 1;
        int rm = (insn >> 16) & 0x1f;
        int rn = (insn >> 5) & 0x1f;
        int rt = insn & 0x1f;
        int is_64 = (size == 3);

        if (rt_out) *rt_out = rt;
        if (rn_out) *rn_out = rn;
        if (is_store) *is_store = !l;
        if (size_bytes) *size_bytes = 1 << size;

        const char *op = l ? "LDR" : "STR";
        if (size == 0) op = l ? "LDRB" : "STRB";
        else if (size == 1) op = l ? "LDRH" : "STRH";

        snprintf(out, out_sz, "%s %s, [%s, %s]", op, hwbp_reg_name(rt, is_64),
                 hwbp_base_reg_name(rn), hwbp_base_reg_name(rm));
        return true;
    }

    snprintf(out, out_sz, "[raw 0x%08x]", insn);
    return false;
}

// Find VMA containing an address
static const struct vma *hwbp_find_vma(const struct vma_table *t, uint64_t addr) {
    if (!t || !t->items) return NULL;
    for (uint32_t i = 0; i < t->count; i++) {
        if (addr >= t->items[i].start && addr < t->items[i].end) {
            return &t->items[i];
        }
    }
    return NULL;
}

// Call stack frame entry
struct stack_frame_entry {
    int frame;
    uint64_t pc;
    char module[128];
    uint64_t rva;
};

// Walk Frame Pointer (X29 / FP) to unwind call stack up to max_frames
static int hwbp_unwind_stack(int pid, uint64_t pc, uint64_t fp, uint64_t lr,
                             struct stack_frame_entry *frames, int max_frames,
                             struct vma_table *vmas) {
    int count = 0;
    // Frame 0: Current PC
    frames[count].frame = 0;
    frames[count].pc = pc;
    const struct vma *v = hwbp_find_vma(vmas, pc);
    if (v) {
        const char *leaf = vma_leaf(v->path);
        strncpy(frames[count].module, leaf && leaf[0] ? leaf : (v->path[0] ? v->path : "[anon]"), 127);
        uint64_t base = 0, span_end = 0; uint32_t v_cnt = 0;
        if (leaf && leaf[0] && module_lookup(vmas, leaf, &base, &span_end, &v_cnt) && base > 0) {
            frames[count].rva = pc - base;
        } else {
            frames[count].rva = pc - v->start;
        }
    } else {
        strcpy(frames[count].module, "unknown");
        frames[count].rva = 0;
    }
    count++;

    // Frame 1: Return address (LR) if valid
    if (lr && lr != pc && count < max_frames) {
        frames[count].frame = 1;
        frames[count].pc = lr;
        v = hwbp_find_vma(vmas, lr);
        if (v) {
            const char *leaf = vma_leaf(v->path);
            strncpy(frames[count].module, leaf && leaf[0] ? leaf : (v->path[0] ? v->path : "[anon]"), 127);
            uint64_t base = 0, span_end = 0; uint32_t v_cnt = 0;
            if (leaf && leaf[0] && module_lookup(vmas, leaf, &base, &span_end, &v_cnt) && base > 0) {
                frames[count].rva = lr - base;
            } else {
                frames[count].rva = lr - v->start;
            }
        } else {
            strcpy(frames[count].module, "unknown");
            frames[count].rva = 0;
        }
        count++;
    }

    // Walk frame pointers: [FP] = previous FP, [FP+8] = return address
    uint64_t cur_fp = fp;
    while (cur_fp != 0 && (cur_fp & 0x7) == 0 && count < max_frames) {
        uint64_t buf[2] = {0};
        if (!raw_read(pid, cur_fp, buf, sizeof(buf))) break;
        uint64_t next_fp = buf[0];
        uint64_t ret_pc = buf[1];
        if (ret_pc == 0 || ret_pc == pc) break;
        if (next_fp <= cur_fp || next_fp - cur_fp > 0x100000) break; // Sanity check

        frames[count].frame = count;
        frames[count].pc = ret_pc;
        v = hwbp_find_vma(vmas, ret_pc);
        if (v) {
            const char *leaf = vma_leaf(v->path);
            strncpy(frames[count].module, leaf && leaf[0] ? leaf : (v->path[0] ? v->path : "[anon]"), 127);
            uint64_t base = 0, span_end = 0; uint32_t v_cnt = 0;
            if (leaf && leaf[0] && module_lookup(vmas, leaf, &base, &span_end, &v_cnt) && base > 0) {
                frames[count].rva = ret_pc - base;
            } else {
                frames[count].rva = ret_pc - v->start;
            }
        } else {
            strcpy(frames[count].module, "unknown");
            frames[count].rva = 0;
        }
        count++;
        cur_fp = next_fp;
    }
    return count;
}

// Format hit entry as JSON object with full registers (PC, SP, LR, FP, X0-X30) and Call Stack
static void hwbp_format_hit_json(int index, int pid, const struct hmbp_hit_record *hit,
                                 struct vma_table *vmas, bool is_last) {
    char insn_str[64];
    int rt = -1, rn = -1, sz_bytes = 4;
    bool is_store = false;
    hwbp_decode_insn(hit->insn, insn_str, sizeof(insn_str), &rt, &rn, &is_store, &sz_bytes);

    // Resolve PC module and RVA
    char mod_name[128] = "unknown";
    uint64_t rva = 0;
    const struct vma *v_pc = hwbp_find_vma(vmas, hit->pc);
    if (v_pc) {
        const char *leaf = vma_leaf(v_pc->path);
        if (leaf && leaf[0]) {
            strncpy(mod_name, leaf, sizeof(mod_name) - 1);
            uint64_t base = 0, span_end = 0; uint32_t v_cnt = 0;
            if (module_lookup(vmas, leaf, &base, &span_end, &v_cnt) && base > 0) {
                rva = hit->pc - base;
            } else {
                rva = hit->pc - v_pc->start;
            }
        } else {
            strncpy(mod_name, v_pc->path[0] ? v_pc->path : "[anon]", sizeof(mod_name) - 1);
            rva = hit->pc - v_pc->start;
        }
    }

    // Resolve LR caller module and RVA
    char lr_mod[128] = "unknown";
    uint64_t lr_rva = 0;
    const struct vma *v_lr = hwbp_find_vma(vmas, hit->lr);
    if (v_lr) {
        const char *leaf = vma_leaf(v_lr->path);
        if (leaf && leaf[0]) {
            strncpy(lr_mod, leaf, sizeof(lr_mod) - 1);
            uint64_t base = 0, span_end = 0; uint32_t v_cnt = 0;
            if (module_lookup(vmas, leaf, &base, &span_end, &v_cnt) && base > 0) {
                lr_rva = hit->lr - base;
            } else {
                lr_rva = hit->lr - v_lr->start;
            }
        } else {
            strncpy(lr_mod, v_lr->path[0] ? v_lr->path : "[anon]", sizeof(lr_mod) - 1);
            lr_rva = hit->lr - v_lr->start;
        }
    }

    // Format written value if it's a store instruction
    char val_buf[64] = "null";
    if (is_store && rt >= 0 && rt <= 30) {
        uint64_t raw_val = hit->regs[rt];
        if (sz_bytes == 1) {
            uint8_t v = (uint8_t)raw_val;
            snprintf(val_buf, sizeof(val_buf), "\"0x%x (%u)\"", v, v);
        } else if (sz_bytes == 2) {
            uint16_t v = (uint16_t)raw_val;
            snprintf(val_buf, sizeof(val_buf), "\"0x%x (%u)\"", v, v);
        } else if (sz_bytes == 4) {
            uint32_t v = (uint32_t)raw_val;
            snprintf(val_buf, sizeof(val_buf), "\"0x%x (%u)\"", v, v);
        } else {
            snprintf(val_buf, sizeof(val_buf), "\"0x%llx (%llu)\"",
                     (unsigned long long)raw_val, (unsigned long long)raw_val);
        }
    }

    // Unwind call stack
    struct stack_frame_entry frames[16];
    int frame_count = hwbp_unwind_stack(pid, hit->pc, hit->regs[29], hit->lr, frames, 16, vmas);

    printf("    {\n"
           "      \"index\": %d,\n"
           "      \"tid\": %u,\n"
           "      \"timestamp_ms\": %llu,\n"
           "      \"pc\": \"0x%llx\",\n"
           "      \"module\": \"%s\",\n"
           "      \"rva\": \"0x%llx\",\n"
           "      \"caller_lr\": \"0x%llx\",\n"
           "      \"caller_module\": \"%s\",\n"
           "      \"caller_rva\": \"0x%llx\",\n"
           "      \"instruction\": \"%s\",\n"
           "      \"is_store\": %s,\n"
           "      \"stored_value\": %s,\n",
           index, hit->tid, (unsigned long long)hit->timestamp_ms,
           (unsigned long long)hit->pc, mod_name, (unsigned long long)rva,
           (unsigned long long)hit->lr, lr_mod, (unsigned long long)lr_rva,
           insn_str, is_store ? "true" : "false", val_buf);

    // Call stack array
    printf("      \"call_stack\": [\n");
    for (int f = 0; f < frame_count; f++) {
        printf("        {\"frame\": %d, \"pc\": \"0x%llx\", \"module\": \"%s\", \"rva\": \"0x%llx\"}%s\n",
               frames[f].frame, (unsigned long long)frames[f].pc,
               frames[f].module, (unsigned long long)frames[f].rva,
               f + 1 == frame_count ? "" : ",");
    }
    printf("      ],\n");

    // Complete registers: PC, SP, LR, FP, PSTATE, X0 - X30
    printf("      \"registers\": {\n"
           "        \"PC\": \"0x%llx\",\n"
           "        \"SP\": \"0x%llx\",\n"
           "        \"LR\": \"0x%llx\",\n"
           "        \"FP\": \"0x%llx\",\n"
           "        \"PSTATE\": \"0x%llx\"",
           (unsigned long long)hit->pc, (unsigned long long)hit->sp,
           (unsigned long long)hit->lr, (unsigned long long)hit->regs[29],
           (unsigned long long)hit->pstate);

    for (int r = 0; r < 31; r++) {
        printf(",\n        \"X%d\": \"0x%llx\"", r, (unsigned long long)hit->regs[r]);
    }
    printf("\n      }\n"
           "    }%s\n", is_last ? "" : ",");
}

// ---------------------------------------------------------------------------
// Engine 1: Kernel Companion Mode (via SYS_GETRESGID / HMBP_MAGIC)
// ---------------------------------------------------------------------------
static bool hwbp_try_kernel_watch(int pid, uint64_t addr, size_t size,
                                  uint32_t type_code, uint32_t duration_ms,
                                  uint32_t max_hits, struct vma_table *vmas) {
    struct hmbp_probe_info probe;
    memset(&probe, 0, sizeof(probe));
    long ret = syscall(SYS_GETRESGID, HMBP_MAGIC, &probe, sizeof(probe));
    if (ret != 0 || probe.magic != HMBP_MAGIC) {
        return false;
    }

    struct hmbp_req req;
    memset(&req, 0, sizeof(req));
    req.pid = pid;
    req.addr = addr;
    req.size = (uint32_t)size;
    req.access_type = type_code;
    req.duration_ms = duration_ms;
    req.max_hits = max_hits;

    ret = syscall(SYS_GETRESGID, HMBP_MAGIC_START, &req, sizeof(req));
    if (ret != 0) return false;

    usleep((useconds_t)duration_ms * 1000);

    size_t buf_cap = sizeof(struct hmbp_hit_record) * max_hits + 16;
    uint8_t *kbuf = (uint8_t *)malloc(buf_cap);
    if (!kbuf) {
        syscall(SYS_GETRESGID, HMBP_MAGIC_STOP, &req, sizeof(req));
        return false;
    }
    memset(kbuf, 0, buf_cap);

    ret = syscall(SYS_GETRESGID, HMBP_MAGIC_POLL, kbuf, buf_cap);
    uint32_t hits_count = 0;
    if (ret >= 0) {
        hits_count = *(uint32_t *)kbuf;
        if (hits_count > max_hits) hits_count = max_hits;
    }
    struct hmbp_hit_record *records = (struct hmbp_hit_record *)(kbuf + 8);

    const char *type_name = "write";
    if (type_code == 1) type_name = "read";
    else if (type_code == 3) type_name = "access";
    else if (type_code == 4) type_name = "exec";

    printf("{\n"
           "  \"status\": \"ok\",\n"
           "  \"pid\": %d,\n"
           "  \"address\": \"0x%llx\",\n"
           "  \"size\": %zu,\n"
           "  \"type\": \"%s\",\n"
           "  \"engine\": \"kernel\",\n"
           "  \"duration_ms\": %u,\n"
           "  \"hits_count\": %u,\n"
           "  \"hits\": [\n",
           pid, (unsigned long long)addr, size, type_name, duration_ms, hits_count);

    for (uint32_t i = 0; i < hits_count; i++) {
        hwbp_format_hit_json(i + 1, pid, &records[i], vmas, (i + 1 == hits_count));
    }

    printf("  ]\n}\n");
    free(kbuf);
    return true;
}

// ---------------------------------------------------------------------------
// Engine 2: Native Hardware Debugger (DBGBVR/DBGBCR + DBGWVR/DBGWCR via ptrace)
// ---------------------------------------------------------------------------
#define MAX_THREADS 512
#define MAX_HITS_CAP 64

struct watched_thread {
    pid_t tid;
    bool attached;
    bool watch_set;
};

static int hwbp_collect_tids(int pid, pid_t *out, int max_tids) {
    char task_dir[64];
    snprintf(task_dir, sizeof(task_dir), "/proc/%d/task", pid);
    DIR *d = opendir(task_dir);
    if (!d) return 0;

    int count = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && count < max_tids) {
        if (de->d_name[0] >= '0' && de->d_name[0] <= '9') {
            pid_t tid = (pid_t)atoi(de->d_name);
            if (tid > 0) {
                out[count++] = tid;
            }
        }
    }
    closedir(d);
    return count;
}

static bool hwbp_native_watch(int pid, uint64_t addr, size_t size,
                              uint32_t type_code, uint32_t duration_ms,
                              uint32_t max_hits, struct vma_table *vmas) {
    if (max_hits > MAX_HITS_CAP) max_hits = MAX_HITS_CAP;

    pid_t tids[MAX_THREADS];
    int tid_count = hwbp_collect_tids(pid, tids, MAX_THREADS);
    if (tid_count == 0) {
        tids[0] = pid;
        tid_count = 1;
    }

    struct watched_thread threads[MAX_THREADS];
    memset(threads, 0, sizeof(threads));

    bool is_exec = (type_code == 4); // 4 = Instruction Breakpoint (DBGBVR/DBGBCR)
    uint64_t aligned_addr = 0;
    uint32_t ctrl = 0;
    uint32_t regset_type = is_exec ? NT_ARM_HW_BREAK : NT_ARM_HW_WATCH;

    if (is_exec) {
        // DBGBVR / DBGBCR: 4-byte instruction aligned, BAS = 0b1111 (0xf)
        aligned_addr = addr & ~0x3ULL;
        ctrl = (1 << 0) | (2 << 1) | (0xf << 5); // enable, EL0, BAS=0xf
    } else {
        // DBGWVR / DBGWCR: 8-byte doubleword aligned
        aligned_addr = addr & ~0x7ULL;
        unsigned int off = (unsigned int)(addr & 0x7ULL);
        unsigned int bas = 0;
        if (size == 1) bas = 1 << off;
        else if (size == 2) bas = 3 << off;
        else if (size == 4) bas = 0xf << off;
        else bas = 0xff;
        // DBGWCR: enable, EL0, type(read/write/rw), BAS
        ctrl = (1 << 0) | (2 << 1) | (type_code << 3) | (bas << 5);
    }

    int attached_count = 0;
    for (int i = 0; i < tid_count; i++) {
        pid_t tid = tids[i];
        threads[i].tid = tid;
        if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) == 0) {
            threads[i].attached = true;
            attached_count++;
            int status = 0;
            waitpid(tid, &status, 0);

            ptrace(PTRACE_SETOPTIONS, tid, NULL,
                   (void *)(uintptr_t)(PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD));

            struct user_hwdebug_state_local hwb;
            struct iovec iov;
            iov.iov_base = &hwb;
            iov.iov_len = sizeof(hwb);
            if (ptrace(PTRACE_GETREGSET, tid, (void *)(uintptr_t)regset_type, &iov) == 0) {
                hwb.dbg_regs[0].addr = aligned_addr;
                hwb.dbg_regs[0].ctrl = ctrl;
                iov.iov_len = sizeof(uint32_t) * 2 + sizeof(hwb.dbg_regs[0]);
                if (ptrace(PTRACE_SETREGSET, tid, (void *)(uintptr_t)regset_type, &iov) == 0) {
                    threads[i].watch_set = true;
                }
            }
            ptrace(PTRACE_CONT, tid, NULL, NULL);
        }
    }

    if (attached_count == 0) {
        printf("{\"status\":\"error\",\"message\":\"Failed to attach to target process/threads (EPERM or already traced)\",\"errno\":%d}\n", errno);
        return false;
    }

    struct hmbp_hit_record *records = (struct hmbp_hit_record *)calloc(max_hits, sizeof(struct hmbp_hit_record));
    uint32_t hits_count = 0;
    uint64_t start_time = get_time_ms();

    while ((get_time_ms() - start_time) < duration_ms && hits_count < max_hits) {
        int status = 0;
        pid_t w = waitpid(-1, &status, WNOHANG);
        if (w <= 0) {
            usleep(2000);
            continue;
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            if (sig == SIGTRAP) {
                siginfo_t si;
                memset(&si, 0, sizeof(si));
                ptrace(PTRACE_GETSIGINFO, w, NULL, &si);

                bool triggered = false;
                if (is_exec) {
                    // Instruction execution breakpoint
                    struct user_pt_regs chk_regs;
                    struct iovec chk_iov = { .iov_base = &chk_regs, .iov_len = sizeof(chk_regs) };
                    ptrace(PTRACE_GETREGSET, w, (void *)(uintptr_t)NT_PRSTATUS, &chk_iov);
                    if (chk_regs.pc == addr || chk_regs.pc == aligned_addr) {
                        triggered = true;
                    }
                } else {
                    // Data watchpoint
                    if (si.si_code == TRAP_HWBKPT || (uint64_t)(uintptr_t)si.si_addr == addr ||
                        ((uint64_t)(uintptr_t)si.si_addr >= aligned_addr &&
                         (uint64_t)(uintptr_t)si.si_addr < aligned_addr + 8)) {
                        triggered = true;
                    }
                }

                if (triggered) {
                    struct user_pt_regs regs;
                    struct iovec reg_iov;
                    reg_iov.iov_base = &regs;
                    reg_iov.iov_len = sizeof(regs);
                    ptrace(PTRACE_GETREGSET, w, (void *)(uintptr_t)NT_PRSTATUS, &reg_iov);

                    uint32_t insn = 0;
                    if (!raw_read(pid, regs.pc, &insn, sizeof(insn))) {
                        errno = 0;
                        long pval = ptrace(PTRACE_PEEKTEXT, w, (void *)(uintptr_t)regs.pc, NULL);
                        if (errno == 0) insn = (uint32_t)pval;
                    }

                    if (hits_count < max_hits && records) {
                        struct hmbp_hit_record *rec = &records[hits_count++];
                        rec->timestamp_ms = get_time_ms();
                        rec->tid = (uint32_t)w;
                        rec->access_type = type_code;
                        rec->pc = regs.pc;
                        rec->lr = regs.regs[30];
                        rec->sp = regs.sp;
                        rec->pstate = regs.pstate;
                        rec->insn = insn;
                        for (int r = 0; r < 31; r++) {
                            rec->regs[r] = regs.regs[r];
                        }
                    }

                    // Single-step step-over
                    struct user_hwdebug_state_local hwb;
                    struct iovec iov;
                    iov.iov_base = &hwb;
                    iov.iov_len = sizeof(hwb);
                    ptrace(PTRACE_GETREGSET, w, (void *)(uintptr_t)regset_type, &iov);
                    hwb.dbg_regs[0].ctrl = 0;
                    iov.iov_len = sizeof(uint32_t) * 2 + sizeof(hwb.dbg_regs[0]);
                    ptrace(PTRACE_SETREGSET, w, (void *)(uintptr_t)regset_type, &iov);

                    ptrace(PTRACE_SINGLESTEP, w, NULL, NULL);
                    int step_status = 0;
                    waitpid(w, &step_status, 0);

                    hwb.dbg_regs[0].ctrl = ctrl;
                    ptrace(PTRACE_SETREGSET, w, (void *)(uintptr_t)regset_type, &iov);

                    ptrace(PTRACE_CONT, w, NULL, (void *)0);
                    continue;
                }
            }

            int sig_pass = (sig != SIGTRAP && sig != SIGSTOP) ? sig : 0;
            ptrace(PTRACE_CONT, w, NULL, (void *)(uintptr_t)sig_pass);
        }
    }

    // Cleanup: clear hardware debug registers and detach threads
    for (int i = 0; i < tid_count; i++) {
        if (threads[i].attached) {
            pid_t tid = threads[i].tid;
            syscall(SYS_tgkill, pid, tid, SIGSTOP);
            int st = 0;
            waitpid(tid, &st, 0);

            struct user_hwdebug_state_local hwb;
            struct iovec iov;
            iov.iov_base = &hwb;
            iov.iov_len = sizeof(hwb);
            if (ptrace(PTRACE_GETREGSET, tid, (void *)(uintptr_t)regset_type, &iov) == 0) {
                hwb.dbg_regs[0].ctrl = 0;
                hwb.dbg_regs[0].addr = 0;
                iov.iov_len = sizeof(uint32_t) * 2 + sizeof(hwb.dbg_regs[0]);
                ptrace(PTRACE_SETREGSET, tid, (void *)(uintptr_t)regset_type, &iov);
            }
            ptrace(PTRACE_DETACH, tid, NULL, (void *)0);
        }
    }

    const char *type_name = "write";
    if (type_code == 1) type_name = "read";
    else if (type_code == 3) type_name = "access";
    else if (type_code == 4) type_name = "exec";

    printf("{\n"
           "  \"status\": \"ok\",\n"
           "  \"pid\": %d,\n"
           "  \"address\": \"0x%llx\",\n"
           "  \"size\": %zu,\n"
           "  \"type\": \"%s\",\n"
           "  \"engine\": \"native_hw\",\n"
           "  \"registers_used\": \"%s\",\n"
           "  \"duration_ms\": %u,\n"
           "  \"hits_count\": %u,\n"
           "  \"hits\": [\n",
           pid, (unsigned long long)addr, size, type_name,
           is_exec ? "DBGBVR/DBGBCR (Instruction Breakpoint)" : "DBGWVR/DBGWCR (Data Watchpoint)",
           duration_ms, hits_count);

    if (records) {
        for (uint32_t i = 0; i < hits_count; i++) {
            hwbp_format_hit_json(i + 1, pid, &records[i], vmas, (i + 1 == hits_count));
        }
        free(records);
    }

    printf("  ]\n}\n");
    return true;
}

// ---------------------------------------------------------------------------
// 1. Entry point: cmd_watch
// ---------------------------------------------------------------------------
int cmd_watch(int pid, uint64_t addr, size_t size, const char *type_str,
              uint32_t duration_ms, uint32_t max_hits) {
    if (pid <= 0) {
        printf("{\"status\":\"error\",\"message\":\"Invalid PID\"}\n");
        return 1;
    }
    if (size != 1 && size != 2 && size != 4 && size != 8) size = 4;
    if (duration_ms == 0) duration_ms = 2000;
    if (duration_ms > 30000) duration_ms = 30000;
    if (max_hits == 0) max_hits = 10;
    if (max_hits > 100) max_hits = 100;

    uint32_t type_code = 2; // default write
    if (type_str) {
        if (strcmp(type_str, "r") == 0 || strcmp(type_str, "read") == 0) type_code = 1;
        else if (strcmp(type_str, "rw") == 0 || strcmp(type_str, "access") == 0) type_code = 3;
        else if (strcmp(type_str, "exec") == 0 || strcmp(type_str, "x") == 0 || strcmp(type_str, "break") == 0) type_code = 4;
        else type_code = 2; // write
    }

    struct vma_table vmas;
    memset(&vmas, 0, sizeof(vmas));
    vma_table_load(pid, &vmas);

    if (!hwbp_try_kernel_watch(pid, addr, size, type_code, duration_ms, max_hits, &vmas)) {
        hwbp_native_watch(pid, addr, size, type_code, duration_ms, max_hits, &vmas);
    }

    vma_table_free(&vmas);
    return 0;
}

// ---------------------------------------------------------------------------
// 2. Suspend target thread or process
// ---------------------------------------------------------------------------
int cmd_thread_suspend(int pid, int tid) {
    if (pid <= 0) {
        printf("{\"status\":\"error\",\"message\":\"Invalid PID\"}\n");
        return 1;
    }
    pid_t target_tid = (tid > 0) ? tid : pid;
    if (ptrace(PTRACE_ATTACH, target_tid, NULL, NULL) != 0) {
        printf("{\"status\":\"error\",\"message\":\"Failed to attach/suspend thread\",\"errno\":%d}\n", errno);
        return 1;
    }
    int status = 0;
    waitpid(target_tid, &status, 0);

    struct user_pt_regs regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    ptrace(PTRACE_GETREGSET, target_tid, (void *)(uintptr_t)NT_PRSTATUS, &iov);

    struct vma_table vmas;
    memset(&vmas, 0, sizeof(vmas));
    vma_table_load(pid, &vmas);

    char mod_name[128] = "unknown";
    uint64_t rva = 0;
    const struct vma *v = hwbp_find_vma(&vmas, regs.pc);
    if (v) {
        const char *leaf = vma_leaf(v->path);
        strncpy(mod_name, leaf && leaf[0] ? leaf : (v->path[0] ? v->path : "[anon]"), 127);
        uint64_t base = 0, span_end = 0; uint32_t v_cnt = 0;
        if (leaf && leaf[0] && module_lookup(&vmas, leaf, &base, &span_end, &v_cnt) && base > 0) {
            rva = regs.pc - base;
        } else {
            rva = regs.pc - v->start;
        }
    }

    struct stack_frame_entry frames[16];
    int frame_count = hwbp_unwind_stack(pid, regs.pc, regs.regs[29], regs.regs[30], frames, 16, &vmas);

    printf("{\n"
           "  \"status\": \"ok\",\n"
           "  \"state\": \"suspended\",\n"
           "  \"pid\": %d,\n"
           "  \"tid\": %d,\n"
           "  \"pc\": \"0x%llx\",\n"
           "  \"module\": \"%s\",\n"
           "  \"rva\": \"0x%llx\",\n"
           "  \"call_stack\": [\n",
           pid, target_tid, (unsigned long long)regs.pc, mod_name, (unsigned long long)rva);

    for (int f = 0; f < frame_count; f++) {
        printf("    {\"frame\": %d, \"pc\": \"0x%llx\", \"module\": \"%s\", \"rva\": \"0x%llx\"}%s\n",
               frames[f].frame, (unsigned long long)frames[f].pc,
               frames[f].module, (unsigned long long)frames[f].rva,
               f + 1 == frame_count ? "" : ",");
    }
    printf("  ],\n"
           "  \"registers\": {\n"
           "    \"PC\": \"0x%llx\",\n"
           "    \"SP\": \"0x%llx\",\n"
           "    \"LR\": \"0x%llx\",\n"
           "    \"FP\": \"0x%llx\"",
           (unsigned long long)regs.pc, (unsigned long long)regs.sp,
           (unsigned long long)regs.regs[30], (unsigned long long)regs.regs[29]);

    for (int r = 0; r < 31; r++) {
        printf(",\n    \"X%d\": \"0x%llx\"", r, (unsigned long long)regs.regs[r]);
    }
    printf("\n  }\n}\n");

    vma_table_free(&vmas);
    return 0;
}

// ---------------------------------------------------------------------------
// 3. Resume target thread or process
// ---------------------------------------------------------------------------
int cmd_thread_resume(int pid, int tid) {
    if (pid <= 0) {
        printf("{\"status\":\"error\",\"message\":\"Invalid PID\"}\n");
        return 1;
    }
    pid_t target_tid = (tid > 0) ? tid : pid;
    if (ptrace(PTRACE_DETACH, target_tid, NULL, (void *)0) != 0) {
        // Fallback: send SIGCONT
        kill(target_tid, SIGCONT);
    }
    printf("{\"status\":\"ok\",\"state\":\"resumed\",\"pid\":%d,\"tid\":%d}\n", pid, target_tid);
    return 0;
}

// ---------------------------------------------------------------------------
// 4. Single-step target thread N instructions
// ---------------------------------------------------------------------------
int cmd_step(int pid, int tid, int steps) {
    if (pid <= 0) {
        printf("{\"status\":\"error\",\"message\":\"Invalid PID\"}\n");
        return 1;
    }
    pid_t target_tid = (tid > 0) ? tid : pid;
    if (steps <= 0) steps = 1;
    if (steps > 100) steps = 100;

    bool need_detach = false;
    // Check if already attached, if not attach
    if (ptrace(PTRACE_ATTACH, target_tid, NULL, NULL) == 0) {
        need_detach = true;
        int status = 0;
        waitpid(target_tid, &status, 0);
    }

    struct vma_table vmas;
    memset(&vmas, 0, sizeof(vmas));
    vma_table_load(pid, &vmas);

    printf("{\n"
           "  \"status\": \"ok\",\n"
           "  \"pid\": %d,\n"
           "  \"tid\": %d,\n"
           "  \"requested_steps\": %d,\n"
           "  \"trace\": [\n",
           pid, target_tid, steps);

    for (int i = 0; i < steps; i++) {
        if (ptrace(PTRACE_SINGLESTEP, target_tid, NULL, (void *)0) != 0) break;
        int status = 0;
        waitpid(target_tid, &status, 0);

        struct user_pt_regs regs;
        struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
        ptrace(PTRACE_GETREGSET, target_tid, (void *)(uintptr_t)NT_PRSTATUS, &iov);

        uint32_t insn = 0;
        if (!raw_read(pid, regs.pc, &insn, sizeof(insn))) {
            errno = 0;
            long pval = ptrace(PTRACE_PEEKTEXT, target_tid, (void *)(uintptr_t)regs.pc, NULL);
            if (errno == 0) insn = (uint32_t)pval;
        }

        char disasm[64];
        int rt = -1, rn = -1, sz_bytes = 4;
        bool is_store = false;
        hwbp_decode_insn(insn, disasm, sizeof(disasm), &rt, &rn, &is_store, &sz_bytes);

        char mod_name[128] = "unknown";
        uint64_t rva = 0;
        const struct vma *v = hwbp_find_vma(&vmas, regs.pc);
        if (v) {
            const char *leaf = vma_leaf(v->path);
            strncpy(mod_name, leaf && leaf[0] ? leaf : (v->path[0] ? v->path : "[anon]"), 127);
            uint64_t base = 0, span_end = 0; uint32_t v_cnt = 0;
            if (leaf && leaf[0] && module_lookup(&vmas, leaf, &base, &span_end, &v_cnt) && base > 0) {
                rva = regs.pc - base;
            } else {
                rva = regs.pc - v->start;
            }
        }

        printf("    {\n"
               "      \"step\": %d,\n"
               "      \"pc\": \"0x%llx\",\n"
               "      \"module\": \"%s\",\n"
               "      \"rva\": \"0x%llx\",\n"
               "      \"instruction\": \"%s\",\n"
               "      \"registers\": {\n"
               "        \"PC\": \"0x%llx\",\n"
               "        \"SP\": \"0x%llx\",\n"
               "        \"LR\": \"0x%llx\",\n"
               "        \"FP\": \"0x%llx\",\n"
               "        \"X0\": \"0x%llx\",\n"
               "        \"X1\": \"0x%llx\",\n"
               "        \"X19\": \"0x%llx\"\n"
               "      }\n"
               "    }%s\n",
               i + 1, (unsigned long long)regs.pc, mod_name, (unsigned long long)rva,
               disasm, (unsigned long long)regs.pc, (unsigned long long)regs.sp,
               (unsigned long long)regs.regs[30], (unsigned long long)regs.regs[29],
               (unsigned long long)regs.regs[0], (unsigned long long)regs.regs[1],
               (unsigned long long)regs.regs[19],
               (i + 1 == steps) ? "" : ",");
    }

    printf("  ]\n}\n");

    if (need_detach) {
        ptrace(PTRACE_DETACH, target_tid, NULL, (void *)0);
    }
    vma_table_free(&vmas);
    return 0;
}

// ---------------------------------------------------------------------------
// 5. List all threads in target process
// ---------------------------------------------------------------------------
int cmd_list_threads(int pid) {
    if (pid <= 0) {
        printf("{\"status\":\"error\",\"message\":\"Invalid PID\"}\n");
        return 1;
    }
    char task_dir[64];
    snprintf(task_dir, sizeof(task_dir), "/proc/%d/task", pid);
    DIR *d = opendir(task_dir);
    if (!d) {
        printf("{\"status\":\"error\",\"message\":\"Cannot open task dir for PID %d\",\"errno\":%d}\n", pid, errno);
        return 1;
    }

    struct thread_info {
        int tid;
        char name[64];
        char state[16];
    };
    int cap = 128;
    int count = 0;
    struct thread_info *list = (struct thread_info *)malloc(sizeof(struct thread_info) * cap);

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] >= '0' && de->d_name[0] <= '9') {
            int tid = atoi(de->d_name);
            if (tid <= 0) continue;
            if (count >= cap) {
                cap *= 2;
                list = (struct thread_info *)realloc(list, sizeof(struct thread_info) * cap);
            }
            list[count].tid = tid;
            list[count].name[0] = '\0';
            list[count].state[0] = '\0';

            char comm_path[80];
            snprintf(comm_path, sizeof(comm_path), "/proc/%d/task/%d/comm", pid, tid);
            int fd = open(comm_path, O_RDONLY);
            if (fd >= 0) {
                ssize_t n = read(fd, list[count].name, sizeof(list[count].name) - 1);
                if (n > 0) {
                    list[count].name[n] = '\0';
                    char *nl = strchr(list[count].name, '\n');
                    if (nl) *nl = '\0';
                }
                close(fd);
            }

            char stat_path[80];
            snprintf(stat_path, sizeof(stat_path), "/proc/%d/task/%d/stat", pid, tid);
            fd = open(stat_path, O_RDONLY);
            if (fd >= 0) {
                char sbuf[256];
                ssize_t n = read(fd, sbuf, sizeof(sbuf) - 1);
                if (n > 0) {
                    sbuf[n] = '\0';
                    char *rparen = strrchr(sbuf, ')');
                    if (rparen && *(rparen + 1) == ' ' && *(rparen + 2)) {
                        list[count].state[0] = *(rparen + 2);
                        list[count].state[1] = '\0';
                    }
                }
                close(fd);
            }
            if (!list[count].state[0]) strcpy(list[count].state, "?");
            count++;
        }
    }
    closedir(d);

    printf("{\n"
           "  \"status\": \"ok\",\n"
           "  \"pid\": %d,\n"
           "  \"threads_count\": %d,\n"
           "  \"threads\": [\n", pid, count);

    for (int i = 0; i < count; i++) {
        char esc_name[128];
        int k = 0;
        for (int j = 0; list[i].name[j] && k < 120; j++) {
            if (list[i].name[j] == '"' || list[i].name[j] == '\\') {
                esc_name[k++] = '\\';
            }
            esc_name[k++] = list[i].name[j];
        }
        esc_name[k] = '\0';

        printf("    {\"tid\": %d, \"name\": \"%s\", \"state\": \"%s\"}%s\n",
               list[i].tid, esc_name, list[i].state, (i + 1 == count) ? "" : ",");
    }

    printf("  ]\n}\n");
    free(list);
    return 0;
}

// ---------------------------------------------------------------------------
// 6. Set register value in target thread
// ---------------------------------------------------------------------------
int cmd_set_register(int pid, int tid, const char *reg_name, uint64_t val) {
    if (pid <= 0 || !reg_name) {
        printf("{\"status\":\"error\",\"message\":\"Invalid PID or register name\"}\n");
        return 1;
    }
    pid_t target_tid = (tid > 0) ? tid : pid;

    bool need_detach = false;
    if (ptrace(PTRACE_ATTACH, target_tid, NULL, NULL) == 0) {
        need_detach = true;
        int status = 0;
        waitpid(target_tid, &status, 0);
    }

    struct user_pt_regs regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, target_tid, (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0) {
        printf("{\"status\":\"error\",\"message\":\"Failed to get registers\",\"errno\":%d}\n", errno);
        if (need_detach) ptrace(PTRACE_DETACH, target_tid, NULL, (void *)0);
        return 1;
    }

    uint64_t old_val = 0;
    bool matched = false;
    char canon_reg[16] = "";

    if (strcasecmp(reg_name, "pc") == 0) {
        old_val = regs.pc;
        regs.pc = val;
        matched = true;
        strcpy(canon_reg, "PC");
    } else if (strcasecmp(reg_name, "sp") == 0) {
        old_val = regs.sp;
        regs.sp = val;
        matched = true;
        strcpy(canon_reg, "SP");
    } else if (strcasecmp(reg_name, "lr") == 0) {
        old_val = regs.regs[30];
        regs.regs[30] = val;
        matched = true;
        strcpy(canon_reg, "LR");
    } else if (strcasecmp(reg_name, "fp") == 0) {
        old_val = regs.regs[29];
        regs.regs[29] = val;
        matched = true;
        strcpy(canon_reg, "FP");
    } else if (strcasecmp(reg_name, "pstate") == 0) {
        old_val = regs.pstate;
        regs.pstate = val;
        matched = true;
        strcpy(canon_reg, "PSTATE");
    } else if ((reg_name[0] == 'x' || reg_name[0] == 'X') && reg_name[1] >= '0' && reg_name[1] <= '9') {
        int r = atoi(reg_name + 1);
        if (r >= 0 && r <= 30) {
            old_val = regs.regs[r];
            regs.regs[r] = val;
            matched = true;
            snprintf(canon_reg, sizeof(canon_reg), "X%d", r);
        }
    } else if ((reg_name[0] == 'w' || reg_name[0] == 'W') && reg_name[1] >= '0' && reg_name[1] <= '9') {
        int r = atoi(reg_name + 1);
        if (r >= 0 && r <= 30) {
            old_val = (uint32_t)regs.regs[r];
            regs.regs[r] = (uint32_t)val;
            matched = true;
            snprintf(canon_reg, sizeof(canon_reg), "W%d", r);
        }
    }

    if (!matched) {
        printf("{\"status\":\"error\",\"message\":\"Unknown register name: %s\"}\n", reg_name);
        if (need_detach) ptrace(PTRACE_DETACH, target_tid, NULL, (void *)0);
        return 1;
    }

    if (ptrace(PTRACE_SETREGSET, target_tid, (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0) {
        printf("{\"status\":\"error\",\"message\":\"Failed to set register\",\"errno\":%d}\n", errno);
        if (need_detach) ptrace(PTRACE_DETACH, target_tid, NULL, (void *)0);
        return 1;
    }

    if (need_detach) {
        ptrace(PTRACE_DETACH, target_tid, NULL, (void *)0);
    }

    printf("{\n"
           "  \"status\": \"ok\",\n"
           "  \"pid\": %d,\n"
           "  \"tid\": %d,\n"
           "  \"register\": \"%s\",\n"
           "  \"old_value\": \"0x%llx\",\n"
           "  \"new_value\": \"0x%llx\"\n"
           "}\n",
           pid, target_tid, canon_reg,
           (unsigned long long)old_val, (unsigned long long)val);
    return 0;
}
