#include <linux/types.h>

// Minimal types for KernelPatch C module
typedef unsigned long long u64;
typedef unsigned int u32;
typedef int s32;
typedef unsigned short u16;
typedef unsigned char u8;

#define HMBP_MAGIC             0x484D4250ULL  // "HMBP" ASCII
#define HMBP_MAGIC_START       (HMBP_MAGIC + 1)
#define HMBP_MAGIC_POLL        (HMBP_MAGIC + 2)
#define HMBP_MAGIC_STOP        (HMBP_MAGIC + 3)

#define SYS_GETRESGID 150

struct hmbp_probe_info {
    u64 magic;
    u32 version;
    u32 features;
    char version_str[16];
};

struct hmbp_req {
    s32 pid;
    u32 access_type; // 1=read, 2=write, 3=rw
    u64 addr;
    u32 size;
    u32 max_hits;
    u32 duration_ms;
};

struct hmbp_hit_record {
    u64 timestamp_ms;
    u32 tid;
    u32 access_type;
    u64 pc;
    u64 lr;
    u64 sp;
    u64 pstate;
    u64 regs[31];
    u32 insn;
};

// KernelPatch SDK declarations
extern unsigned long kallsyms_lookup_name(const char *name);
extern int hook_syscalln_override(int sysno, int nargs, void *hook_fn, void **orig_fn);
extern int unhook_syscalln(int sysno);
extern int printk(const char *fmt, ...);
extern long compat_copy_to_user(void *dst, const void *src, unsigned long size);

// Function pointer signatures resolved via kallsyms
struct perf_event;
struct perf_event_attr;
struct task_struct;
struct pt_regs;

typedef void (*perf_overflow_handler_t)(struct perf_event *, void *, struct pt_regs *);

static struct perf_event *(*k_register_user_hw_breakpoint)(
    struct perf_event_attr *attr,
    perf_overflow_handler_t triggered,
    void *context,
    struct task_struct *tsk) = 0;

static void (*k_unregister_hw_breakpoint)(struct perf_event *bp) = 0;
static struct task_struct *(*k_find_task_by_vpid)(s32 vpid) = 0;

static void *orig_sys_getresgid = 0;

// Maximum captured events in ring buffer
#define RING_BUF_MAX 64
static struct hmbp_hit_record g_hits[RING_BUF_MAX];
static volatile u32 g_hit_count = 0;
static volatile s32 g_target_pid = 0;
static struct perf_event *g_active_bp = 0;

// Hardware watchpoint overflow handler: called in kernel exception context
static void hwbp_triggered(struct perf_event *bp, void *data, struct pt_regs *regs) {
    (void)bp;
    (void)data;
    if (!regs) return;

    u32 idx = g_hit_count;
    if (idx < RING_BUF_MAX) {
        struct hmbp_hit_record *h = &g_hits[idx];
        // Read PC, LR, SP from pt_regs
        // In ARM64 pt_regs: regs[0..30], sp, pc, pstate
        u64 *r = (u64 *)regs;
        for (int i = 0; i < 31; i++) {
            h->regs[i] = r[i];
        }
        h->sp = r[31];
        h->pc = r[32];
        h->pstate = r[33];
        h->lr = h->regs[30];
        h->access_type = 2; // Write
        g_hit_count = idx + 1;
    }
}

// Hook for syscall 150 (sys_getresgid)
static long hmbp_syscall_hook(u64 r0, u64 r1, u64 r2, u64 r3, u64 r4, u64 r5) {
    if (r0 == HMBP_MAGIC) {
        // Probe info
        struct hmbp_probe_info info = {
            .magic = HMBP_MAGIC,
            .version = 0x010000,
            .features = 0x1,
            .version_str = "HMBP-1.0",
        };
        if (r1 && r2 >= sizeof(info)) {
            compat_copy_to_user((void *)r1, &info, sizeof(info));
            return 0;
        }
        return -22; // EINVAL
    } else if (r0 == HMBP_MAGIC_START) {
        // Start watchpoint
        g_hit_count = 0;
        return 0;
    } else if (r0 == HMBP_MAGIC_POLL) {
        // Return hits
        if (r1 && r2 >= 8) {
            u32 cnt = g_hit_count;
            compat_copy_to_user((void *)r1, (void *)&cnt, sizeof(cnt));
            if (cnt > 0 && r2 >= sizeof(struct hmbp_hit_record) * cnt + 8) {
                compat_copy_to_user((void *)(r1 + 8), g_hits, sizeof(struct hmbp_hit_record) * cnt);
            }
            return (long)cnt;
        }
        return 0;
    } else if (r0 == HMBP_MAGIC_STOP) {
        if (g_active_bp && k_unregister_hw_breakpoint) {
            k_unregister_hw_breakpoint(g_active_bp);
            g_active_bp = 0;
        }
        return 0;
    }

    // Pass through to original system call
    if (orig_sys_getresgid) {
        typedef long (*fn_t)(u64, u64, u64, u64, u64, u64);
        return ((fn_t)orig_sys_getresgid)(r0, r1, r2, r3, r4, r5);
    }
    return -38; // ENOSYS
}

// KernelPatch Module Entry & Exit
long kpm_init(void) {
    printk("[+] [HMBP] Initializing Hardware Breakpoint Companion Module\n");

    k_register_user_hw_breakpoint = (void *)kallsyms_lookup_name("register_user_hw_breakpoint");
    k_unregister_hw_breakpoint = (void *)kallsyms_lookup_name("unregister_hw_breakpoint");
    k_find_task_by_vpid = (void *)kallsyms_lookup_name("find_task_by_vpid");

    printk("[+] [HMBP] register_user_hw_breakpoint = %px, unregister = %px\n",
           k_register_user_hw_breakpoint, k_unregister_hw_breakpoint);

    int ret = hook_syscalln_override(SYS_GETRESGID, 3, (void *)hmbp_syscall_hook, &orig_sys_getresgid);
    if (ret != 0) {
        printk("[-] [HMBP] hook_syscalln_override failed: %d\n", ret);
        return ret;
    }

    printk("[+] [HMBP] Successfully hooked syscall %d (HMBP_MAGIC=0x%llx)\n",
           SYS_GETRESGID, HMBP_MAGIC);
    return 0;
}

long kpm_exit(void) {
    printk("[+] [HMBP] Exiting Hardware Breakpoint Companion Module\n");
    if (g_active_bp && k_unregister_hw_breakpoint) {
        k_unregister_hw_breakpoint(g_active_bp);
        g_active_bp = 0;
    }
    unhook_syscalln(SYS_GETRESGID);
    return 0;
}

long kpm_ctl0(void) {
    return 0;
}

// KernelPatch metadata sections
__attribute__((section(".kpm.init"))) void *kpm_init_ptr = (void *)kpm_init;
__attribute__((section(".kpm.exit"))) void *kpm_exit_ptr = (void *)kpm_exit;
__attribute__((section(".kpm.ctl0"))) void *kpm_ctl0_ptr = (void *)kpm_ctl0;
__attribute__((section(".kpm.info"))) const char kpm_info[] =
    "name=hm_hwbp\0"
    "version=1.0.0\0"
    "license=GPL v2\0"
    "author=hmkpm-mcp\0"
    "description=HMKPM Hardware Breakpoint Companion Module\0";
