// SPDX-License-Identifier: GPL-2.0
/*
 * KernelPatch Module (KPM) - [hm_hwbp]
 * Hardware Breakpoint Companion Module for hmkpm-mcp
 */

#include <asm/current.h>
#include <common.h>
#include <compiler.h>
#include <hook.h>
#include <kconfig.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <ktypes.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>

#define HM_HWBP_VERSION_STR "1.0.0"

KPM_NAME("hm_hwbp");
KPM_VERSION(HM_HWBP_VERSION_STR);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("hmkpm-mcp");
KPM_DESCRIPTION("KernelPatch Hardware Breakpoint Module");

#define HMBP_MAGIC             0x484D4250ULL  // "HMBP" ASCII
#define HMBP_MAGIC_START       (HMBP_MAGIC + 1)
#define HMBP_MAGIC_POLL        (HMBP_MAGIC + 2)
#define HMBP_MAGIC_STOP        (HMBP_MAGIC + 3)

struct hmbp_probe_info {
    uint64_t magic;
    uint32_t version;
    uint32_t features;
    char version_str[16];
};

struct hmbp_req {
    int32_t pid;
    uint32_t access_type; // 1=read, 2=write, 3=rw, 4=exec
    uint64_t addr;
    uint32_t size;
    uint32_t max_hits;
    uint32_t duration_ms;
};

struct hmbp_hit_record {
    uint64_t timestamp_ms;
    uint32_t tid;
    uint32_t access_type;
    uint64_t pc;
    uint64_t lr;
    uint64_t sp;
    uint64_t pstate;
    uint64_t regs[31];
    uint32_t insn;
};

#define RING_BUF_MAX 64
static struct hmbp_hit_record g_hits[RING_BUF_MAX];
static volatile uint32_t g_hit_count = 0;

void *memset(void *s, int c, size_t count)
{
    unsigned char *p = (unsigned char *)s;
    while (count--)
        *p++ = (unsigned char)c;
    return s;
}

static void hmbp_syscall_handle(hook_fargs3_t *args, void *udata)
{
    (void)udata;
    uint64_t magic = syscall_argn(args, 0);

    if (magic != HMBP_MAGIC && magic != HMBP_MAGIC_START &&
        magic != HMBP_MAGIC_POLL && magic != HMBP_MAGIC_STOP)
        return;

    uid_t uid = current_uid();
    if (uid != 0)
        return;

    args->skip_origin = 1;

    if (magic == HMBP_MAGIC) {
        void __user *user_ptr = (void __user *)syscall_argn(args, 1);
        uint64_t total_len = syscall_argn(args, 2);

        if (user_ptr && total_len >= sizeof(struct hmbp_probe_info)) {
            struct hmbp_probe_info info;
            memset(&info, 0, sizeof(info));
            info.magic = HMBP_MAGIC;
            info.version = 0x010000;
            info.features = 0x1;
            const char *vstr = "HMBP-1.0";
            for (int i = 0; vstr[i] && i < (int)sizeof(info.version_str) - 1; i++) {
                info.version_str[i] = vstr[i];
            }
            if (compat_copy_to_user(user_ptr, &info, sizeof(info)) == 0) {
                args->ret = 0;
                return;
            }
        }
        args->ret = (uint64_t)(long)-EINVAL;
        return;
    }

    if (magic == HMBP_MAGIC_START) {
        g_hit_count = 0;
        args->ret = 0;
        return;
    }

    if (magic == HMBP_MAGIC_POLL) {
        void __user *user_ptr = (void __user *)syscall_argn(args, 1);
        uint64_t total_len = syscall_argn(args, 2);
        if (user_ptr && total_len >= 8) {
            uint32_t cnt = g_hit_count;
            if (compat_copy_to_user(user_ptr, &cnt, sizeof(cnt)) == 0) {
                if (cnt > 0 && total_len >= sizeof(struct hmbp_hit_record) * cnt + 8) {
                    compat_copy_to_user((void __user *)((uintptr_t)user_ptr + 8),
                                        g_hits, sizeof(struct hmbp_hit_record) * cnt);
                }
                args->ret = cnt;
                return;
            }
        }
        args->ret = 0;
        return;
    }

    if (magic == HMBP_MAGIC_STOP) {
        args->ret = 0;
        return;
    }

    args->ret = (uint64_t)(long)-EINVAL;
}

static long module_init_handler(const char *args, const char *event, void *reserved)
{
    (void)args;
    (void)event;
    (void)reserved;

    logki("[HMBP] Initializing Hardware Breakpoint Companion Module\n");

    hook_err_t err = hook_syscalln_override(__NR_getresgid, 3, (void *)hmbp_syscall_handle, 0, 0);
    if (err) {
        logke("[HMBP] hook_syscalln_override error: %d\n", err);
        return -ENOENT;
    }

    logki("[HMBP] module loaded successfully (hooked syscall %d)\n", __NR_getresgid);
    return 0;
}

static long module_control_handler(const char *args, char __user *out_msg, int outlen)
{
    (void)args;
    (void)out_msg;
    (void)outlen;
    return 0;
}

static long module_cleanup_handler(void *reserved)
{
    (void)reserved;
    unhook_syscalln(__NR_getresgid, (void *)hmbp_syscall_handle, 0);
    logki("[HMBP] module cleaned up\n");
    return 0;
}

KPM_INIT(module_init_handler);
KPM_CTL0(module_control_handler);
KPM_EXIT(module_cleanup_handler);
