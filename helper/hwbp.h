#ifndef HWBP_H
#define HWBP_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

// Forward declarations
struct vma_table;

// Protocol for companion kernel module (HMBP) via sys_getresgid (syscall 150)
#define HMBP_MAGIC             0x484D4250ULL  // "HMBP" ASCII
#define HMBP_MAGIC_START       (HMBP_MAGIC + 1)
#define HMBP_MAGIC_POLL        (HMBP_MAGIC + 2)
#define HMBP_MAGIC_STOP        (HMBP_MAGIC + 3)

struct hmbp_probe_info {
    uint64_t magic;
    uint32_t version;
    uint32_t features;
    char     version_str[16];
};

struct hmbp_req {
    int32_t  pid;
    uint32_t access_type; // 1=read, 2=write, 3=rw, 4=exec (instruction breakpoint)
    uint64_t addr;
    uint32_t size;        // 1, 2, 4, 8
    uint32_t max_hits;
    uint32_t duration_ms;
};

struct hmbp_hit_record {
    uint64_t timestamp_ms;
    uint32_t tid;
    uint32_t access_type; // 1=read, 2=write, 3=rw, 4=exec
    uint64_t pc;
    uint64_t lr;
    uint64_t sp;
    uint64_t pstate;
    uint64_t regs[31];
    uint32_t insn;
};

// 1. Hardware Breakpoint & Watchpoint Watch
int cmd_watch(int pid, uint64_t addr, size_t size, const char *type_str,
              uint32_t duration_ms, uint32_t max_hits);

// 2. Suspend target thread or process
int cmd_thread_suspend(int pid, int tid);

// 3. Resume target thread or process
int cmd_thread_resume(int pid, int tid);

// 4. Single-step target thread N instructions
int cmd_step(int pid, int tid, int steps);

// 5. List all threads in target process
int cmd_list_threads(int pid);

// 6. Set register value in target thread
int cmd_set_register(int pid, int tid, const char *reg_name, uint64_t val);

#endif // HWBP_H
