#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <math.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/mman.h>

#define SYS_GETRESUID 148

#define HMKPM_MAGIC             0x484D4B504DULL
#define HMKPM_MAGIC_READ        (HMKPM_MAGIC + 1)
#define HMKPM_MAGIC_WRITE       (HMKPM_MAGIC + 2)
#define HMKPM_MAGIC_READ_BATCH  (HMKPM_MAGIC + 3)
#define HMKPM_MAGIC_WRITE_BATCH (HMKPM_MAGIC + 4)
#define HMKPM_MAGIC_V2P_BATCH   (HMKPM_MAGIC + 5)
#define HMKPM_MAGIC_SCAN_KERNEL (HMKPM_MAGIC + 6)

struct hmkpm_version_info {
    uint64_t magic;
    uint32_t version_code;
    uint16_t version_major;
    uint16_t version_minor;
    uint16_t version_patch;
    uint8_t  is_lockless;
    uint8_t  _pad;
    int32_t  mmap_lock_offset;
    uint64_t features;
    char     version_str[16];
};

struct hmkpm_req {
    int32_t  pid;
    uint32_t _pad;
    uint64_t addr;
    uint64_t size;
};

#define HMKPM_SCAN_TYPE_I8     1
#define HMKPM_SCAN_TYPE_U8     2
#define HMKPM_SCAN_TYPE_I16    3
#define HMKPM_SCAN_TYPE_U16    4
#define HMKPM_SCAN_TYPE_I32    5
#define HMKPM_SCAN_TYPE_U32    6
#define HMKPM_SCAN_TYPE_I64    7
#define HMKPM_SCAN_TYPE_U64    8
#define HMKPM_SCAN_TYPE_F32    9
#define HMKPM_SCAN_TYPE_F64    10
#define HMKPM_SCAN_TYPE_BYTES  11

#define HMKPM_SCAN_OP_EXACT    1
#define HMKPM_SCAN_OP_RANGE    2
#define HMKPM_SCAN_OP_MASK     3

struct hmkpm_scan_range {
    uint64_t start_va;
    uint64_t size;
};

struct hmkpm_scan_hdr {
    int32_t  pid;
    uint8_t  type;
    uint8_t  op;
    uint8_t  align;
    uint8_t  _pad;
    uint32_t range_count;
    uint32_t max_matches;
    uint64_t pattern_len;
    union {
        struct {
            uint64_t val;
            uint64_t mask;
        } exact;
        struct {
            uint64_t min;
            uint64_t max;
        } range_u;
        struct {
            int64_t  min;
            int64_t  max;
        } range_i;
    } criteria;
    uint64_t matches_found;
};

static void print_error(const char *msg, int err) {
    printf("{\"status\":\"error\",\"message\":\"%s\",\"errno\":%d}\n", msg, err);
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// ---------------------------------------------------------------------------
// Raw process memory access.
//
// A single-address HMKPM_READ is unreliable: the kernel returns EFAULT both
// when the target page is unreadable and when its copy_to_user cannot land in
// our frame, so callers could not tell a real zero from a dropped read. Every
// access therefore goes through a page-aligned span read, which only fails when
// the target memory itself is unreadable. One page per syscall is also the
// cheapest granularity: candidates from a scan are dense inside a mapping, so
// one read serves every value that falls in that 4 KiB.
// ---------------------------------------------------------------------------

#define PAGE_SIZE_ 4096
#define PAGE_MASK_ (~0xFFFULL)

// Largest span we ask hmkpm to copy in one call. Bounded so a huge dump cannot
// make the kernel allocate more than a few hundred KiB at a time.
#define READ_SPAN_MAX (256 * 1024)

// Read `size` bytes from `addr` into `out`. Returns true on success.
//
// The request is placed on the stack with its payload following immediately,
// which is the layout hmkpm expects (struct hmkpm_req header, then the caller's
// buffer). Reads that cross into an unreadable page are retried page by page so
// a hole in the middle of a mapping does not lose the readable part around it.
//
// `unreadable_out`, when given, receives the number of bytes that could not be
// read (they are zero-filled in `out`). A caller that only needs the readable
// bytes can use the count instead of treating the whole read as failed.
static bool raw_read_count(int pid, uint64_t addr, void *out, size_t size,
                           size_t *unreadable_out) {
    if (unreadable_out) *unreadable_out = 0;
    if (size == 0) return true;
    size_t cap = size < READ_SPAN_MAX ? size : READ_SPAN_MAX;
    size_t total_len = sizeof(struct hmkpm_req) + cap;
    uint8_t *buf = (uint8_t *)malloc(total_len);
    if (!buf) { if (unreadable_out) *unreadable_out = size; return false; }

    struct hmkpm_req *req = (struct hmkpm_req *)buf;
    uint8_t *data = buf + sizeof(struct hmkpm_req);
    uint8_t *dst = (uint8_t *)out;

    bool all_ok = true;
    size_t done = 0;
    size_t holes = 0;
    while (done < size) {
        size_t want = size - done;
        if (want > cap) want = cap;
        req->pid = pid;
        req->addr = addr + done;
        req->size = want;
        errno = 0;
        long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_READ, buf, sizeof(struct hmkpm_req) + want);
        if (ret >= 0 || ret == 0) {
            memcpy(dst + done, data, want);
            done += want;
            continue;
        }
        if (want == 1) {
            // A single unreadable byte: nothing to narrow.
            ((uint8_t *)out)[done] = 0;
            all_ok = false;
            holes += 1;
            done += 1;
            continue;
        }
        // Failed. Narrow to a single page and retry; if a lone page fails, the
        // target memory is genuinely unreadable there and we leave it zeroed.
        if (want > PAGE_SIZE_) {
            want = PAGE_SIZE_;
            req->pid = pid;
            req->addr = addr + done;
            req->size = want;
            errno = 0;
            ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_READ, buf, sizeof(struct hmkpm_req) + want);

            if (ret >= 0 || ret == 0) {
                memcpy(dst + done, data, want);
                done += want;
                continue;
            }
            want = PAGE_SIZE_;
        }
        memset(dst + done, 0, want);
        all_ok = false;
        holes += want;
        done += want;
    }
    free(buf);
    if (unreadable_out) *unreadable_out = holes;
    return all_ok;
}

static bool raw_read(int pid, uint64_t addr, void *out, size_t size) {
    return raw_read_count(pid, addr, out, size, NULL);
}

// Read a single value of `size` bytes (1-8). Returns false when unreadable.
static bool raw_read_exact(int pid, uint64_t addr, void *out, size_t size) {
    // Prefer the value alone, but fall back to a full page-aligned span so a
    // page whose head is unmapped still yields the bytes that do exist.
    if (raw_read(pid, addr, out, size)) return true;

    uint64_t page = addr & PAGE_MASK_;
    size_t off = (size_t)(addr - page);
    if (off + size > PAGE_SIZE_) return false;
    uint8_t *span = (uint8_t *)malloc(PAGE_SIZE_);
    if (!span) return false;
    bool ok = raw_read(pid, page, span, PAGE_SIZE_);
    if (ok) memcpy(out, span + off, size);
    free(span);
    return ok;
}

// Write `size` bytes at `addr`. Returns the errno-style failure code, 0 on
// success. Writing has no page-aligned workaround: hmkpm copies straight from
// our buffer into the target, so the request either lands or it does not.
static int raw_write(int pid, uint64_t addr, const void *src, size_t size) {
    size_t total_len = sizeof(struct hmkpm_req) + size;
    uint8_t *buf = (uint8_t *)malloc(total_len);
    if (!buf) return ENOMEM;
    struct hmkpm_req *req = (struct hmkpm_req *)buf;
    req->pid = pid;
    req->addr = addr;
    req->size = size;
    memcpy(buf + sizeof(struct hmkpm_req), src, size);
    errno = 0;
    long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_WRITE, buf, total_len);
    int err = (ret < 0 && ret != 0) ? (errno ? errno : EFAULT) : 0;
    free(buf);
    return err;
}

// ---------------------------------------------------------------------------
// Parsed /proc/<pid>/maps, shared by every command that needs VMA topology
// (range collection, module lookup, RVA resolution, dumps).
// ---------------------------------------------------------------------------

struct vma {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    char     perms[5];
    char     path[256];
};

struct vma_table {
    struct vma *items;
    uint32_t    count;
};

static void vma_table_free(struct vma_table *t) {
    if (t) {
        free(t->items);
        t->items = NULL;
        t->count = 0;
    }
}

// Parse the maps file once. Returns false only when the file is unreadable
// (a dead pid), so callers can distinguish "no matches" from "no process".
static bool vma_table_load(int pid, struct vma_table *out) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return false;

    uint32_t cap = 512;
    uint32_t n = 0;
    struct vma *items = (struct vma *)malloc(sizeof(struct vma) * cap);
    if (!items) { fclose(f); return false; }

    char line[600];
    while (fgets(line, sizeof(line), f)) {
        uint64_t start = 0, end = 0, offset = 0;
        char perms[8] = {0}, dev[16] = {0}, pathname[300] = {0};
        unsigned long inode = 0;
        // pathname is optional (anonymous mappings have none).
        int c = sscanf(line, "%llx-%llx %7s %llx %15s %lu %299[^\n]",
                       (unsigned long long *)&start, (unsigned long long *)&end,
                       perms, (unsigned long long *)&offset, dev, &inode, pathname);
        if (c < 5) continue;

        if (n == cap) {
            cap *= 2;
            struct vma *grown = (struct vma *)realloc(items, sizeof(struct vma) * cap);
            if (!grown) { free(items); fclose(f); return false; }
            items = grown;
        }
        struct vma *v = &items[n++];
        v->start = start;
        v->end = end;
        v->offset = offset;
        memcpy(v->perms, perms, 4);
        v->perms[4] = '\0';
        v->path[0] = '\0';
        if (c >= 7 && pathname[0]) {
            char *name = pathname;
            while (*name == ' ') name++;
            // Paths are already bounded; reject control characters so the JSON
            // we emit downstream stays valid.
            size_t k = 0;
            for (; name[k] && k < sizeof(v->path) - 1; k++) {
                unsigned char ch = (unsigned char)name[k];
                v->path[k] = (ch < 32 || ch == 127) ? ' ' : (char)ch;
            }
            v->path[k] = '\0';
            // Trailing whitespace / CR would break comparisons with a caller's
            // module name, so trim it.
            while (k > 0 && (v->path[k - 1] == ' ' || v->path[k - 1] == '\r')) {
                v->path[--k] = '\0';
            }
        }
    }
    fclose(f);
    out->items = items;
    out->count = n;
    return true;
}

// True when `perms` satisfies a filter such as "rw-p". The filter is a
// substring match, matching the historical behaviour of `maps [filter]`,
// but the leading 'r' is always required: hmkpm cannot read unreadable pages.
static bool perms_match(const char *perms, const char *filter) {
    if (perms[0] != 'r') return false;
    if (!filter || !*filter) return true;
    return strstr(perms, filter) != NULL;
}

// The leaf name of a mapping path ("/apex/.../libc.so" -> "libc.so").
static const char *vma_leaf(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static uint32_t collect_ranges(int pid, const char *perm_req,
                               struct hmkpm_scan_range *ranges, uint32_t max_ranges);

static uint32_t count_ranges(int pid, const char *perm_req);

static struct hmkpm_scan_range *collect_ranges_alloc(int pid, const char *perm_req,
                                                     uint32_t *count_out);

static bool kernel_scan_ranges(int pid, uint8_t type, uint8_t align, uint64_t criteria_val,
                               const struct hmkpm_scan_range *ranges, uint32_t range_count,
                               uint32_t cap, uint64_t *found_out,
                               uint64_t **matches_out, uint32_t *reported_out);

static int cmd_probe(void) {
    struct hmkpm_version_info info;
    memset(&info, 0, sizeof(info));
    errno = 0;
    long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC, &info, sizeof(info));
    if (ret < 0 || info.magic != HMKPM_MAGIC) {
        print_error("HMKPM probe magic mismatch or module not loaded", errno ? errno : EINVAL);
        return 1;
    }
    printf("{\"status\":\"ok\",\"magic\":\"0x%llx\",\"version\":\"%.16s\",\"version_code\":%u,"
           "\"version_major\":%u,\"version_minor\":%u,\"version_patch\":%u,"
           "\"is_lockless\":%u,\"mmap_lock_offset\":%d,\"features\":\"0x%llx\"}\n",
           (unsigned long long)info.magic, info.version_str, info.version_code,
           info.version_major, info.version_minor, info.version_patch,
           info.is_lockless, info.mmap_lock_offset, (unsigned long long)info.features);
    return 0;
}

static int cmd_read(int pid, uint64_t addr, size_t size) {
    if (size == 0 || size > (16 * 1024 * 1024)) {
        print_error("Invalid size (max 16MB)", EINVAL);
        return 1;
    }
    uint8_t *data = (uint8_t *)malloc(size);
    if (!data) {
        print_error("Out of memory", ENOMEM);
        return 1;
    }
    if (!raw_read(pid, addr, data, size)) {
        // A span with a hole in it still yields whatever pages were readable;
        // report the failure but emit those bytes rather than nothing.
        printf("{\"status\":\"partial\",\"pid\":%d,\"addr\":\"0x%llx\",\"size\":%zu,\"hex\":\"",
               pid, (unsigned long long)addr, size);
        for (size_t i = 0; i < size; i++) printf("%02x", data[i]);
        printf("\"}\n");
        free(data);
        return 0;
    }

    printf("{\"status\":\"ok\",\"pid\":%d,\"addr\":\"0x%llx\",\"size\":%zu,\"hex\":\"",
           pid, (unsigned long long)addr, size);
    for (size_t i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
    printf("\",\"ascii\":\"");
    for (size_t i = 0; i < size; i++) {
        unsigned char c = data[i];
        if (c >= 32 && c <= 126 && c != '"' && c != '\\') {
            putchar(c);
        } else {
            putchar('.');
        }
    }
    printf("\"}\n");
    free(data);
    return 0;
}

static int cmd_write(int pid, uint64_t addr, const char *hex_str) {
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0 || hex_len == 0) {
        print_error("Hex string length must be even and positive", EINVAL);
        return 1;
    }
    size_t size = hex_len / 2;
    uint8_t *data = (uint8_t *)malloc(size);
    if (!data) {
        print_error("Out of memory", ENOMEM);
        return 1;
    }

    for (size_t i = 0; i < size; i++) {
        int hi = hex_digit(hex_str[2 * i]);
        int lo = hex_digit(hex_str[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            print_error("Invalid hex digit", EINVAL);
            free(data);
            return 1;
        }
        data[i] = (uint8_t)((hi << 4) | lo);
    }

    int err = raw_write(pid, addr, data, size);
    free(data);
    if (err) {
        print_error("HMKPM write failed", err);
        return 1;
    }

    printf("{\"status\":\"ok\",\"pid\":%d,\"addr\":\"0x%llx\",\"bytes_written\":%zu}\n",
           pid, (unsigned long long)addr, size);
    return 0;
}

static int cmd_read_val(int pid, uint64_t addr, const char *type_name) {
    size_t sz = 4;
    if (strcmp(type_name, "i8") == 0 || strcmp(type_name, "u8") == 0) sz = 1;
    else if (strcmp(type_name, "i16") == 0 || strcmp(type_name, "u16") == 0) sz = 2;
    else if (strcmp(type_name, "i32") == 0 || strcmp(type_name, "u32") == 0 || strcmp(type_name, "f32") == 0) sz = 4;
    else if (strcmp(type_name, "i64") == 0 || strcmp(type_name, "u64") == 0 || strcmp(type_name, "f64") == 0) sz = 8;
    else {
        print_error("Unsupported type (supported: i8,u8,i16,u16,i32,u32,i64,u64,f32,f64)", EINVAL);
        return 1;
    }

    uint8_t value[8] = {0};
    if (!raw_read_exact(pid, addr, value, sz)) {
        print_error("HMKPM read failed (address not readable)", EFAULT);
        return 1;
    }

    const uint8_t *data = value;
    printf("{\"status\":\"ok\",\"pid\":%d,\"addr\":\"0x%llx\",\"type\":\"%s\",",
           pid, (unsigned long long)addr, type_name);

    if (strcmp(type_name, "i8") == 0) {
        printf("\"value\":%d", *(int8_t *)data);
    } else if (strcmp(type_name, "u8") == 0) {
        printf("\"value\":%u", *(uint8_t *)data);
    } else if (strcmp(type_name, "i16") == 0) {
        printf("\"value\":%d", *(int16_t *)data);
    } else if (strcmp(type_name, "u16") == 0) {
        printf("\"value\":%u", *(uint16_t *)data);
    } else if (strcmp(type_name, "i32") == 0) {
        printf("\"value\":%d", *(int32_t *)data);
    } else if (strcmp(type_name, "u32") == 0) {
        printf("\"value\":%u", *(uint32_t *)data);
    } else if (strcmp(type_name, "i64") == 0) {
        printf("\"value\":%lld", (long long)*(int64_t *)data);
    } else if (strcmp(type_name, "u64") == 0) {
        printf("\"value\":%llu", (unsigned long long)*(uint64_t *)data);
    } else if (strcmp(type_name, "f32") == 0) {
        printf("\"value\":%g", *(float *)data);
    } else if (strcmp(type_name, "f64") == 0) {
        printf("\"value\":%g", *(double *)data);
    }
    printf("}\n");
    return 0;
}

static int cmd_write_val(int pid, uint64_t addr, const char *type_name, const char *val_str) {
    size_t sz = 4;
    uint8_t raw[8] = {0};

    if (strcmp(type_name, "i8") == 0) {
        sz = 1; *(int8_t *)raw = (int8_t)strtol(val_str, NULL, 0);
    } else if (strcmp(type_name, "u8") == 0) {
        sz = 1; *(uint8_t *)raw = (uint8_t)strtoul(val_str, NULL, 0);
    } else if (strcmp(type_name, "i16") == 0) {
        sz = 2; *(int16_t *)raw = (int16_t)strtol(val_str, NULL, 0);
    } else if (strcmp(type_name, "u16") == 0) {
        sz = 2; *(uint16_t *)raw = (uint16_t)strtoul(val_str, NULL, 0);
    } else if (strcmp(type_name, "i32") == 0) {
        sz = 4; *(int32_t *)raw = (int32_t)strtol(val_str, NULL, 0);
    } else if (strcmp(type_name, "u32") == 0) {
        sz = 4; *(uint32_t *)raw = (uint32_t)strtoul(val_str, NULL, 0);
    } else if (strcmp(type_name, "i64") == 0) {
        sz = 8; *(int64_t *)raw = (int64_t)strtoll(val_str, NULL, 0);
    } else if (strcmp(type_name, "u64") == 0) {
        sz = 8; *(uint64_t *)raw = (uint64_t)strtoull(val_str, NULL, 0);
    } else if (strcmp(type_name, "f32") == 0) {
        sz = 4; *(float *)raw = (float)strtof(val_str, NULL);
    } else if (strcmp(type_name, "f64") == 0) {
        sz = 8; *(double *)raw = (double)strtod(val_str, NULL);
    } else {
        print_error("Unsupported type", EINVAL);
        return 1;
    }

    int err = raw_write(pid, addr, raw, sz);
    if (err) {
        print_error("HMKPM write failed", err);
        return 1;
    }

    printf("{\"status\":\"ok\",\"pid\":%d,\"addr\":\"0x%llx\",\"type\":\"%s\",\"value\":\"%s\"}\n",
           pid, (unsigned long long)addr, type_name, val_str);
    return 0;
}

static int cmd_maps(int pid, const char *filter) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        print_error("Cannot open maps file", errno);
        return 1;
    }

    char line[512];
    bool first = true;
    printf("[");

    while (fgets(line, sizeof(line), f)) {
        if (filter && strlen(filter) > 0 && !strstr(line, filter)) {
            continue;
        }

        uint64_t start = 0, end = 0, offset = 0;
        char perms[8] = {0};
        char dev[16] = {0};
        unsigned long inode = 0;
        char pathname[256] = {0};

        int count = sscanf(line, "%llx-%llx %7s %llx %15s %lu %255[^\n]",
                           (unsigned long long *)&start, (unsigned long long *)&end,
                           perms, (unsigned long long *)&offset, dev, &inode, pathname);

        if (count >= 3) {
            if (!first) printf(",");
            first = false;
            printf("{\"start\":\"0x%llx\",\"end\":\"0x%llx\",\"size\":%llu,\"perms\":\"%s\",\"path\":\"%s\"}",
                   (unsigned long long)start, (unsigned long long)end,
                   (unsigned long long)(end - start), perms, count >= 7 ? pathname : "");
        }
    }
    fclose(f);
    printf("]\n");
    return 0;
}

static int cmd_scan(int pid, const char *type_name, const char *val_str, int custom_align, const char *filter_perms) {
    uint8_t scan_type = HMKPM_SCAN_TYPE_I32;
    uint8_t align = 4;
    uint64_t criteria_val = 0;

    if (strcmp(type_name, "i8") == 0) {
        scan_type = HMKPM_SCAN_TYPE_I8; align = 1; criteria_val = (uint8_t)strtol(val_str, NULL, 0);
    } else if (strcmp(type_name, "u8") == 0) {
        scan_type = HMKPM_SCAN_TYPE_U8; align = 1; criteria_val = (uint8_t)strtoul(val_str, NULL, 0);
    } else if (strcmp(type_name, "i16") == 0) {
        scan_type = HMKPM_SCAN_TYPE_I16; align = 2; criteria_val = (uint16_t)strtol(val_str, NULL, 0);
    } else if (strcmp(type_name, "u16") == 0) {
        scan_type = HMKPM_SCAN_TYPE_U16; align = 2; criteria_val = (uint16_t)strtoul(val_str, NULL, 0);
    } else if (strcmp(type_name, "i32") == 0) {
        scan_type = HMKPM_SCAN_TYPE_I32; align = 4; criteria_val = (uint32_t)strtol(val_str, NULL, 0);
    } else if (strcmp(type_name, "u32") == 0) {
        scan_type = HMKPM_SCAN_TYPE_U32; align = 4; criteria_val = (uint32_t)strtoul(val_str, NULL, 0);
    } else if (strcmp(type_name, "i64") == 0) {
        scan_type = HMKPM_SCAN_TYPE_I64; align = 8; criteria_val = (uint64_t)strtoll(val_str, NULL, 0);
    } else if (strcmp(type_name, "u64") == 0) {
        scan_type = HMKPM_SCAN_TYPE_U64; align = 8; criteria_val = (uint64_t)strtoull(val_str, NULL, 0);
    } else if (strcmp(type_name, "f32") == 0) {
        scan_type = HMKPM_SCAN_TYPE_F32; align = 4;
        float f = strtof(val_str, NULL);
        memcpy(&criteria_val, &f, 4);
    } else if (strcmp(type_name, "f64") == 0) {
        scan_type = HMKPM_SCAN_TYPE_F64; align = 8;
        double d = strtod(val_str, NULL);
        memcpy(&criteria_val, &d, 8);
    } else {
        print_error("Invalid scan type", EINVAL);
        return 1;
    }

    if (custom_align > 0) {
        align = (uint8_t)custom_align;
    }

    // Collect readable/writable memory ranges from /proc/<pid>/maps. Sized to
    // the process's real VMA count: a fixed cap silently skipped a third of a
    // large app's address space.
    uint32_t range_count = 0;
    struct hmkpm_scan_range *ranges = collect_ranges_alloc(pid, filter_perms, &range_count);
    if (!ranges && count_ranges(pid, filter_perms) == 0) {
        printf("{\"status\":\"error\",\"message\":\"Cannot open maps for scan\",\"errno\":%d}\n", EACCES);
        return 1;
    }

    // Print the envelope BEFORE the scan runs. The kernel reports a match count
    // that can exceed the slot array (it keeps counting while capping writes,
    // e.g. 11M zero-i32 hits in a 500 MB dalvik space), and a single-line
    // printf of that much output made the CLI look like it hung for minutes.
    // Streaming the result keeps memory flat and the caller can stop reading.
    #define MAX_MATCHES 2048
    if (range_count == 0) {
        printf("{\"status\":\"ok\",\"matches_found\":0,\"truncated\":false,\"matches\":[]}\n");
        free(ranges);
        return 0;
    }

    uint64_t found = 0;
    uint32_t reported = 0;
    uint64_t *matches = NULL;
    if (!kernel_scan_ranges(pid, scan_type, align, criteria_val, ranges, range_count,
                            MAX_MATCHES, &found, &matches, &reported)) {
        print_error("HMKPM scan kernel syscall failed", errno ? errno : EFAULT);
        free(ranges);
        return 1;
    }

    printf("{\"status\":\"ok\",\"matches_found\":%llu,\"truncated\":%s,\"matches\":[",
           (unsigned long long)found, found > MAX_MATCHES ? "true" : "false");
    for (uint32_t i = 0; i < reported; i++) {
        printf("%s\"0x%llx\"", i ? "," : "", (unsigned long long)matches[i]);
        if ((i & 255) == 255) fflush(stdout);
    }
    printf("]}\n");
    free(matches);
    free(ranges);
    return 0;
}

// Run HMKPM_OP_EXACT over `ranges`, in batches, and merge the hits.
//
// The kernel's fixed-size VMA table rejects a request carrying more ranges than
// it can hold (E2BIG). A large app like systemui has ~1600 rw-p VMAs, well past
// that limit, so a single request fails for exactly the apps users care about.
// Splitting into batches keeps the kernel's NEON path usable instead of falling
// back to a userspace byte-by-byte scan.
//
// Returns false only when a batch fails for a reason other than "too many
// ranges" (which is handled by halving the batch).
#define KERNEL_RANGE_BATCH 512
// Per-request output slot cap. The kernel writes at most this many addresses
// per call; scan_seed then accumulates hits across batches up to its own cap.
#define KERNEL_BATCH_HITS 65536
static bool kernel_scan_ranges(int pid, uint8_t type, uint8_t align, uint64_t criteria_val,
                               const struct hmkpm_scan_range *ranges, uint32_t range_count,
                               uint32_t cap, uint64_t *found_out,
                               uint64_t **matches_out, uint32_t *reported_out) {
    *found_out = 0;
    *reported_out = 0;
    *matches_out = (uint64_t *)malloc(sizeof(uint64_t) * (cap ? cap : 1));
    if (!*matches_out) return false;
    uint32_t slot_cap = cap < KERNEL_BATCH_HITS ? cap : KERNEL_BATCH_HITS;

    size_t max_ranges_bytes = (size_t)KERNEL_RANGE_BATCH * sizeof(struct hmkpm_scan_range);
    size_t matches_bytes = (size_t)slot_cap * sizeof(uint64_t);
    size_t total_len = sizeof(struct hmkpm_scan_hdr) + max_ranges_bytes + matches_bytes;
    uint8_t *buf = (uint8_t *)calloc(1, total_len);
    if (!buf) { free(*matches_out); *matches_out = NULL; return false; }

    struct hmkpm_scan_hdr *hdr = (struct hmkpm_scan_hdr *)buf;
    uint8_t *slot_base = buf + sizeof(struct hmkpm_scan_hdr) + max_ranges_bytes;

    uint32_t batch = KERNEL_RANGE_BATCH;
    uint32_t done = 0;
    while (done < range_count) {
        uint32_t n = range_count - done;
        if (n > batch) n = batch;

        memset(hdr, 0, sizeof(*hdr));
        hdr->pid = pid;
        hdr->type = type;
        hdr->op = HMKPM_SCAN_OP_EXACT;
        hdr->align = align;
        hdr->range_count = n;
        // Ask the kernel for at most what one batch can return. Requesting the
        // full session cap (millions of slots) makes the kernel refuse the
        // request outright, which is what pushed scan_seed onto the slow
        // userspace path.
        hdr->max_matches = cap < KERNEL_BATCH_HITS ? cap : KERNEL_BATCH_HITS;
        hdr->pattern_len = 0;
        hdr->criteria.exact.val = criteria_val;
        hdr->criteria.exact.mask = ~0ULL;
        hdr->matches_found = 0;
        memcpy(buf + sizeof(struct hmkpm_scan_hdr), ranges + done,
               (size_t)n * sizeof(struct hmkpm_scan_range));

        errno = 0;
        long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_SCAN_KERNEL, buf,
                           sizeof(struct hmkpm_scan_hdr) + (size_t)n * sizeof(struct hmkpm_scan_range) + matches_bytes);
        if (ret < 0 && ret != 0) {
            // errno 7 (E2BIG on arm64) means the kernel's range table is still
            // full; shrink the batch and retry the same slice.
            if (errno == E2BIG && n > 1) { batch = n / 2; continue; }
            free(buf);
            free(*matches_out);
            *matches_out = NULL;
            if (errno != E2BIG) errno = errno ? errno : EFAULT;
            return false;
        }

        uint64_t hits = hdr->matches_found;
        uint64_t *src = (uint64_t *)slot_base;
        uint32_t take = hits > slot_cap ? slot_cap : (uint32_t)hits;
        uint32_t usable = 0;
        for (uint32_t i = 0; i < take && *reported_out < cap; i++) {
            // Address 0 is never a real hit (no process maps page 0). A
            // truncated scan against a small process has been observed to
            // report its hits as 0x0, and a caller that trusts such an address
            // would write into the target's null page, so drop it.
            if (src[i] == 0) continue;
            (*matches_out)[(*reported_out)++] = src[i];
            usable++;
        }
        // Count only hits we can actually report. The raw kernel count is
        // meaningless when the slot array was filled with unusable entries.
        *found_out += usable > 0 ? (hits > slot_cap ? hits : usable) : 0;
        done += n;
        batch = KERNEL_RANGE_BATCH;            // restore full batch on success
    }

    free(buf);
    return true;
}

// ---------------------------------------------------------------------------
// Fuzzy / differential scan sessions.
//
// The CLI is a one-shot process, so a scan session (a set of candidate
// addresses + their last observed values) is persisted to a temp file keyed by
// pid + type (`HMKPM_SESSION_DIR`, default /data/local/tmp). Each subsequent
// filter pass re-reads the current value of every candidate address and keeps
// the ones matching the requested predicate.
// ---------------------------------------------------------------------------

#define SESSION_DIR_DEFAULT "/data/local/tmp"
// Cap on stored candidates. Overridable at runtime via HMKPM_SCAN_MAX.
// sizeof(struct scan_entry) == 16 bytes, so 4M entries ~= 64 MB RAM.
#define SESSION_MAX_DEFAULT 4194304

static uint32_t session_max(void) {
    const char *e = getenv("HMKPM_SCAN_MAX");
    if (e && *e) {
        long v = strtol(e, NULL, 0);
        if (v > 0 && v <= 268435456) return (uint32_t)v;
    }
    return SESSION_MAX_DEFAULT;
}

struct scan_entry {
    uint64_t addr;
    union {
        int64_t  i;
        uint64_t u;
        double   f;
    } val;
};

struct scan_session {
    int32_t  pid;
    uint8_t  type;       // HMKPM_SCAN_TYPE_*
    uint8_t  elem_size;  // bytes per element
    uint32_t count;
    struct scan_entry *entries;
};

static void session_path(char *out, size_t out_sz, int pid, const char *type_name) {
    const char *dir = getenv("HMKPM_SESSION_DIR");
    if (!dir || !*dir) dir = SESSION_DIR_DEFAULT;
    snprintf(out, out_sz, "%s/.hmkpm_scan_%d_%s", dir, pid, type_name);
}

static uint8_t scan_type_from_name(const char *t, uint8_t *elem_size, uint8_t *align) {
    if (strcmp(t, "i8") == 0)  { *elem_size = 1; *align = 1; return HMKPM_SCAN_TYPE_I8; }
    if (strcmp(t, "u8") == 0)  { *elem_size = 1; *align = 1; return HMKPM_SCAN_TYPE_U8; }
    if (strcmp(t, "i16") == 0) { *elem_size = 2; *align = 2; return HMKPM_SCAN_TYPE_I16; }
    if (strcmp(t, "u16") == 0) { *elem_size = 2; *align = 2; return HMKPM_SCAN_TYPE_U16; }
    if (strcmp(t, "i32") == 0) { *elem_size = 4; *align = 4; return HMKPM_SCAN_TYPE_I32; }
    if (strcmp(t, "u32") == 0) { *elem_size = 4; *align = 4; return HMKPM_SCAN_TYPE_U32; }
    if (strcmp(t, "i64") == 0) { *elem_size = 8; *align = 8; return HMKPM_SCAN_TYPE_I64; }
    if (strcmp(t, "u64") == 0) { *elem_size = 8; *align = 8; return HMKPM_SCAN_TYPE_U64; }
    if (strcmp(t, "f32") == 0) { *elem_size = 4; *align = 4; return HMKPM_SCAN_TYPE_F32; }
    if (strcmp(t, "f64") == 0) { *elem_size = 8; *align = 8; return HMKPM_SCAN_TYPE_F64; }
    return 0;
}

static bool scan_type_is_float(uint8_t type) {
    return type == HMKPM_SCAN_TYPE_F32 || type == HMKPM_SCAN_TYPE_F64;
}

// Decode raw bytes into the numeric union according to the session type.
static void decode_value(struct scan_entry *e, uint8_t type, const uint8_t *data) {
    switch (type) {
        case HMKPM_SCAN_TYPE_I8:  e->val.i = *(int8_t *)data; break;
        case HMKPM_SCAN_TYPE_U8:  e->val.u = *(uint8_t *)data; break;
        case HMKPM_SCAN_TYPE_I16: e->val.i = *(int16_t *)data; break;
        case HMKPM_SCAN_TYPE_U16: e->val.u = *(uint16_t *)data; break;
        case HMKPM_SCAN_TYPE_I32: e->val.i = *(int32_t *)data; break;
        case HMKPM_SCAN_TYPE_U32: e->val.u = *(uint32_t *)data; break;
        case HMKPM_SCAN_TYPE_I64: e->val.i = *(int64_t *)data; break;
        case HMKPM_SCAN_TYPE_U64: e->val.u = *(uint64_t *)data; break;
        case HMKPM_SCAN_TYPE_F32: e->val.f = *(float *)data; break;
        case HMKPM_SCAN_TYPE_F64: e->val.f = *(double *)data; break;
        default: e->val.u = 0; break;
    }
}

// Ordered comparison of two entries (handles signed / unsigned / float).
static double entry_as_double(const struct scan_entry *e, uint8_t type) {
    if (scan_type_is_float(type)) return e->val.f;
    // Unsigned types: expose as double for comparison (precision ok up to 2^53)
    switch (type) {
        case HMKPM_SCAN_TYPE_U8:
        case HMKPM_SCAN_TYPE_U16:
        case HMKPM_SCAN_TYPE_U32:
        case HMKPM_SCAN_TYPE_U64:
            return (double)e->val.u;
        default:
            return (double)e->val.i;
    }
}

static int compare_entries(const struct scan_entry *a, const struct scan_entry *b, uint8_t type) {
    double da = entry_as_double(a, type);
    double db = entry_as_double(b, type);
    if (scan_type_is_float(type)) {
        if (da < db) return -1;
        if (da > db) return 1;
        return 0;
    }
    // Integer compare: signed vs unsigned
    switch (type) {
        case HMKPM_SCAN_TYPE_U8:
        case HMKPM_SCAN_TYPE_U16:
        case HMKPM_SCAN_TYPE_U32:
        case HMKPM_SCAN_TYPE_U64:
            if (a->val.u < b->val.u) return -1;
            if (a->val.u > b->val.u) return 1;
            return 0;
        default:
            if (a->val.i < b->val.i) return -1;
            if (a->val.i > b->val.i) return 1;
            return 0;
    }
}

static int entry_equals_value(const struct scan_entry *e, uint8_t type, double target) {
    if (scan_type_is_float(type)) {
        double d = e->val.f;
        return (d < target) ? -1 : (d > target) ? 1 : 0;
    }
    switch (type) {
        case HMKPM_SCAN_TYPE_U8:
        case HMKPM_SCAN_TYPE_U16:
        case HMKPM_SCAN_TYPE_U32:
        case HMKPM_SCAN_TYPE_U64: {
            uint64_t t = (uint64_t)llabs((long long)target);
            return (e->val.u < t) ? -1 : (e->val.u > t) ? 1 : 0;
        }
        default: {
            int64_t t = (int64_t)target;
            return (e->val.i < t) ? -1 : (e->val.i > t) ? 1 : 0;
        }
    }
}

static int session_save(int pid, const char *type_name, struct scan_session *s) {
    char path[128];
    session_path(path, sizeof(path), pid, type_name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;

    // One write for the header and one for the whole entry array: fwrite() on a
    // 60 MB session did millions of buffered copies. Entries are already a
    // contiguous array, so a single writev-style syscall pair is enough.
    struct {
        uint32_t magic;
        int32_t  pid;
        uint8_t  type;
        uint8_t  elem_size;
        uint32_t count;
    } hdr;
    hdr.magic = 0x484D4B53; // "HMKS"
    hdr.pid = s->pid;
    hdr.type = s->type;
    hdr.elem_size = s->elem_size;
    hdr.count = s->count;

    if (write(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) { close(fd); return -1; }
    if (s->count > 0 && s->entries) {
        size_t bytes = sizeof(struct scan_entry) * (size_t)s->count;
        const uint8_t *p = (const uint8_t *)s->entries;
        while (bytes > 0) {
            ssize_t n = write(fd, p, bytes);
            if (n <= 0) { close(fd); return -1; }
            p += n;
            bytes -= (size_t)n;
        }
    }
    close(fd);
    return 0;
}

static int session_load(int pid, const char *type_name, struct scan_session *s) {
    char path[128];
    session_path(path, sizeof(path), pid, type_name);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    // The session is read start-to-finish exactly once; telling the kernel that
    // lets it skip aggressive readahead tuning and drop pages behind us.
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);

    struct {
        uint32_t magic;
        int32_t  pid;
        uint8_t  type;
        uint8_t  elem_size;
        uint32_t count;
    } hdr;
    if (read(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr) || hdr.magic != 0x484D4B53) {
        close(fd);
        return -1;
    }
    s->pid = hdr.pid;
    s->type = hdr.type;
    s->elem_size = hdr.elem_size;
    s->count = hdr.count;

    s->entries = NULL;
    if (s->count > 0) {
        size_t bytes = sizeof(struct scan_entry) * (size_t)s->count;
        s->entries = (struct scan_entry *)malloc(bytes);
        if (!s->entries) { close(fd); return -1; }
        uint8_t *p = (uint8_t *)s->entries;
        size_t left = bytes;
        while (left > 0) {
            ssize_t n = read(fd, p, left);
            if (n <= 0) break;
            p += n;
            left -= (size_t)n;
        }
        if (left != 0) {
            // Truncated session (killed mid-write): trust only what we got.
            s->count = (uint32_t)((bytes - left) / sizeof(struct scan_entry));
        }
    }
    close(fd);
    return 0;
}

static void session_free(struct scan_session *s) {
    if (s->entries) { free(s->entries); s->entries = NULL; }
    s->count = 0;
}

// (Single-address reads go through read_many below: a per-candidate syscall
// loop over millions of addresses is far too slow for a filter pass.)

// Re-read a run of addresses in as few syscalls as possible.
//
// HMKPM_READ copies a CONTIGUOUS span, so a batch is only valid when the
// addresses inside it are contiguous. Filter candidates are dense inside a
// mapping (a scan walks every aligned slot) but sparse across mappings and
// broken by unreadable pages. Batching therefore happens per PAGE: all
// candidates falling inside one page are served by a single read of that page,
// which is both exact and cheap (one syscall per 4 KiB instead of per slot).
//
// `live` (optional) marks the slots the kernel actually returned so callers can
// distinguish a real zero from a dropped slot.
struct page_candidates {
    uint64_t addr;
    uint32_t idx;
};

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

static int cmp_page_candidates(const void *a, const void *b) {
    const struct page_candidates *x = (const struct page_candidates *)a;
    const struct page_candidates *y = (const struct page_candidates *)b;
    if (x->addr < y->addr) return -1;
    if (x->addr > y->addr) return 1;
    return 0;
}

static void read_many(int pid, const uint64_t *addrs, uint32_t n, uint8_t size,
                      uint8_t *out, uint32_t *ok_count, uint8_t *live) {
    *ok_count = 0;
    if (live) memset(live, 0, n);
    if (n == 0) return;

    struct {
        struct hmkpm_req req;
        uint8_t scratch[4096];
    } buf;
    buf.req.pid = pid;

    uint32_t i = 0;
    while (i < n) {
        uint64_t page = addrs[i] & ~0xFFFULL;

        // Collect every candidate that lives in this page. Candidate lists are
        // address-ordered, so this is a simple forward scan.
        uint32_t start = i;
        while (i < n && (addrs[i] & ~0xFFFULL) == page) i++;
        uint32_t end = i;                       // exclusive

        // Whole-page read: the kernel returns the page's 4096 bytes and each
        // candidate is sliced out of it.
        buf.req.addr = page;
        buf.req.size = sizeof(buf.scratch);
        errno = 0;
        long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_READ, &buf,
                           sizeof(struct hmkpm_req) + sizeof(buf.scratch));
        if (ret < 0 && ret != 0) {
            // Page not readable: try a partial read ending at the last
            // candidate, which still succeeds for a page whose tail is the
            // unreadable part.
            uint64_t last = addrs[end - 1] + size - page;
            if (last <= sizeof(buf.scratch)) {
                buf.req.size = (size_t)last;
                errno = 0;
                ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_READ, &buf,
                              sizeof(struct hmkpm_req) + last);
            }
        }
        if (ret < 0 && ret != 0) continue;       // whole page gone, leave zeroed

        size_t avail = buf.req.size;
        for (uint32_t k = start; k < end; k++) {
            size_t off = (size_t)(addrs[k] - page);
            if (off + size > avail) continue;
            memcpy(out + (size_t)k * size, buf.scratch + off, size);
            if (live) live[k] = 1;
            (*ok_count)++;
        }
    }
}

// Same as read_many, but order-independent: candidates are bucketed by page
// first, so callers whose address list is not sorted (the kernel's batched scan
// concatenates per-batch lists, which are each sorted but not jointly) still
// get exact values. read_many's inner loop assumes ascending addresses, so
// anything that is not guaranteed sorted must come through here.
#define HMKPM_PUBLIC_API 1
void read_many_unsorted(int pid, const uint64_t *addrs, uint32_t n, uint8_t size,
                        uint8_t *out, uint32_t *ok_count, uint8_t *live) {
    *ok_count = 0;
    if (live) memset(live, 0, n);
    if (n == 0) return;

    // Sort (address, original index) pairs so identical pages are adjacent, run
    // the sorted path over a shadow copy, then scatter the results back.
    struct page_candidates *pairs =
        (struct page_candidates *)malloc(sizeof(struct page_candidates) * n);
    uint64_t *sorted = (uint64_t *)malloc(sizeof(uint64_t) * n);
    uint8_t *mid_out = (uint8_t *)malloc((size_t)n * size);
    uint8_t *mid_live = (uint8_t *)malloc(n);
    if (!pairs || !sorted || !mid_out || !mid_live) {
        free(pairs); free(sorted); free(mid_out); free(mid_live);
        memset(out, 0, (size_t)n * size);
        return;
    }
    for (uint32_t i = 0; i < n; i++) { pairs[i].addr = addrs[i]; pairs[i].idx = i; }
    qsort(pairs, n, sizeof(struct page_candidates), cmp_page_candidates);
    for (uint32_t i = 0; i < n; i++) sorted[i] = pairs[i].addr;

    uint32_t ok_mid = 0;
    read_many(pid, sorted, n, size, mid_out, &ok_mid, mid_live);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t dst = pairs[i].idx;
        memcpy(out + (size_t)dst * size, mid_out + (size_t)i * size, size);
        if (live) live[dst] = mid_live[i];
        if (mid_live[i]) (*ok_count)++;
    }

    free(pairs); free(sorted); free(mid_out); free(mid_live);
}

// Collect readable ranges (matches the semantics used by cmd_scan).
// `max_ranges` caps the returned count; pass 0 for "as many as fit".
// A large app (systemui) has ~1600 rw-p VMAs, so the old fixed 1024-slot
// stack array silently skipped a third of the address space.
static uint32_t collect_ranges(int pid, const char *perm_req,
                               struct hmkpm_scan_range *ranges, uint32_t max_ranges) {
    struct vma_table t;
    if (!vma_table_load(pid, &t)) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < t.count; i++) {
        if (max_ranges && n >= max_ranges) break;
        if (!perms_match(t.items[i].perms, perm_req)) continue;
        ranges[n].start_va = t.items[i].start;
        ranges[n].size = t.items[i].end - t.items[i].start;
        n++;
    }
    vma_table_free(&t);
    return n;
}

// Count how many VMAs match, without storing them, so callers can allocate the
// exact number of slots instead of guessing a cap.
static uint32_t count_ranges(int pid, const char *perm_req) {
    struct vma_table t;
    if (!vma_table_load(pid, &t)) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < t.count; i++) {
        if (perms_match(t.items[i].perms, perm_req)) n++;
    }
    vma_table_free(&t);
    return n;
}

// Allocate a range array sized to the process's actual VMA count and fill it in
// a single maps parse. Returns NULL when the process has no matching mapping.
static struct hmkpm_scan_range *collect_ranges_alloc(int pid, const char *perm_req,
                                                     uint32_t *count_out) {
    *count_out = 0;
    struct vma_table t;
    if (!vma_table_load(pid, &t)) return NULL;

    uint32_t n = 0;
    for (uint32_t i = 0; i < t.count; i++) {
        if (perms_match(t.items[i].perms, perm_req)) n++;
    }
    if (n == 0) { vma_table_free(&t); return NULL; }

    struct hmkpm_scan_range *ranges =
        (struct hmkpm_scan_range *)malloc(sizeof(struct hmkpm_scan_range) * n);
    if (!ranges) { vma_table_free(&t); return NULL; }

    uint32_t k = 0;
    for (uint32_t i = 0; i < t.count; i++) {
        if (!perms_match(t.items[i].perms, perm_req)) continue;
        ranges[k].start_va = t.items[i].start;
        ranges[k].size = t.items[i].end - t.items[i].start;
        k++;
    }
    vma_table_free(&t);
    *count_out = k;
    return ranges;
}

// First pass: find ALL locations whose raw bytes have no fixed value -- i.e.
// the "unknown initial value" scan. We snapshot every aligned slot, storing
// address + current value. This produces a large candidate set which later
// filter passes narrow down.
static int cmd_scan_unknown(int pid, const char *type_name, int custom_align, const char *filter_perms) {
    uint8_t elem_size = 4, align = 4;
    uint8_t type = scan_type_from_name(type_name, &elem_size, &align);
    if (type == 0) { print_error("Invalid scan type", EINVAL); return 1; }
    if (custom_align > 0) align = (uint8_t)custom_align;

    uint32_t range_count = 0;
    struct hmkpm_scan_range *ranges = collect_ranges_alloc(pid, filter_perms, &range_count);
    if (range_count == 0) {
        free(ranges);
        printf("{\"status\":\"ok\",\"count\":0}\n");
        return 0;
    }

    // Snapshot by reading the whole ranges into a scratch buffer in chunks, at
    // elem-aligned offsets. To keep it simple and bounded we cap total bytes.
    // We allocate one large buffer per range (bounded).
    uint32_t smax = session_max();
    struct scan_session sess;
    sess.pid = pid;
    sess.type = type;
    sess.elem_size = elem_size;
    sess.count = 0;
    sess.entries = (struct scan_entry *)malloc(sizeof(struct scan_entry) * smax);
    if (!sess.entries) { print_error("Out of memory for session", ENOMEM); return 1; }

    const size_t CHUNK = 1 * 1024 * 1024;
    uint8_t *chunk = (uint8_t *)malloc(CHUNK + sizeof(struct hmkpm_req));
    if (!chunk) { print_error("Out of memory for chunk", ENOMEM); free(sess.entries); return 1; }

    for (uint32_t r = 0; r < range_count && sess.count < smax; r++) {
        uint64_t cur = ranges[r].start_va;
        uint64_t end_va = ranges[r].start_va + ranges[r].size;
        while (cur < end_va && sess.count < smax) {
            size_t want = (size_t)(end_va - cur);
            if (want > CHUNK) want = CHUNK;
            struct hmkpm_req *req = (struct hmkpm_req *)chunk;
            req->pid = pid;
            req->size = want;
            errno = 0;
            // Retry a failing span page by page (the usual cause is one
            // PROT_NONE guard page inside a 1 MiB chunk). A whole-span retry
            // is pointless: hmkpm copies straight into our buffer, so any
            // single unreadable page fails the entire request.
            size_t got = 0;
            while (got < want && sess.count < smax) {
                req->addr = cur + got;
                req->size = want - got;
                errno = 0;
                long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_READ, chunk, sizeof(struct hmkpm_req) + req->size);
                size_t span;
                if (ret >= 0 || ret == 0) {
                    span = req->size;
                } else if (req->size > 4096) {
                    span = 4096;
                } else {
                    span = 4096;                     // unreadable page, skip it
                    got += span;
                    continue;
                }
                uint8_t *data = chunk + sizeof(struct hmkpm_req);
                for (size_t off = 0; off + elem_size <= span && sess.count < smax; off += align) {
                    struct scan_entry *e = &sess.entries[sess.count];
                    e->addr = cur + got + off;
                    decode_value(e, type, data + off);
                    sess.count++;
                }
                got += span;
            }
            cur += want;
        }
    }
    free(chunk);

    if (session_save(pid, type_name, &sess) != 0) {
        print_error("Cannot write session file", errno);
        session_free(&sess);
        return 1;
    }
    uint32_t n = sess.count;
    bool truncated = (n >= smax);
    session_free(&sess);
    printf("{\"status\":\"ok\",\"pid\":%d,\"type\":\"%s\",\"count\":%u,\"truncated\":%s,\"session\":\"first_pass\"}\n",
           pid, type_name, n, truncated ? "true" : "false");
    return 0;
}

// Userspace exact-value scan. Same semantics as the kernel OP_EXACT scan, but
// done with hmkpm READ + memcmp in 256 KiB chunks, so it works when the VMA
// table is too large for the kernel request struct (E2BIG) and it never
// depends on the kernel's NEON path. Collects up to `cap` hit addresses and
// persists them as a scan session.
static int scan_exact_userspace(int pid, const char *type_name, uint8_t type, uint8_t elem_size,
                                uint8_t align, uint64_t criteria_val, const char *filter_perms,
                                uint32_t cap) {
    uint32_t max_ranges = 4096;
    struct hmkpm_scan_range *ranges =
        (struct hmkpm_scan_range *)malloc(sizeof(struct hmkpm_scan_range) * max_ranges);
    uint8_t *chunk = (uint8_t *)malloc(sizeof(struct hmkpm_req) + 256 * 1024);
    struct scan_entry *entries = (struct scan_entry *)malloc(sizeof(struct scan_entry) * (cap ? cap : 1));
    if (!ranges || !chunk || !entries) {
        free(ranges); free(chunk); free(entries);
        print_error("Out of memory for fallback scan", ENOMEM);
        return 1;
    }
    uint32_t range_count = collect_ranges(pid, filter_perms, ranges, max_ranges);

    uint8_t criteria_bytes[8];
    memcpy(criteria_bytes, &criteria_val, elem_size);

    uint32_t count = 0;
    for (uint32_t r = 0; r < range_count && count < cap; r++) {
        uint64_t cur = ranges[r].start_va;
        uint64_t end_va = ranges[r].start_va + ranges[r].size;
        struct hmkpm_req *req = (struct hmkpm_req *)chunk;
        uint8_t *data = chunk + sizeof(struct hmkpm_req);
        while (cur < end_va && count < cap) {
            size_t want = (size_t)(end_va - cur);
            if (want > 256 * 1024) want = 256 * 1024;
            req->pid = pid;
            req->addr = cur;
            req->size = want;
            errno = 0;
            long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_READ, chunk,
                               sizeof(struct hmkpm_req) + want);
            size_t span;
            if (ret >= 0 || ret == 0) {
                span = want;
            } else if (want > 4096) {
                span = 4096;                        // retry the bad span page by page
            } else {
                span = 4096;                        // unreadable page: skip
                cur += span;
                continue;
            }
            for (size_t off = 0; off + elem_size <= span && count < cap; off += align) {
                if (memcmp(data + off, criteria_bytes, elem_size) == 0) {
                    entries[count].addr = cur + off;
                    entries[count].val.u = 0;
                    memcpy(&entries[count].val, &criteria_val, elem_size);
                    count++;
                }
            }
            cur += span;
        }
    }

    struct scan_session sess;
    sess.pid = pid;
    sess.type = type;
    sess.elem_size = elem_size;
    sess.count = count;
    sess.entries = entries;
    session_save(pid, type_name, &sess);

    printf("{\"status\":\"ok\",\"pid\":%d,\"type\":\"%s\",\"count\":%u,\"matches_found\":%u,"
           "\"session\":\"seed_userspace\"}\n", pid, type_name, count, count);
    free(ranges);
    free(chunk);
    free(entries);
    return 0;
}

// Seed a session from an exact-value scan. This is the fast, GameGuardian-style
// path: instead of snapshotting every slot (which can be truncated on large
// processes), search for a specific value first so the candidate set starts
// small and targeted. Uses the kernel SIMD scan, then re-reads each hit and
// persists the addresses into the session.
static int cmd_scan_seed(int pid, const char *type_name, const char *val_str, int custom_align, const char *filter_perms) {
    uint8_t elem_size = 4, align = 4;
    uint8_t type = scan_type_from_name(type_name, &elem_size, &align);
    if (type == 0) { print_error("Invalid scan type", EINVAL); return 1; }
    if (custom_align > 0) align = (uint8_t)custom_align;

    uint64_t criteria_val = 0;
    double target_d = strtod(val_str, NULL);
    switch (type) {
        case HMKPM_SCAN_TYPE_I8:  criteria_val = (uint8_t)(int8_t)strtol(val_str, NULL, 0); break;
        case HMKPM_SCAN_TYPE_U8:  criteria_val = (uint8_t)strtoul(val_str, NULL, 0); break;
        case HMKPM_SCAN_TYPE_I16: criteria_val = (uint16_t)(int16_t)strtol(val_str, NULL, 0); break;
        case HMKPM_SCAN_TYPE_U16: criteria_val = (uint16_t)strtoul(val_str, NULL, 0); break;
        case HMKPM_SCAN_TYPE_I32: criteria_val = (uint32_t)(int32_t)strtol(val_str, NULL, 0); break;
        case HMKPM_SCAN_TYPE_U32: criteria_val = (uint32_t)strtoul(val_str, NULL, 0); break;
        case HMKPM_SCAN_TYPE_I64: criteria_val = (uint64_t)(int64_t)strtoll(val_str, NULL, 0); break;
        case HMKPM_SCAN_TYPE_U64: criteria_val = (uint64_t)strtoull(val_str, NULL, 0); break;
        case HMKPM_SCAN_TYPE_F32: { float f = (float)target_d; memcpy(&criteria_val, &f, 4); break; }
        case HMKPM_SCAN_TYPE_F64: { memcpy(&criteria_val, &target_d, 8); break; }
    }

    // Cap the persisted session. A generic value such as 0 matches millions of
    // slots; seeding all of them wastes RAM and makes later passes slow, but
    // an empty session makes the feature useless. Keep a usable slice.
    uint32_t cap = session_max();
    uint64_t found = 0;
    uint32_t range_count = 0;
    struct hmkpm_scan_range *ranges = collect_ranges_alloc(pid, filter_perms, &range_count);
    if (range_count == 0) {
        free(ranges);
        printf("{\"status\":\"ok\",\"pid\":%d,\"type\":\"%s\",\"count\":0,\"matches_found\":0}\n",
               pid, type_name);
        return 0;
    }

    uint32_t reported = 0;
    uint64_t *matches = NULL;
    if (!kernel_scan_ranges(pid, type, align, criteria_val, ranges, range_count,
                            cap, &found, &matches, &reported)) {
        // Batching already handles the oversized-VMA case, so a failure here is
        // genuinely fatal for the kernel path. Keep the userspace scan as a
        // last resort for older kernels that reject the request for other
        // reasons.
        free(ranges);
        return scan_exact_userspace(pid, type_name, type, elem_size, align,
                                    criteria_val, filter_perms, cap);
    }
    free(ranges);
    uint64_t kept = found < cap ? found : cap;

    // Everything the kernel matched holds `criteria_val`, so the hit list *is*
    // the baseline -- no re-read needed. But the hits arrive per batch, so they
    // are not jointly sorted, and later passes rely on ascending addresses for
    // their per-page reads. Sort once here (O(n log n) on an in-memory array is
    // free next to the scan itself) and dedupe overlapping batch boundaries.
    qsort(matches, (size_t)reported, sizeof(uint64_t), cmp_u64);

    struct scan_session sess;
    sess.pid = pid;
    sess.type = type;
    sess.elem_size = elem_size;
    sess.count = 0;
    sess.entries = (struct scan_entry *)malloc(sizeof(struct scan_entry) * (kept ? kept : 1));
    if (!sess.entries) { print_error("Out of memory", ENOMEM); free(matches); return 1; }
    for (uint32_t i = 0; i < reported && sess.count < kept; i++) {
        if (matches[i] == 0) continue;
        if (sess.count > 0 && sess.entries[sess.count - 1].addr == matches[i]) continue;
        struct scan_entry *e = &sess.entries[sess.count];
        e->addr = matches[i];
        e->val.u = 0;
        memcpy(&e->val, &criteria_val, elem_size);
        sess.count++;
    }
    free(matches);

    session_save(pid, type_name, &sess);
    uint32_t n = sess.count;
    session_free(&sess);
    printf("{\"status\":\"ok\",\"pid\":%d,\"type\":\"%s\",\"count\":%u,\"matches_found\":%llu,\"session\":\"seed\"}\n",
           pid, type_name, n, (unsigned long long)found);
    return 0;
}

// Second+ pass: re-read candidates and keep only those satisfying a predicate.
// mode: gt <v> | lt <v> | eq <v> | ne <v> | changed | unchanged | increased | decreased
static int cmd_scan_filter(int pid, const char *type_name, const char *mode, const char *arg) {
    uint8_t elem_size = 4, align = 4;
    uint8_t type = scan_type_from_name(type_name, &elem_size, &align);
    if (type == 0) { print_error("Invalid scan type", EINVAL); return 1; }

    struct scan_session sess;
    memset(&sess, 0, sizeof(sess));
    if (session_load(pid, type_name, &sess) != 0) {
        print_error("No scan session (run scan_unknown first)", ENOENT);
        return 1;
    }

    bool have_arg = (arg != NULL && arg[0] != '\0');
    double target = have_arg ? strtod(arg, NULL) : 0.0;

    struct scan_entry *kept = (struct scan_entry *)malloc(sizeof(struct scan_entry) * (sess.count ? sess.count : 1));
    if (!kept) { print_error("Out of memory", ENOMEM); session_free(&sess); return 1; }
    uint8_t *raw = (uint8_t *)malloc((size_t)(sess.count ? sess.count : 1) * sess.elem_size);
    if (!raw) { free(kept); print_error("Out of memory", ENOMEM); session_free(&sess); return 1; }

    // One batched read for the whole candidate set: slot-by-slot reads made a
    // multi-million candidate session take minutes and let the target mutate
    // between reads. `raw` is zeroed; read_many overwrites every readable slot.
    memset(raw, 0, (size_t)(sess.count ? sess.count : 1) * sess.elem_size);
    uint64_t *addrs = (uint64_t *)malloc(sizeof(uint64_t) * (sess.count ? sess.count : 1));
    if (!addrs) { free(raw); free(kept); print_error("Out of memory", ENOMEM); session_free(&sess); return 1; }
    for (uint32_t i = 0; i < sess.count; i++) addrs[i] = sess.entries[i].addr;
    uint32_t ok_count = 0;
    read_many(pid, addrs, sess.count, sess.elem_size, raw, &ok_count, NULL);
    free(addrs);

    uint32_t kept_n = 0;

    // Resolve the predicate ONCE. Comparing mode strings inside the loop meant
    // up to 8 strcmp() calls per candidate, i.e. tens of millions of string
    // comparisons on a 4M-entry session.
    enum { M_CHANGED, M_UNCHANGED, M_INCREASED, M_DECREASED,
           M_GT, M_LT, M_EQ, M_NE, M_RANGE } m;
    if      (strcmp(mode, "changed") == 0)   m = M_CHANGED;
    else if (strcmp(mode, "unchanged") == 0) m = M_UNCHANGED;
    else if (strcmp(mode, "increased") == 0) m = M_INCREASED;
    else if (strcmp(mode, "decreased") == 0) m = M_DECREASED;
    else if (strcmp(mode, "gt") == 0)        m = M_GT;
    else if (strcmp(mode, "lt") == 0)        m = M_LT;
    else if (strcmp(mode, "eq") == 0)        m = M_EQ;
    else if (strcmp(mode, "ne") == 0)        m = M_NE;
    else if (strcmp(mode, "range") == 0)     m = M_RANGE;
    else {
        free(raw); free(kept); session_free(&sess);
        print_error("Unknown filter mode", EINVAL);
        return 1;
    }
    double lo = 0, hi = 0;
    if (m == M_RANGE) sscanf(arg, "%lf:%lf", &lo, &hi);

    for (uint32_t i = 0; i < sess.count; i++) {
        struct scan_entry cur;
        uint8_t *slot = raw + (size_t)i * sess.elem_size;
        cur.addr = sess.entries[i].addr;
        decode_value(&cur, type, slot);

        int old_vs_new = compare_entries(&sess.entries[i], &cur, type); // old - new
        bool keep = false;

        switch (m) {
            case M_CHANGED:   keep = (old_vs_new != 0); break;
            case M_UNCHANGED: keep = (old_vs_new == 0); break;
            case M_INCREASED: keep = (old_vs_new < 0);  break;
            case M_DECREASED: keep = (old_vs_new > 0);  break;
            case M_GT:        keep = (entry_as_double(&cur, type) > target); break;
            case M_LT:        keep = (entry_as_double(&cur, type) < target); break;
            case M_EQ:        keep = entry_equals_value(&cur, type, target) == 0; break;
            case M_NE:        keep = entry_equals_value(&cur, type, target) != 0; break;
            case M_RANGE: {
                double d = entry_as_double(&cur, type);
                keep = (d >= lo && d <= hi);
                break;
            }
        }

        if (keep) {
            kept[kept_n++] = cur;
        }
    }

    // Persist the narrowed session.
    uint8_t saved_elem = sess.elem_size ? sess.elem_size : elem_size;
    uint32_t scanned = sess.count;          // capture BEFORE free (it zeroes count)
    session_free(&sess);
    struct scan_session out;
    out.pid = pid;
    out.type = type;
    out.elem_size = saved_elem;
    out.count = kept_n;
    out.entries = kept;
    session_save(pid, type_name, &out);
    free(raw);
    free(kept);

    printf("{\"status\":\"ok\",\"pid\":%d,\"type\":\"%s\",\"mode\":\"%s\",\"count\":%u,\"scanned\":%u,\"readable\":%u}\n",
           pid, type_name, mode, kept_n, scanned, ok_count);
    return 0;
}

// List the remaining candidate addresses (up to a cap).
static int cmd_scan_results(int pid, const char *type_name) {
    struct scan_session sess;
    memset(&sess, 0, sizeof(sess));
    if (session_load(pid, type_name, &sess) != 0) {
        print_error("No scan session", ENOENT);
        return 1;
    }
    uint32_t cap = 4096;
    uint32_t shown = sess.count < cap ? sess.count : cap;
    printf("{\"status\":\"ok\",\"pid\":%d,\"type\":\"%s\",\"count\":%u,\"matches\":[",
           pid, type_name, sess.count);
    for (uint32_t i = 0; i < shown; i++) {
        if (i > 0) printf(",");
        printf("\"0x%llx\"", (unsigned long long)sess.entries[i].addr);
    }
    printf("]}\n");
    session_free(&sess);
    return 0;
}

static int cmd_scan_reset(int pid, const char *type_name) {
    char path[128];
    session_path(path, sizeof(path), pid, type_name);
    if (unlink(path) != 0 && errno != ENOENT) {
        print_error("Cannot remove session file", errno);
        return 1;
    }
    printf("{\"status\":\"ok\",\"pid\":%d,\"type\":\"%s\",\"reset\":true}\n", pid, type_name);
    return 0;
}

// Read many addresses in one pass. Essential for inspecting a candidate list
// without one CLI invocation (and one syscall) per address.
// argv: read_values <pid> <type> <addr1> [addr2 ...]
static int cmd_read_values(int pid, const char *type_name, int argc, char **argv) {
    uint8_t elem_size = 4, align = 4;
    uint8_t type = scan_type_from_name(type_name, &elem_size, &align);
    if (type == 0) { print_error("Invalid type", EINVAL); return 1; }
    if (argc <= 0) { print_error("No addresses given", EINVAL); return 1; }
    if (argc > 65536) { print_error("Too many addresses (max 65536)", E2BIG); return 1; }

    uint32_t n = (uint32_t)argc;
    uint64_t *addrs = (uint64_t *)malloc(sizeof(uint64_t) * n);
    uint8_t *raw = (uint8_t *)calloc(1, (size_t)n * elem_size);
    uint8_t *live = (uint8_t *)calloc(1, n);
    if (!addrs || !raw || !live) {
        free(addrs); free(raw); free(live);
        print_error("Out of memory", ENOMEM);
        return 1;
    }
    for (uint32_t i = 0; i < n; i++) addrs[i] = strtoull(argv[i], NULL, 0);

    uint32_t okn = 0;
    read_many(pid, addrs, n, elem_size, raw, &okn, live);

    printf("{\"status\":\"ok\",\"pid\":%d,\"type\":\"%s\",\"count\":%u,\"values\":[", pid, type_name, n);
    for (uint32_t i = 0; i < n; i++) {
        if (i) printf(",");
        printf("{\"addr\":\"0x%llx\",", (unsigned long long)addrs[i]);
        if (!live[i]) {
            printf("\"readable\":false}");
            continue;
        }
        struct scan_entry e;
        e.addr = addrs[i];
        decode_value(&e, type, raw + (size_t)i * elem_size);
        printf("\"readable\":true,\"value\":");
        if (scan_type_is_float(type)) {
            printf("%.9g", e.val.f);
        } else if (type == HMKPM_SCAN_TYPE_U64 || type == HMKPM_SCAN_TYPE_U32 ||
                   type == HMKPM_SCAN_TYPE_U16 || type == HMKPM_SCAN_TYPE_U8) {
            printf("%llu", (unsigned long long)e.val.u);
        } else {
            printf("%lld", (long long)e.val.i);
        }
        printf("}");
    }
    printf("],\"readable_count\":%u}\n", okn);

    free(addrs); free(raw); free(live);
    return 0;
}

// Search for a literal byte/string across the target's readable memory.
// Far more useful for tracing config values, URLs and localization strings
// than a numeric scan. argv: find_string <pid> <needle> [perms] [limit]
static int cmd_find_string(int pid, const char *needle, const char *filter_perms, int limit) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0) { print_error("Empty search string", EINVAL); return 1; }
    if (limit <= 0) limit = 100;

    uint32_t range_count = 0;
    struct hmkpm_scan_range *ranges = collect_ranges_alloc(pid, filter_perms, &range_count);
    if (!ranges) { print_error("Cannot read maps for search", EACCES); return 1; }

    const size_t CHUNK = 1024 * 1024;
    uint8_t *buf = (uint8_t *)malloc(CHUNK + sizeof(struct hmkpm_req));
    if (!buf) { free(ranges); print_error("Out of memory", ENOMEM); return 1; }

    int found = 0;
    printf("{\"status\":\"ok\",\"pid\":%d,\"pattern\":\"", pid);
    for (size_t i = 0; i < needle_len; i++) {
        unsigned char c = (unsigned char)needle[i];
        if (c == '"' || c == '\\') printf("\\%c", c);
        else if (c >= 32 && c < 127) putchar(c);
        else printf("\\u%04x", c);
    }
    printf("\",\"matches\":[");

    for (uint32_t r = 0; r < range_count && found < limit; r++) {
        uint64_t cur = ranges[r].start_va;
        uint64_t end_va = ranges[r].start_va + ranges[r].size;
        struct hmkpm_req *req = (struct hmkpm_req *)buf;
        uint8_t *data = buf + sizeof(struct hmkpm_req);
        while (cur < end_va && found < limit) {
            size_t want = (size_t)(end_va - cur);
            if (want > CHUNK) want = CHUNK;
            req->pid = pid;
            req->addr = cur;
            req->size = want;
            errno = 0;
            long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_READ, buf,
                               sizeof(struct hmkpm_req) + want);
            if ((ret < 0 && ret != 0) && want > 4096) {
                want = 4096;                       // page-by-page around a hole
                req->size = want;
                ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_READ, buf,
                              sizeof(struct hmkpm_req) + want);
            }
            if (ret < 0 && ret != 0) { cur += want ? want : 4096; continue; }

            if (want >= needle_len) {
                for (size_t off = 0; off + needle_len <= want; off++) {
                    if (data[off] != (uint8_t)needle[0]) continue;
                    if (memcmp(data + off, needle, needle_len) != 0) continue;
                    if (found) printf(",");
                    printf("\"0x%llx\"", (unsigned long long)(cur + off));
                    found++;
                    if (found >= limit) break;
                }
            }
            cur += want;
        }
    }
    printf("],\"count\":%d}\n", found);

    free(buf);
    free(ranges);
    return 0;
}

// Largest legal address the process can hold. Anything above this is not a
// pointer, so a chain walk stops rather than chasing an integer that happens to
// look like one.
#define USER_ADDR_MAX  ((uint64_t)1 << 48)

// Find the module whose leaf name matches and return its load base, span and
// VMA count. Module leaves collide across app/lib/system dirs, so the caller
// passes an optional path fragment to disambiguate when needed.
static bool module_lookup(struct vma_table *t, const char *module,
                          uint64_t *base_out, uint64_t *span_end_out, uint32_t *vma_count) {
    uint64_t best = 0, end = 0;
    uint32_t hits = 0;
    for (uint32_t i = 0; i < t->count; i++) {
        const char *leaf = vma_leaf(t->items[i].path);
        if (!leaf[0] || strcmp(leaf, module) != 0) continue;
        hits++;
        // The mapping with file offset 0 is the module's true load address;
        // without one, fall back to the lowest VMA that carries the name.
        if (t->items[i].offset == 0 && t->items[i].start != 0) {
            best = t->items[i].start;
            end = t->items[i].end;
        } else if (!best || t->items[i].start < best) {
            best = t->items[i].start;
            end = t->items[i].end;
        } else if (t->items[i].end > end) {
            end = t->items[i].end;
        }
    }
    *base_out = best;
    *span_end_out = end;
    *vma_count = hits;
    return hits > 0;
}

// Resolve the load base of a module (e.g. libil2cpp.so) and optionally add an
// RVA, which is how every pointer chain in a game actually starts.
// argv: module_base <pid> <module> [rva]
static int cmd_module_base(int pid, const char *module, const char *rva_str) {
    struct vma_table t;
    if (!vma_table_load(pid, &t)) { print_error("Cannot read maps", errno); return 1; }

    uint64_t base = 0, end = 0, rva = rva_str ? strtoull(rva_str, NULL, 0) : 0;
    uint32_t vma_count = 0;
    bool found = module_lookup(&t, module, &base, &end, &vma_count);
    vma_table_free(&t);

    if (!found) { print_error("Module not mapped in this process", ENOENT); return 1; }
    printf("{\"status\":\"ok\",\"pid\":%d,\"module\":\"%s\",\"base\":\"0x%llx\",\"rva\":\"0x%llx\","
           "\"address\":\"0x%llx\",\"module_end\":\"0x%llx\",\"vmas\":%u}\n",
           pid, module, (unsigned long long)base, (unsigned long long)rva,
           (unsigned long long)(base + rva), (unsigned long long)end, vma_count);
    return 0;
}

// ---------------------------------------------------------------------------
// Pointer chain resolution.
//
// A game address is never absolute across launches: it is
//   base + rva  ->  [ + off1 ]  ->  [ + off2 ]  -> ...  -> final address
// where the first hop lives inside a module (stable RVA) and each following hop
// is a pointer read from the target plus a fixed offset. Resolving the chain in
// one CLI call avoids a process spawn and a round trip per hop, which is what
// makes this usable interactively.
// ---------------------------------------------------------------------------

// Read a 64-bit pointer at `addr`. Returns false when the memory is unreadable
// or the value cannot be a userspace pointer.
static bool read_pointer(int pid, uint64_t addr, uint64_t *out) {
    uint8_t buf[8];
    if (!raw_read_exact(pid, addr, buf, 8)) return false;
    uint64_t v;
    memcpy(&v, buf, 8);
    if (v == 0 || v >= USER_ADDR_MAX) return false;
    *out = v;
    return true;
}

// Walk a chain. `base` may be a module name (resolved inside the CLI) or an
// absolute address supplied by the caller. `offsets` are applied as
// read(ptr + off) then dereference, except the LAST offset which is added
// without dereferencing -- that is the final field address the caller wants.
//
// argv: pointer_chain <pid> <base_module|0xaddr> <rva> <type> [off ...]
static int cmd_pointer_chain(int pid, const char *base_arg, const char *rva_str,
                             const char *type_name, int off_count, char **off_args) {
    uint8_t elem_size = 4, align = 4;
    uint8_t type = scan_type_from_name(type_name, &elem_size, &align);
    if (type == 0) { print_error("Invalid type", EINVAL); return 1; }

    uint64_t cur = 0;
    char module_echo[256] = {0};
    if (base_arg[0] >= '0' && base_arg[0] <= '9') {
        cur = strtoull(base_arg, NULL, 0);
    } else {
        struct vma_table t;
        if (!vma_table_load(pid, &t)) { print_error("Cannot read maps", errno); return 1; }
        uint64_t base = 0, end = 0;
        uint32_t vma_count = 0;
        bool found = module_lookup(&t, base_arg, &base, &end, &vma_count);
        vma_table_free(&t);
        if (!found) { print_error("Module not mapped in this process", ENOENT); return 1; }
        cur = base;
        snprintf(module_echo, sizeof(module_echo), "%s", base_arg);
    }

    uint64_t rva = rva_str ? strtoull(rva_str, NULL, 0) : 0;
    cur += rva;

    printf("{\"status\":\"ok\",\"pid\":%d,\"module\":\"%s\",\"rva\":\"0x%llx\",\"steps\":[",
           pid, module_echo, (unsigned long long)rva);

    bool ok = true;
    int  fail_step = -1;
    /* hop 0 is the entry address itself */ {
        printf("{\"step\":0,\"addr\":\"0x%llx\"}", (unsigned long long)cur);
    }

    for (int i = 0; i < off_count && ok; i++) {
        int64_t off = (int64_t)strtoll(off_args[i], NULL, 0);
        uint64_t at = (uint64_t)((int64_t)cur + off);
        bool last = (i == off_count - 1);

        if (last) {
            cur = at;                          // final field address, no deref
            printf(",{\"step\":%d,\"offset\":\"%s\",\"addr\":\"0x%llx\",\"final\":true}",
                   i + 1, off_args[i], (unsigned long long)cur);
            break;
        }

        uint64_t ptr = 0;
        if (!read_pointer(pid, at, &ptr)) {
            ok = false;
            fail_step = i + 1;
            printf(",{\"step\":%d,\"offset\":\"%s\",\"addr\":\"0x%llx\",\"error\":\"pointer unreadable or invalid\"}",
                   i + 1, off_args[i], (unsigned long long)at);
            break;
        }
        cur = ptr;
        printf(",{\"step\":%d,\"offset\":\"%s\",\"addr\":\"0x%llx\",\"pointer\":\"0x%llx\"}",
               i + 1, off_args[i], (unsigned long long)at, (unsigned long long)ptr);
    }

    if (!ok) {
        printf("],\"resolved\":false,\"failed_step\":%d}\n", fail_step);
        return 0;
    }

    // With no offsets at all the chain IS the address; resolve its value.
    printf("],\"resolved\":true,\"address\":\"0x%llx\",\"type\":\"%s\"",
           (unsigned long long)cur, type_name);

    uint8_t raw[8] = {0};
    if (raw_read_exact(pid, cur, raw, elem_size)) {
        struct scan_entry e;
        e.addr = cur;
        decode_value(&e, type, raw);
        printf(",\"readable\":true,\"value\":");
        if (scan_type_is_float(type)) {
            printf("%.9g", e.val.f);
        } else if (type == HMKPM_SCAN_TYPE_U64 || type == HMKPM_SCAN_TYPE_U32 ||
                   type == HMKPM_SCAN_TYPE_U16 || type == HMKPM_SCAN_TYPE_U8) {
            printf("%llu", (unsigned long long)e.val.u);
        } else {
            printf("%lld", (long long)e.val.i);
        }
    } else {
        printf(",\"readable\":false");
    }
    printf("}\n");
    return 0;
}

// ---------------------------------------------------------------------------
// Value freezing.
//
// A frozen value has to be rewritten continuously: the app overwrites the slot
// on its next frame, so a one-shot write is useless. The CLI itself is a
// one-shot process, so freezing runs in a detached daemon (this same binary
// re-executed with the internal `_freeze_daemon` command and its own session).
// Writing requires no read, so the daemon only needs HMKPM_WRITE per slot, and
// a single write per slot per tick is enough to win against any game loop.
// ---------------------------------------------------------------------------

#define FREEZE_STATE_DIR_DEFAULT "/data/local/tmp"
#define FREEZE_MAX_SLOTS 256

struct freeze_slot {
    uint64_t addr;
    uint8_t  data[8];
    uint8_t  size;
};

// "<dir>/.hmkpm_freeze_<pid>.bin" -- one daemon per target process, so two
// freezes on different apps can coexist.
static void freeze_path(char *out, size_t out_sz, int pid, const char *suffix) {
    const char *dir = getenv("HMKPM_SESSION_DIR");
    if (!dir || !*dir) dir = FREEZE_STATE_DIR_DEFAULT;
    snprintf(out, out_sz, "%s/.hmkpm_freeze_%d%s", dir, pid, suffix);
}

// The daemon's own record: it needs a pid file so `freeze_stop` can signal it
// and `freeze_list` can report liveness without scanning /proc.
static void freeze_pid_path(char *out, size_t out_sz, int pid) {
    freeze_path(out, out_sz, pid, ".pid");
}

static int freeze_state_path(char *out, size_t out_sz, int pid) {
    freeze_path(out, out_sz, pid, ".bin");
    return 0;
}

static int freeze_save_slots(int pid, const struct freeze_slot *slots, uint32_t n) {
    char path[256];
    freeze_state_path(path, sizeof(path), pid);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    struct { int32_t pid; uint32_t count; } hdr = { pid, n };
    bool ok = write(fd, &hdr, sizeof(hdr)) == (ssize_t)sizeof(hdr);
    if (ok && n > 0) {
        ok = write(fd, slots, sizeof(struct freeze_slot) * n) ==
             (ssize_t)(sizeof(struct freeze_slot) * n);
    }
    close(fd);
    return ok ? 0 : -1;
}

static int freeze_load_slots(int pid, struct freeze_slot *slots, uint32_t max, uint32_t *n_out) {
    char path[256];
    freeze_state_path(path, sizeof(path), pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    struct { int32_t pid; uint32_t count; } hdr;
    if (read(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr) || hdr.count > max) {
        close(fd);
        return -1;
    }
    *n_out = hdr.count;
    if (hdr.count > 0) {
        size_t want = sizeof(struct freeze_slot) * hdr.count;
        if (read(fd, slots, want) != (ssize_t)want) { close(fd); return -1; }
    }
    close(fd);
    return 0;
}

// Internal command: `helpers _freeze_daemon <pid> <interval_ms>`.
// Never prints to stdout (its parent is gone); it just keeps writing.
static int cmd_freeze_daemon(int pid, int interval_ms, const char *self_path) {
    // Detach from the caller's session so a closed MCP transport or a killed
    // shell does not take the daemon down with it.
    setsid();

    char pid_path[256];
    freeze_pid_path(pid_path, sizeof(pid_path), pid);
    int pfd = open(pid_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (pfd >= 0) {
        char buf[32];
        int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
        if (write(pfd, buf, (size_t)n) != n) { /* best effort */ }
        close(pfd);
    }

    struct freeze_slot slots[FREEZE_MAX_SLOTS];
    uint32_t n = 0;
    if (freeze_load_slots(pid, slots, FREEZE_MAX_SLOTS, &n) != 0) return 1;

    if (interval_ms < 10) interval_ms = 10;
    if (interval_ms > 2000) interval_ms = 2000;
    struct timespec ts = { interval_ms / 1000, (long)(interval_ms % 1000) * 1000000L };

    // Exit conditions: our pid file vanished (freeze_stop), the state file was
    // removed, or the target process died. Checking all three keeps a stale
    // daemon from spinning on a dead pid forever.
    for (;;) {
        if (kill(pid, 0) != 0) break;

        // Re-read the slot table each tick so `freeze_add` takes effect without
        // restarting the daemon, and a `freeze_remove` of the last slot ends it.
        uint32_t cur_n = 0;
        struct freeze_slot cur[FREEZE_MAX_SLOTS];
        if (freeze_load_slots(pid, cur, FREEZE_MAX_SLOTS, &cur_n) != 0) break;
        if (cur_n == 0) break;

        for (uint32_t i = 0; i < cur_n; i++) {
            raw_write(pid, cur[i].addr, cur[i].data, cur[i].size);
        }
        nanosleep(&ts, NULL);
    }

    // Clean up our own bookkeeping: state file and pid file both go away.
    unlink(pid_path);
    char state[256];
    freeze_state_path(state, sizeof(state), pid);
    unlink(state);
    (void)self_path;
    return 0;
}

static bool pid_alive(int pid) {
    return pid > 0 && kill(pid, 0) == 0;
}

// Parse a typed value the same way write_val does, into `data`/`size`.
static bool parse_typed_value(const char *type_name, const char *val_str,
                              uint8_t *data, uint8_t *size_out) {
    memset(data, 0, 8);
    if (strcmp(type_name, "i8") == 0) { *size_out = 1; *(int8_t *)data = (int8_t)strtol(val_str, NULL, 0); }
    else if (strcmp(type_name, "u8") == 0) { *size_out = 1; *(uint8_t *)data = (uint8_t)strtoul(val_str, NULL, 0); }
    else if (strcmp(type_name, "i16") == 0) { *size_out = 2; *(int16_t *)data = (int16_t)strtol(val_str, NULL, 0); }
    else if (strcmp(type_name, "u16") == 0) { *size_out = 2; *(uint16_t *)data = (uint16_t)strtoul(val_str, NULL, 0); }
    else if (strcmp(type_name, "i32") == 0) { *size_out = 4; *(int32_t *)data = (int32_t)strtol(val_str, NULL, 0); }
    else if (strcmp(type_name, "u32") == 0) { *size_out = 4; *(uint32_t *)data = (uint32_t)strtoul(val_str, NULL, 0); }
    else if (strcmp(type_name, "i64") == 0) { *size_out = 8; *(int64_t *)data = (int64_t)strtoll(val_str, NULL, 0); }
    else if (strcmp(type_name, "u64") == 0) { *size_out = 8; *(uint64_t *)data = (uint64_t)strtoull(val_str, NULL, 0); }
    else if (strcmp(type_name, "f32") == 0) { *size_out = 4; *(float *)data = strtof(val_str, NULL); }
    else if (strcmp(type_name, "f64") == 0) { *size_out = 8; *(double *)data = strtod(val_str, NULL); }
    else return false;
    return true;
}

// Read the daemon's pid, or 0 when none is running.
static int freeze_daemon_pid(int pid) {
    char path[256];
    freeze_pid_path(path, sizeof(path), pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int out = 0;
    if (fscanf(f, "%d", &out) != 1) out = 0;
    fclose(f);
    if (!pid_alive(out)) return 0;
    return out;
}

// Start the daemon if it is not already running. Re-execs this binary; the
// child inherits nothing but needs to stay alive after we exit, so it is
// spawned detached and the parent never waits on it.
static int freeze_ensure_daemon(int pid, int interval_ms) {
    if (freeze_daemon_pid(pid) > 0) return 0;

    // argv must outlive the fork call only; the child gets a copy.
    char self[512];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n <= 0) snprintf(self, sizeof(self), "/data/local/tmp/hmkpm_cli");
    else self[n] = '\0';

    char pid_s[16], iv_s[16];
    snprintf(pid_s, sizeof(pid_s), "%d", pid);
    snprintf(iv_s, sizeof(iv_s), "%d", interval_ms);

    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        // Detach: new session, no controlling terminal, stdio to /dev/null.
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, 0);
            dup2(devnull, 1);
            dup2(devnull, 2);
            if (devnull > 2) close(devnull);
        }
        execl(self, self, "_freeze_daemon", pid_s, iv_s, (char *)NULL);
        _exit(127);
    }
    // Give the child a moment to publish its pid file before we report success.
    for (int i = 0; i < 50; i++) {
        if (freeze_daemon_pid(pid) > 0) return 0;
        struct timespec ts = { 0, 10 * 1000000L };
        nanosleep(&ts, NULL);
    }
    return -1;
}

// Resolve the addresses to freeze: an explicit list, or a scan session when
// none is given (the common flow: scan -> filter -> freeze the survivors).
static uint32_t freeze_resolve_addrs(int pid, const char *type_name, int argc, char **argv,
                                     uint64_t *addrs, uint32_t max) {
    uint32_t n = 0;
    if (argc > 0) {
        for (int i = 0; i < argc && n < max; i++) addrs[n++] = strtoull(argv[i], NULL, 0);
        return n;
    }
    struct scan_session sess;
    memset(&sess, 0, sizeof(sess));
    if (session_load(pid, type_name, &sess) != 0) return 0;
    for (uint32_t i = 0; i < sess.count && n < max; i++) addrs[n++] = sess.entries[i].addr;
    session_free(&sess);
    return n;
}

// argv: freeze_add <pid> <type> <value> <interval_ms> [addr ...]
static int cmd_freeze_add(int pid, const char *type_name, const char *val_str,
                          int interval_ms, int argc, char **argv) {
    uint8_t data[8], size = 0;
    if (!parse_typed_value(type_name, val_str, data, &size)) {
        print_error("Invalid type", EINVAL);
        return 1;
    }

    uint64_t *addrs = (uint64_t *)malloc(sizeof(uint64_t) * FREEZE_MAX_SLOTS);
    if (!addrs) { print_error("Out of memory", ENOMEM); return 1; }
    uint32_t want = freeze_resolve_addrs(pid, type_name, argc, argv, addrs, FREEZE_MAX_SLOTS);
    if (want == 0) {
        free(addrs);
        print_error("No addresses given and no scan session to freeze", ENOENT);
        return 1;
    }

    // Merge with any existing slots so repeated calls accumulate instead of
    // clobbering the previous freeze set.
    struct freeze_slot slots[FREEZE_MAX_SLOTS];
    uint32_t existing = 0;
    if (freeze_load_slots(pid, slots, FREEZE_MAX_SLOTS, &existing) != 0) existing = 0;

    uint32_t added = 0, total = existing;
    for (uint32_t i = 0; i < want && total < FREEZE_MAX_SLOTS; i++) {
        bool dup = false;
        for (uint32_t k = 0; k < total; k++) {
            if (slots[k].addr == addrs[i]) { dup = true; break; }
        }
        if (dup) continue;
        slots[total].addr = addrs[i];
        memcpy(slots[total].data, data, 8);
        slots[total].size = size;
        total++;
        added++;
    }
    free(addrs);

    // Write once immediately so the value is correct even before the daemon
    // ticks (or if the daemon fails to start on an unprivileged device).
    uint32_t written = 0;
    for (uint32_t i = 0; i < total; i++) {
        if (raw_write(pid, slots[i].addr, slots[i].data, slots[i].size) == 0) written++;
    }

    if (freeze_save_slots(pid, slots, total) != 0) {
        print_error("Cannot persist freeze state", errno);
        return 1;
    }
    int dpid_ok = freeze_ensure_daemon(pid, interval_ms);
    int dpid = freeze_daemon_pid(pid);

    printf("{\"status\":\"ok\",\"pid\":%d,\"type\":\"%s\",\"added\":%u,\"slots\":%u,"
           "\"written\":%u,\"interval_ms\":%d,\"daemon\":%d,\"running\":%s}\n",
           pid, type_name, added, total, written, interval_ms, dpid,
           (dpid_ok == 0 && dpid > 0) ? "true" : "false");
    return 0;
}

// argv: freeze_remove <pid> [addr ...]   (no addr = clear everything)
static int cmd_freeze_remove(int pid, int argc, char **argv) {
    if (argc == 0) {
        char path[256];
        freeze_state_path(path, sizeof(path), pid);
        unlink(path);
        int dpid = freeze_daemon_pid(pid);
        if (dpid > 0) kill(dpid, SIGTERM);
        // The daemon also removes the pid file when it notices the empty state.
        char pidp[256];
        freeze_pid_path(pidp, sizeof(pidp), pid);
        for (int i = 0; i < 30 && freeze_daemon_pid(pid) > 0; i++) {
            struct timespec ts = { 0, 10 * 1000000L };
            nanosleep(&ts, NULL);
        }
        unlink(pidp);
        printf("{\"status\":\"ok\",\"pid\":%d,\"cleared\":true,\"remaining\":0}\n", pid);
        return 0;
    }

    struct freeze_slot slots[FREEZE_MAX_SLOTS];
    uint32_t n = 0;
    if (freeze_load_slots(pid, slots, FREEZE_MAX_SLOTS, &n) != 0 || n == 0) {
        printf("{\"status\":\"ok\",\"pid\":%d,\"removed\":0,\"remaining\":0}\n", pid);
        return 0;
    }

    uint32_t kept = 0, removed = 0;
    for (uint32_t i = 0; i < n; i++) {
        bool drop = false;
        for (int k = 0; k < argc; k++) {
            if (slots[i].addr == strtoull(argv[k], NULL, 0)) { drop = true; break; }
        }
        if (drop) { removed++; continue; }
        slots[kept++] = slots[i];
    }

    if (kept == 0) {
        char path[256];
        freeze_state_path(path, sizeof(path), pid);
        unlink(path);
        int dpid = freeze_daemon_pid(pid);
        if (dpid > 0) kill(dpid, SIGTERM);
    } else {
        freeze_save_slots(pid, slots, kept);
    }
    printf("{\"status\":\"ok\",\"pid\":%d,\"removed\":%u,\"remaining\":%u}\n", pid, removed, kept);
    return 0;
}

// Report what is frozen and whether the daemon is alive. Values are re-read so
// the caller can see the freeze actually holding.
static int cmd_freeze_list(int pid) {
    struct freeze_slot slots[FREEZE_MAX_SLOTS];
    uint32_t n = 0;
    int dpid = freeze_daemon_pid(pid);

    if (freeze_load_slots(pid, slots, FREEZE_MAX_SLOTS, &n) != 0) n = 0;

    printf("{\"status\":\"ok\",\"pid\":%d,\"daemon\":%d,\"running\":\"%s\",\"count\":%u,\"slots\":[",
           pid, dpid, dpid > 0 ? "true" : "false", n);
    for (uint32_t i = 0; i < n; i++) {
        printf("%s{\"addr\":\"0x%llx\",\"size\":%u,\"data\":\"",
               i ? "," : "", (unsigned long long)slots[i].addr, slots[i].size);
        for (uint32_t b = 0; b < slots[i].size; b++) printf("%02x", slots[i].data[b]);
        printf("\"}");
    }
    printf("]}\n");
    return 0;
}

// ---------------------------------------------------------------------------
// Heap/module dump to a file.
//
// The inline `read` caps at 16 MiB of hex and blows up the JSON on anything
// bigger. A dump streams directly to a file on the device, with a .txt sidecar
// of VMA offsets so the caller can map file offsets back to addresses.
// ---------------------------------------------------------------------------

// argv: dump <pid> <addr|module:NAME> <size|all> <out_path> [perms]
static int cmd_dump(int pid, const char *target, const char *size_arg,
                    const char *out_path, const char *filter_perms) {
    struct vma_table t;
    if (!vma_table_load(pid, &t)) { print_error("Cannot read maps", errno); return 1; }

    uint64_t start = 0, end = 0;
    bool whole_module = false;
    if (strncmp(target, "module:", 7) == 0) {
        uint64_t base = 0, span_end = 0;
        uint32_t vmas = 0;
        if (!module_lookup(&t, target + 7, &base, &span_end, &vmas)) {
            vma_table_free(&t);
            print_error("Module not mapped in this process", ENOENT);
            return 1;
        }
        // A module's segments are not contiguous: dump the union of every VMA
        // that belongs to it, which is what a reverse engineer wants.
        start = base;
        end = 0;
        for (uint32_t i = 0; i < t.count; i++) {
            if (strcmp(vma_leaf(t.items[i].path), target + 7) != 0) continue;
            if (t.items[i].end > end) end = t.items[i].end;
        }
        whole_module = true;
    } else {
        start = strtoull(target, NULL, 0);
        if (strcmp(size_arg, "all") == 0) {
            // Everything readable from `start` onward, stopping at the first
            // unmapped gap.
            end = start;
            bool grew = true;
            while (grew) {
                grew = false;
                for (uint32_t i = 0; i < t.count; i++) {
                    if (!perms_match(t.items[i].perms, filter_perms)) continue;
                    if (t.items[i].start <= end && t.items[i].end > end) {
                        end = t.items[i].end;
                        grew = true;
                    }
                }
            }
            if (end <= start) {
                vma_table_free(&t);
                print_error("No readable region at that address", EINVAL);
                return 1;
            }
        } else {
            uint64_t want = strtoull(size_arg, NULL, 0);
            if (want == 0) { vma_table_free(&t); print_error("size must be > 0", EINVAL); return 1; }
            end = start + want;
        }
    }

    uint64_t total = end - start;
    int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        vma_table_free(&t);
        print_error("Cannot create output file", errno);
        return 1;
    }

    const size_t CHUNK = 256 * 1024;
    uint8_t *buf = (uint8_t *)malloc(CHUNK);
    if (!buf) { close(fd); vma_table_free(&t); print_error("Out of memory", ENOMEM); return 1; }

    char sidecar[600];
    snprintf(sidecar, sizeof(sidecar), "%s.txt", out_path);
    FILE *map = fopen(sidecar, "w");
    if (map) {
        fprintf(map, "# offset addr size perms path\n");
    }

    uint64_t written = 0, unreadable = 0;
    uint64_t cur = start;
    while (cur < end) {
        size_t want = (size_t)(end - cur);
        if (want > CHUNK) want = CHUNK;

        // Find the VMA covering `cur`; when there is none (a gap between
        // mappings) skip ahead to the next one that starts after it.
        uint32_t slot = t.count;
        for (uint32_t i = 0; i < t.count; i++) {
            if (t.items[i].start <= cur && t.items[i].end > cur) { slot = i; break; }
        }
        if (slot == t.count) {
            uint64_t next = end;
            for (uint32_t i = 0; i < t.count; i++) {
                if (t.items[i].start > cur && t.items[i].start < next) next = t.items[i].start;
            }
            // Fill the gap with zeros so file offsets still equal addr-start.
            size_t gap = (size_t)(next - cur);
            memset(buf, 0, gap < CHUNK ? gap : CHUNK);
            if (write(fd, buf, gap < CHUNK ? gap : CHUNK) < 0) break;
            written += gap < CHUNK ? gap : CHUNK;
            unreadable += gap < CHUNK ? gap : CHUNK;
            cur += gap < CHUNK ? gap : CHUNK;
            continue;
        }
        if (t.items[slot].end < cur + want) want = (size_t)(t.items[slot].end - cur);

        // raw_read fills holes inside the span with zeros and still returns the
        // readable pages, so byte counts are per page, not per chunk. A chunk
        // wholly inside one VMA that fails is an unbacked region (dalvik
        // reserves its heap without committing it), which is normal.
        if (!raw_read(pid, cur, buf, want)) unreadable += want;
        if (write(fd, buf, want) < 0) break;
        if (map) {
            fprintf(map, "0x%llx 0x%llx 0x%llx %s %s\n",
                    (unsigned long long)(cur - start), (unsigned long long)cur,
                    (unsigned long long)want, t.items[slot].perms,
                    t.items[slot].path[0] ? t.items[slot].path : "[anon]");
        }
        written += want;
        cur += want;
    }
    if (map) fclose(map);
    fsync(fd);
    close(fd);
    free(buf);
    vma_table_free(&t);

    printf("{\"status\":\"ok\",\"pid\":%d,\"start\":\"0x%llx\",\"end\":\"0x%llx\","
           "\"span_bytes\":%llu,\"bytes\":%llu,\"unreadable_bytes\":%llu,"
           "\"file\":\"%s\",\"map_file\":\"%s\",\"module\":%s}\n",
           pid, (unsigned long long)start, (unsigned long long)end,
           (unsigned long long)total, (unsigned long long)written,
           (unsigned long long)unreadable,
           out_path, sidecar, whole_module ? "true" : "false");
    return 0;
}

// ---------------------------------------------------------------------------
// Module-relative (RVA) scanning.
//
// Absolute addresses are worthless across a restart. The stable identifier is
// "offset inside libX.so", so an RVA scan reports module + offset (+0x..) and
// never the absolute address. Value semantics are identical to `scan`, but the
// ranges are restricted to the module's own VMAs.
// ---------------------------------------------------------------------------

// argv: scan_rva <pid> <module> <type> <value> [align]
static int cmd_scan_rva(int pid, const char *module, const char *type_name,
                        const char *val_str, int custom_align) {
    uint8_t elem_size = 4, align = 4;
    uint8_t type = scan_type_from_name(type_name, &elem_size, &align);
    if (type == 0) { print_error("Invalid scan type", EINVAL); return 1; }
    if (custom_align > 0) align = (uint8_t)custom_align;

    uint64_t criteria_val = 0;
    if (type == HMKPM_SCAN_TYPE_F32) {
        float f = strtof(val_str, NULL);
        memcpy(&criteria_val, &f, 4);
    } else if (type == HMKPM_SCAN_TYPE_F64) {
        double d = strtod(val_str, NULL);
        memcpy(&criteria_val, &d, 8);
    } else if (type == HMKPM_SCAN_TYPE_I64) {
        criteria_val = (uint64_t)strtoll(val_str, NULL, 0);
    } else if (type == HMKPM_SCAN_TYPE_U64) {
        criteria_val = strtoull(val_str, NULL, 0);
    } else {
        criteria_val = (uint64_t)strtoll(val_str, NULL, 0);
    }

    struct vma_table t;
    if (!vma_table_load(pid, &t)) { print_error("Cannot read maps", errno); return 1; }

    uint64_t base = 0, span_end = 0;
    uint32_t vmas = 0;
    if (!module_lookup(&t, module, &base, &span_end, &vmas)) {
        vma_table_free(&t);
        print_error("Module not mapped in this process", ENOENT);
        return 1;
    }

    // Only the module's own readable segments are scanned. The base is the
    // mapping whose file offset is 0, so an RVA equals (addr - base) even
    // though the segments are not contiguous.
    struct hmkpm_scan_range *ranges =
        (struct hmkpm_scan_range *)malloc(sizeof(struct hmkpm_scan_range) * (vmas ? vmas : 1));
    if (!ranges) { vma_table_free(&t); print_error("Out of memory", ENOMEM); return 1; }
    uint32_t rc = 0;
    for (uint32_t i = 0; i < t.count; i++) {
        if (strcmp(vma_leaf(t.items[i].path), module) != 0) continue;
        if (!perms_match(t.items[i].perms, NULL)) continue;
        ranges[rc].start_va = t.items[i].start;
        ranges[rc].size = t.items[i].end - t.items[i].start;
        rc++;
    }
    vma_table_free(&t);

    if (rc == 0) {
        free(ranges);
        printf("{\"status\":\"ok\",\"pid\":%d,\"module\":\"%s\",\"base\":\"0x%llx\","
               "\"matches_found\":0,\"rvas\":[]}\n",
               pid, module, (unsigned long long)base);
        return 0;
    }

    #define RVA_MAX_MATCHES 4096
    uint64_t found = 0;
    uint32_t reported = 0;
    uint64_t *matches = NULL;
    if (!kernel_scan_ranges(pid, type, align, criteria_val, ranges, rc,
                            RVA_MAX_MATCHES, &found, &matches, &reported)) {
        free(ranges);
        print_error("HMKPM scan kernel syscall failed", errno ? errno : EFAULT);
        return 1;
    }
    free(ranges);

    printf("{\"status\":\"ok\",\"pid\":%d,\"module\":\"%s\",\"base\":\"0x%llx\","
           "\"matches_found\":%llu,\"truncated\":%s,\"rvas\":[",
           pid, module, (unsigned long long)base, (unsigned long long)found,
           found > RVA_MAX_MATCHES ? "true" : "false");
    for (uint32_t i = 0; i < reported; i++) {
        printf("%s\"0x%llx\"", i ? "," : "",
               (unsigned long long)(matches[i] - base));
    }
    printf("]}\n");
    free(matches);
    return 0;
}

// ---------------------------------------------------------------------------
// ARM64 instruction-pattern search.
//
// Game logic that resets a value lives in code, not data, so finding the
// instruction that writes a field is a routine step when a memory freeze is not
// appropriate. The pattern is an ARM64 encoding where some bit fields are fixed
// and the rest are wildcards, e.g. "B9000000/FFF00000" for a 32-bit STR with
// any Rt/Rn/offset. Matching is over little-endian 4-byte words.
// ---------------------------------------------------------------------------

// argv: find_instructions <pid> <pattern[/mask]> <module|perms> [limit]
static int cmd_find_instructions(int pid, const char *pattern, const char *where, int limit) {
    char value_s[32] = {0}, mask_s[32] = {0};
    const char *slash = strchr(pattern, '/');
    if (slash) {
        size_t n = (size_t)(slash - pattern);
        if (n >= sizeof(value_s)) { print_error("Pattern too long", EINVAL); return 1; }
        memcpy(value_s, pattern, n);
        value_s[n] = '\0';
        snprintf(mask_s, sizeof(mask_s), "%s", slash + 1);
    } else {
        snprintf(value_s, sizeof(value_s), "%s", pattern);
        snprintf(mask_s, sizeof(mask_s), "FFFFFFFF");
    }

    uint32_t value = (uint32_t)strtoul(value_s, NULL, 16);
    uint32_t mask  = (uint32_t)strtoul(mask_s, NULL, 16);
    if (mask == 0) { print_error("Mask must not be zero", EINVAL); return 1; }
    if (limit <= 0) limit = 100;

    struct vma_table t;
    if (!vma_table_load(pid, &t)) { print_error("Cannot read maps", errno); return 1; }

    // Executable, readable segments: either one module's code or every VMA
    // that matches the permission filter.
    bool by_module = strchr(where, '.') != NULL || strchr(where, '/') != NULL;
    bool by_perm = !by_module && strchr(where, 'x') != NULL;

    uint64_t base = 0;
    if (by_module) {
        uint64_t span_end = 0;
        uint32_t vmas = 0;
        if (!module_lookup(&t, where, &base, &span_end, &vmas)) {
            vma_table_free(&t);
            print_error("Module not mapped in this process", ENOENT);
            return 1;
        }
    }

    printf("{\"status\":\"ok\",\"pid\":%d,\"pattern\":\"%08x/%08x\",\"matches\":[",
           pid, value, mask);

    const size_t CHUNK = 256 * 1024;
    uint8_t *buf = (uint8_t *)malloc(CHUNK);
    if (!buf) { vma_table_free(&t); print_error("Out of memory", ENOMEM); return 1; }

    int found = 0;
    for (uint32_t i = 0; i < t.count && found < limit; i++) {
        struct vma *v = &t.items[i];
        if (v->perms[2] != 'x' || v->perms[0] != 'r') continue;
        if (by_module) {
            const char *leaf = vma_leaf(v->path);
            if (strcmp(leaf, where) != 0) continue;
        } else if (by_perm) {
            if (!perms_match(v->perms, where)) continue;
        }

        uint64_t cur = v->start;
        while (cur < v->end && found < limit) {
            size_t want = (size_t)(v->end - cur);
            if (want > CHUNK) want = CHUNK;
            if (raw_read(pid, cur, buf, want)) {
                for (size_t off = 0; off + 4 <= want && found < limit; off += 4) {
                    uint32_t insn;
                    memcpy(&insn, buf + off, 4);
                    if ((insn & mask) != (value & mask)) continue;
                    uint64_t at = cur + off;
                    // A bare absolute address is useless after a restart, so an
                    // RVA is always reported alongside it when it is inside a
                    // module.
                    if (by_module) {
                        printf("%s{\"addr\":\"0x%llx\",\"rva\":\"0x%llx\",\"insn\":\"%08x\"}",
                               found ? "," : "", (unsigned long long)at,
                               (unsigned long long)(at - base), insn);
                    } else {
                        const char *leaf = vma_leaf(v->path);
                        if (leaf[0] && strchr(leaf, '.')) {
                            uint64_t mbase = 0, mspan = 0;
                            uint32_t mvmas = 0;
                            module_lookup(&t, leaf, &mbase, &mspan, &mvmas);
                            printf("%s{\"addr\":\"0x%llx\",\"module\":\"%s\",\"rva\":\"0x%llx\",\"insn\":\"%08x\"}",
                                   found ? "," : "", (unsigned long long)at, leaf,
                                   (unsigned long long)(at >= mbase ? at - mbase : 0), insn);
                        } else {
                            printf("%s{\"addr\":\"0x%llx\",\"insn\":\"%08x\"}",
                                   found ? "," : "", (unsigned long long)at, insn);
                        }
                    }
                    found++;
                }
            }
            cur += want;
        }
    }
    printf("],\"count\":%d}\n", found);

    free(buf);
    vma_table_free(&t);
    return 0;
}

// Internal: a writable test target. `_hold <millis>` allocates a page, stamps
// a known pattern into it and sleeps, so write/freeze paths have a real process
// to work against without ever touching an app's live heap. Not exposed to MCP.
static int cmd_hold(int millis) {
    if (millis <= 0) millis = 1000;
    if (millis > 3600000) millis = 3600000;
    // A dedicated anonymous mapping, not malloc: glibc's allocator hands out
    // addresses from a large reservation whose pages are not resident until
    // touched, and the kernel cannot read an unbacked page.
    size_t len = PAGE_SIZE_ * 4;
    void *mem = mmap(NULL, len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (mem == MAP_FAILED) { print_error("mmap failed", errno); return 1; }
    volatile uint32_t *page = (volatile uint32_t *)mem;
    for (size_t i = 0; i < len / 4; i++) page[i] = 0x11111111u;
    printf("{\"status\":\"ok\",\"pid\":%d,\"addr\":\"0x%llx\",\"size\":%zu}\n",
           (int)getpid(), (unsigned long long)(uintptr_t)mem, len);
    fflush(stdout);
    struct timespec ts = { millis / 1000, (long)(millis % 1000) * 1000000L };
    nanosleep(&ts, NULL);
    munmap(mem, len);
    return 0;
}

// ---------------------------------------------------------------------------
// Embedded Lua.
//
// The CLI's own commands are one operation per process: an MCP client that
// wants "scan, filter, confirm, write, re-check" pays a process spawn and a
// round trip for each step. A script collapses that into one call and can keep
// state across steps.
//
// Design constraints that shaped this:
//   - The Lua API is SYNCHRONOUS and calls the same internal helpers the
//     commands use (raw_read, raw_write, kernel_scan_ranges). No subprocess and
//     no JSON parsing, so a script's read costs one syscall, not a fork.
//   - Lua cannot outlive the call. It is a scripting layer over memory access,
//     not a resident agent, so there is no way to leave code running inside the
//     CLI or the target.
//   - Only safe libraries are opened: no io, no os.execute, no package loader.
//     A script must not be able to spawn processes or read files on its own;
//     everything it does goes through the explicit hm.* functions.
//   - Every loop-invoked hm.* function checks `lua_sethook`'s instruction
//     budget so a runaway `while true do hm.read(...) end` is interrupted
//     rather than hanging the MCP call until its timeout.
// ---------------------------------------------------------------------------

#include "vendor/lua/lua.h"
#include "vendor/lua/lauxlib.h"
#include "vendor/lua/lualib.h"

#define LUA_SCRIPT_BYTES_MAX  (256 * 1024)   // script size cap
#define LUA_RESULT_BYTES_MAX  (16 * 1024 * 1024)
#define LUA_SCAN_HITS_MAX     200000         // per hm.scan call
#define LUA_TIMEOUT_DEFAULT   30             // seconds

// The target pid is bound once at script start rather than passed to every
// call, matching how the commands already work.
static int g_lua_pid = 0;

static uint8_t lua_type_code(lua_State *L, int idx) {
    const char *name = luaL_checkstring(L, idx);
    uint8_t size = 4, align = 4;
    uint8_t t = scan_type_from_name(name, &size, &align);
    if (t == 0) luaL_error(L, "invalid type '%s'", name);
    return t;
}

static uint8_t lua_type_size(uint8_t type) {
    switch (type) {
        case HMKPM_SCAN_TYPE_I8: case HMKPM_SCAN_TYPE_U8: return 1;
        case HMKPM_SCAN_TYPE_I16: case HMKPM_SCAN_TYPE_U16: return 2;
        case HMKPM_SCAN_TYPE_I32: case HMKPM_SCAN_TYPE_U32: case HMKPM_SCAN_TYPE_F32: return 4;
        default: return 8;
    }
}

// Push a typed value onto the Lua stack. Unsigned and float widths are handled
// explicitly so a u64 above 2^63 does not come back negative.
static void lua_push_typed(lua_State *L, uint8_t type, const uint8_t *raw) {
    switch (type) {
        case HMKPM_SCAN_TYPE_I8:  lua_pushinteger(L, *(const int8_t *)raw); break;
        case HMKPM_SCAN_TYPE_U8:  lua_pushinteger(L, *(const uint8_t *)raw); break;
        case HMKPM_SCAN_TYPE_I16: lua_pushinteger(L, *(const int16_t *)raw); break;
        case HMKPM_SCAN_TYPE_U16: lua_pushinteger(L, *(const uint16_t *)raw); break;
        case HMKPM_SCAN_TYPE_I32: lua_pushinteger(L, *(const int32_t *)raw); break;
        case HMKPM_SCAN_TYPE_U32: lua_pushinteger(L, *(const uint32_t *)raw); break;
        case HMKPM_SCAN_TYPE_I64: lua_pushinteger(L, (lua_Integer)*(const int64_t *)raw); break;
        case HMKPM_SCAN_TYPE_U64: {
            // lua_Integer is 64-bit signed and Lua 5.4 wraps on overflow, which
            // is exactly the bit pattern a caller wants for an unsigned value.
            uint64_t v; memcpy(&v, raw, 8); lua_pushinteger(L, (lua_Integer)v);
            break;
        }
        case HMKPM_SCAN_TYPE_F32: lua_pushnumber(L, (lua_Number)*(const float *)raw); break;
        case HMKPM_SCAN_TYPE_F64: lua_pushnumber(L, (lua_Number)*(const double *)raw); break;
        default: lua_pushnil(L); break;
    }
}

// Encode a Lua value into bytes for the requested type.
static void lua_encode_typed(lua_State *L, uint8_t type, int idx, uint8_t *raw) {
    memset(raw, 0, 8);
    switch (type) {
        case HMKPM_SCAN_TYPE_I8:  *(int8_t *)raw = (int8_t)luaL_checkinteger(L, idx); break;
        case HMKPM_SCAN_TYPE_U8:  *(uint8_t *)raw = (uint8_t)lua_tointeger(L, idx); break;
        case HMKPM_SCAN_TYPE_I16: *(int16_t *)raw = (int16_t)luaL_checkinteger(L, idx); break;
        case HMKPM_SCAN_TYPE_U16: *(uint16_t *)raw = (uint16_t)lua_tointeger(L, idx); break;
        case HMKPM_SCAN_TYPE_I32: *(int32_t *)raw = (int32_t)luaL_checkinteger(L, idx); break;
        case HMKPM_SCAN_TYPE_U32: *(uint32_t *)raw = (uint32_t)lua_tointeger(L, idx); break;
        case HMKPM_SCAN_TYPE_I64: *(int64_t *)raw = (int64_t)luaL_checkinteger(L, idx); break;
        case HMKPM_SCAN_TYPE_U64: *(uint64_t *)raw = (uint64_t)lua_tointeger(L, idx); break;
        case HMKPM_SCAN_TYPE_F32: *(float *)raw = (float)luaL_checknumber(L, idx); break;
        case HMKPM_SCAN_TYPE_F64: *(double *)raw = (double)luaL_checknumber(L, idx); break;
        default: break;
    }
}

// Addresses arrive as integers or hex strings ("0x7f..."), because a Lua number
// cannot represent a 64-bit address without losing bits once it is a double.
static uint64_t lua_to_addr(lua_State *L, int idx) {
    if (lua_isstring(L, idx)) return strtoull(lua_tostring(L, idx), NULL, 0);
    lua_Integer v = luaL_checkinteger(L, idx);
    return (uint64_t)v;
}

// hm.read(addr, type) -> value, or nil + errno when unreadable.
static int lua_hm_read(lua_State *L) {
    uint64_t addr = lua_to_addr(L, 1);
    uint8_t type = lua_type_code(L, 2);
    uint8_t size = lua_type_size(type);
    uint8_t raw[8];
    if (!raw_read_exact(g_lua_pid, addr, raw, size)) {
        lua_pushnil(L);
        lua_pushinteger(L, EFAULT);
        return 2;
    }
    lua_push_typed(L, type, raw);
    return 1;
}

// hm.write(addr, type, value) -> true, or nil + errno.
static int lua_hm_write(lua_State *L) {
    uint64_t addr = lua_to_addr(L, 1);
    uint8_t type = lua_type_code(L, 2);
    uint8_t size = lua_type_size(type);
    uint8_t raw[8];
    lua_encode_typed(L, type, 3, raw);
    int err = raw_write(g_lua_pid, addr, raw, size);
    if (err) {
        lua_pushnil(L);
        lua_pushinteger(L, err);
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}

// hm.read_bytes(addr, n) -> string [, unreadable_byte_count]
//
// raw_read zero-fills pages the kernel refuses, so the bytes that do exist are
// still worth returning: discarding a 1 MiB read because one page in the middle
// is unmapped defeats the purpose. The buffer is always returned, and the count
// of bytes that could not be read is passed as a second value so a caller can
// decide whether to trust it.
static int lua_hm_read_bytes(lua_State *L) {
    uint64_t addr = lua_to_addr(L, 1);
    lua_Integer n = luaL_checkinteger(L, 2);
    if (n <= 0 || n > (lua_Integer)LUA_RESULT_BYTES_MAX) {
        return luaL_error(L, "read_bytes size must be 1..%d", LUA_RESULT_BYTES_MAX);
    }
    // malloc + pushlstring rather than userdata: Lua strings are immutable and
    // the bytes are needed on the stack anyway, so a second copy is wasted work.
    char *buf = (char *)malloc((size_t)n);
    if (!buf) return luaL_error(L, "out of memory");
    size_t holes = 0;
    bool all = raw_read_count(g_lua_pid, addr, buf, (size_t)n, &holes);
    if (holes == (size_t)n) {
        // Nothing at all was readable: this is a failed read, not a partial one,
        // so report it the same way hm.read does.
        free(buf);
        lua_pushnil(L);
        lua_pushinteger(L, EFAULT);
        return 2;
    }
    lua_pushlstring(L, buf, (size_t)n);
    free(buf);
    if (all) return 1;
    // Partial read: the buffer is still returned, with the number of zero-filled
    // bytes as a second value. A caller that needs guaranteed-valid data must
    // check it; one that only needs the surrounding bytes can use them.
    lua_pushinteger(L, (lua_Integer)holes);
    return 2;
}

// hm.write_bytes(addr, string) -> true or nil + errno.
static int lua_hm_write_bytes(lua_State *L) {
    uint64_t addr = lua_to_addr(L, 1);
    size_t n = 0;
    const char *s = luaL_checklstring(L, 2, &n);
    int err = raw_write(g_lua_pid, addr, s, n);
    if (err) { lua_pushnil(L); lua_pushinteger(L, err); return 2; }
    lua_pushboolean(L, 1);
    return 1;
}

// hm.map(path_filter) -> list of {start, stop, size, perms, path}
static int lua_hm_map(lua_State *L) {
    const char *filter = luaL_optstring(L, 1, NULL);
    struct vma_table t;
    if (!vma_table_load(g_lua_pid, &t)) {
        lua_pushnil(L);
        lua_pushinteger(L, errno);
        return 2;
    }
    lua_newtable(L);
    int n = 0;
    for (uint32_t i = 0; i < t.count; i++) {
        if (filter && *filter && !strstr(t.items[i].path, filter)) continue;
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)t.items[i].start); lua_setfield(L, -2, "start");
        lua_pushinteger(L, (lua_Integer)t.items[i].end);   lua_setfield(L, -2, "stop");
        lua_pushinteger(L, (lua_Integer)(t.items[i].end - t.items[i].start));
        lua_setfield(L, -2, "size");
        lua_pushstring(L, t.items[i].perms);               lua_setfield(L, -2, "perms");
        lua_pushstring(L, t.items[i].path);                lua_setfield(L, -2, "path");
        lua_rawseti(L, -2, ++n);
    }
    vma_table_free(&t);
    return 1;
}

// hm.module(name) -> {base, stop, name} or nil + errno
static int lua_hm_module(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    struct vma_table t;
    if (!vma_table_load(g_lua_pid, &t)) {
        lua_pushnil(L); lua_pushinteger(L, errno); return 2;
    }
    uint64_t base = 0, end = 0;
    uint32_t vmas = 0;
    bool found = module_lookup(&t, name, &base, &end, &vmas);
    vma_table_free(&t);
    if (!found) { lua_pushnil(L); lua_pushinteger(L, ENOENT); return 2; }
    lua_newtable(L);
    lua_pushinteger(L, (lua_Integer)base);  lua_setfield(L, -2, "base");
    lua_pushinteger(L, (lua_Integer)end);   lua_setfield(L, -2, "stop");
    lua_pushinteger(L, (lua_Integer)vmas);  lua_setfield(L, -2, "vmas");
    lua_pushstring(L, name);                lua_setfield(L, -2, "name");
    return 1;
}

// hm.chain(base, rva, {off1, off2, ...}) -> address, or nil + step index.
// Mirrors pointer_chain: every offset but the last is dereferenced.
static int lua_hm_chain(lua_State *L) {
    uint64_t cur;
    // An address is pure hex ("0x7f..."); a module name ("libil2cpp.so")
    // contains characters an address never would, so the two are separable.
    bool is_module = false;
    char module_buf[256];
    if (lua_isstring(L, 1)) {
        const char *s = lua_tostring(L, 1);
        size_t hex_len = strspn(s, "0123456789xXabcdefABCDEF");
        if (hex_len != strlen(s) || hex_len == 0) {
            snprintf(module_buf, sizeof(module_buf), "%s", s);
            is_module = true;
        }
    }
    if (is_module) {
        struct vma_table t;
        if (!vma_table_load(g_lua_pid, &t)) { lua_pushnil(L); lua_pushinteger(L, errno); return 2; }
        uint64_t base = 0, end = 0;
        uint32_t vmas = 0;
        bool found = module_lookup(&t, module_buf, &base, &end, &vmas);
        vma_table_free(&t);
        if (!found) { lua_pushnil(L); lua_pushinteger(L, ENOENT); return 2; }
        cur = base;
    } else {
        cur = lua_to_addr(L, 1);
    }
    cur += lua_to_addr(L, 2);

    lua_Integer n = 0;
    if (!lua_isnoneornil(L, 3)) {
        luaL_checktype(L, 3, LUA_TTABLE);
        n = (lua_Integer)lua_rawlen(L, 3);
    }
    for (lua_Integer i = 1; i <= n; i++) {
        lua_rawgeti(L, 3, i);
        int64_t off = (int64_t)lua_to_addr(L, -1);
        lua_pop(L, 1);
        uint64_t at = (uint64_t)((int64_t)cur + off);
        if (i == n) { cur = at; break; }           // final field, no deref
        uint8_t raw[8];
        if (!raw_read_exact(g_lua_pid, at, raw, 8)) {
            lua_pushnil(L);
            lua_pushinteger(L, i);                 // failing step
            return 2;
        }
        uint64_t ptr; memcpy(&ptr, raw, 8);
        if (ptr == 0 || ptr >= USER_ADDR_MAX) {
            lua_pushnil(L);
            lua_pushinteger(L, i);
            return 2;
        }
        cur = ptr;
    }
    lua_pushinteger(L, (lua_Integer)cur);
    return 1;
}

// hm.b64(data) -> base64 string. Turns arbitrary bytes into something that
// survives a JSON response unaffected by control characters.
static int lua_hm_b64(lua_State *L) {
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = 0;
    const unsigned char *s = (const unsigned char *)luaL_checklstring(L, 1, &n);
    size_t out_len = ((n + 2) / 3) * 4;
    char *out = (char *)malloc(out_len + 1);
    if (!out) { lua_pushnil(L); return 1; }
    size_t k = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)s[i] << 16;
        if (i + 1 < n) v |= (uint32_t)s[i + 1] << 8;
        if (i + 2 < n) v |= s[i + 2];
        out[k++] = tab[(v >> 18) & 63];
        out[k++] = tab[(v >> 12) & 63];
        out[k++] = (i + 1 < n) ? tab[(v >> 6) & 63] : '=';
        out[k++] = (i + 2 < n) ? tab[v & 63] : '=';
    }
    lua_pushlstring(L, out, k);
    free(out);
    return 1;
}

// hm.scan(type, value, opts) -> array of {addr, value}
// opts: align (default from type), perms (default "rw-p"), limit, ranges
// (explicit {{start,size},...} used by the RVA helpers below).
static int lua_hm_scan(lua_State *L) {
    uint8_t type = lua_type_code(L, 1);
    uint8_t size = lua_type_size(type);
    // decode into a full 64-bit word: kernel_scan_ranges takes a uint64_t and a
    // narrower type must not leave the upper bytes as stack garbage.
    uint64_t criteria = 0;
    lua_encode_typed(L, type, 2, (uint8_t *)&criteria);

    lua_Integer align = 0, limit = 0;
    char perms_buf[16];
    snprintf(perms_buf, sizeof(perms_buf), "rw-p");
    const char *perms = perms_buf;
    char module_buf[256];
    const char *module = NULL;
    if (lua_istable(L, 3)) {
        // Field reads must not leave a value on the stack below the calls that
        // follow, and luaL_checkstring may convert in place, so copy the string
        // out before popping the field.
        lua_getfield(L, 3, "align");
        if (lua_isnumber(L, -1)) align = lua_tointeger(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, 3, "limit");
        if (lua_isnumber(L, -1)) limit = lua_tointeger(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, 3, "perms");
        if (lua_isstring(L, -1)) {
            snprintf(perms_buf, sizeof(perms_buf), "%s", lua_tostring(L, -1));
            perms = perms_buf;
        }
        lua_pop(L, 1);

        lua_getfield(L, 3, "module");
        if (lua_isstring(L, -1)) {
            snprintf(module_buf, sizeof(module_buf), "%s", lua_tostring(L, -1));
            module = module_buf;
        }
        lua_pop(L, 1);
    }
    if (align <= 0) align = size;
    // The kernel needs a working output window to report hits: below roughly
    // 4k slots it stops early and silently under-reports. Default high enough
    // that a plain hm.scan(type, value) is trustworthy.
    if (limit <= 0 || limit > LUA_SCAN_HITS_MAX) limit = 65536;

    struct hmkpm_scan_range *ranges = NULL;
    uint32_t range_count = 0;
    struct vma_table t;

    if (module) {
        // Module-scoped scan: only that module's readable VMAs.
        if (!vma_table_load(g_lua_pid, &t)) {
            lua_pushnil(L); lua_pushinteger(L, errno); return 2;
        }
        ranges = (struct hmkpm_scan_range *)malloc(sizeof(struct hmkpm_scan_range) * (t.count ? t.count : 1));
        if (!ranges) { vma_table_free(&t); lua_pushnil(L); lua_pushinteger(L, ENOMEM); return 2; }
        for (uint32_t i = 0; i < t.count; i++) {
            if (strcmp(vma_leaf(t.items[i].path), module) != 0) continue;
            if (!perms_match(t.items[i].perms, NULL)) continue;
            ranges[range_count].start_va = t.items[i].start;
            ranges[range_count].size = t.items[i].end - t.items[i].start;
            range_count++;
        }
        vma_table_free(&t);
    } else {
        ranges = collect_ranges_alloc(g_lua_pid, perms, &range_count);
    }

    if (range_count == 0) {
        free(ranges);
        lua_newtable(L);
        return 1;
    }
    // Surface what the scan actually decided to read: a silent empty result is
    // indistinguishable from a bad filter without this.
    lua_getglobal(L, "__hm_dbg");
    if (lua_type(L, -1) == LUA_TTABLE) {
        lua_pushinteger(L, range_count);
        lua_setfield(L, -2, "ranges");
        lua_pushstring(L, perms);
        lua_setfield(L, -2, "perms");
        lua_pushstring(L, module ? module : "");
        lua_setfield(L, -2, "module");
        lua_pushinteger(L, align);
        lua_setfield(L, -2, "align");
    }
    lua_pop(L, 1);

    uint64_t found = 0;
    uint32_t reported = 0;
    uint64_t *matches = NULL;
    bool ok = kernel_scan_ranges(g_lua_pid, type, (uint8_t)align, criteria,
                                 ranges, range_count, (uint32_t)limit, &found,
                                 &matches, &reported);
    free(ranges);
    if (!ok) {
        free(matches);
        lua_pushnil(L);
        lua_pushinteger(L, errno ? errno : EFAULT);
        return 2;
    }

    lua_createtable(L, (int)reported, 0);
    for (uint32_t i = 0; i < reported; i++) {
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)matches[i]);
        lua_setfield(L, -2, "addr");
        // Read the current value back so a script sees what is there now, not
        // what it asked for (a scan only proves the match at scan time).
        uint8_t cur[8];
        if (raw_read_exact(g_lua_pid, matches[i], cur, size)) {
            lua_push_typed(L, type, cur);
            lua_setfield(L, -2, "value");
        }
        lua_rawseti(L, -2, (lua_Integer)i + 1);
    }
    free(matches);
    return 1;
}

// hm.freeze(list, type, value, interval_ms) -> count written.
// Resolves to the same daemon the freeze_value tool uses, so a script's freeze
// is visible to (and releasable by) the MCP layer.
static int lua_hm_freeze(lua_State *L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    uint8_t type = lua_type_code(L, 2);
    uint8_t size = lua_type_size(type);
    uint8_t raw[8];
    lua_encode_typed(L, type, 3, raw);
    lua_Integer interval = luaL_optinteger(L, 4, 50);

    struct freeze_slot slots[FREEZE_MAX_SLOTS];
    uint32_t existing = 0;
    if (freeze_load_slots(g_lua_pid, slots, FREEZE_MAX_SLOTS, &existing) != 0) existing = 0;

    lua_Integer n = (lua_Integer)lua_rawlen(L, 1);
    for (lua_Integer i = 1; i <= n && existing < FREEZE_MAX_SLOTS; i++) {
        lua_rawgeti(L, 1, i);
        uint64_t addr = lua_to_addr(L, -1);
        lua_pop(L, 1);
        bool dup = false;
        for (uint32_t k = 0; k < existing; k++) {
            if (slots[k].addr == addr) { dup = true; break; }
        }
        if (dup) continue;
        slots[existing].addr = addr;
        memcpy(slots[existing].data, raw, 8);
        slots[existing].size = size;
        existing++;
    }

    uint32_t written = 0;
    for (uint32_t i = 0; i < existing; i++) {
        if (raw_write(g_lua_pid, slots[i].addr, slots[i].data, slots[i].size) == 0) written++;
    }
    if (freeze_save_slots(g_lua_pid, slots, existing) != 0) {
        lua_pushnil(L); lua_pushinteger(L, errno); return 2;
    }
    freeze_ensure_daemon(g_lua_pid, (int)interval);
    lua_pushinteger(L, (lua_Integer)written);
    return 1;
}

// hm.unfreeze() -> true
static int lua_hm_unfreeze(lua_State *L) {
    char path[256];
    freeze_state_path(path, sizeof(path), g_lua_pid);
    unlink(path);
    int dpid = freeze_daemon_pid(g_lua_pid);
    if (dpid > 0) kill(dpid, SIGTERM);
    lua_pushboolean(L, 1);
    return 1;
}

// hm.log(...) -> appends a line to the script's captured output.
static int lua_hm_log(lua_State *L) {
    int n = lua_gettop(L);
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    for (int i = 1; i <= n; i++) {
        if (i > 1) luaL_addchar(&b, '\t');
        size_t len = 0;
        // luaL_tolstring pushes a copy, so use it directly instead of the
        // userdata it may also create (which the buffer could collect).
        const char *s = luaL_tolstring(L, i, &len);
        luaL_addlstring(&b, s, len);
        lua_pop(L, 1);
    }
    luaL_addchar(&b, '\n');
    luaL_pushresult(&b);
    // Reading the global leaves the buffer on top; concatenating in place
    // avoids holding two references across a possible allocation.
    lua_getglobal(L, "__hm_logbuf");
    lua_insert(L, -2);
    lua_concat(L, 2);
    lua_setglobal(L, "__hm_logbuf");
    return 0;
}

// hm.sleep(ms) — a script that polls a changing value needs to wait, and there
// is no os library visible to it.
static int lua_hm_sleep(lua_State *L) {
    lua_Integer ms = luaL_checkinteger(L, 1);
    if (ms > 0) {
        struct timespec ts = { (time_t)(ms / 1000), (long)(ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
    }
    return 0;
}

static const luaL_Reg hm_funcs[] = {
    { "read",        lua_hm_read },
    { "write",       lua_hm_write },
    { "read_bytes",  lua_hm_read_bytes },
    { "write_bytes", lua_hm_write_bytes },
    { "chain",       lua_hm_chain },
    { "scan",        lua_hm_scan },
    { "freeze",      lua_hm_freeze },
    { "unfreeze",    lua_hm_unfreeze },
    { "module",      lua_hm_module },
    { "map",         lua_hm_map },
    { "b64",         lua_hm_b64 },
    { "log",         lua_hm_log },
    { "sleep",       lua_hm_sleep },
    { NULL, NULL },
};

// Interrupt a script that has run too long.
//
// The hook fires every N VM instructions. A plain wall-clock comparison is not
// enough: a `pcall` around a `while true do end` turns the error into a normal
// return value and the loop simply continues, so each entry must also force
// the VM to stop. Lua has no "abort" flag, but a hook that raises an error the
// interpreter cannot swallow does: repeated instructions with a trip count of
// 0 re-fire on the very next instruction, and the error path terminates.
static volatile int g_lua_deadline_hit = 0;
static int64_t g_lua_deadline_ms = 0;

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void lua_timeout_hook(lua_State *L, lua_Debug *ar) {
    (void)ar;
    if (now_ms() < g_lua_deadline_ms) return;
    g_lua_deadline_hit = 1;
    // Once the budget is gone, stop checking instructions entirely and unwind.
    lua_sethook(L, NULL, 0, 0);
    luaL_error(L, "script exceeded its time budget");
}

// JSON-escape a string into a FILE*. Control bytes become \uXXXX so the output
// is always valid JSON regardless of what the script logged.
static void json_escape(FILE *f, const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n", f); break;
            case '\r': fputs("\\r", f); break;
            case '\t': fputs("\\t", f); break;
            default:
                if (c < 32) fprintf(f, "\\u%04x", c);
                else fputc(c, f);
        }
    }
}

// argv: run_lua <pid> <script_path|-> [timeout_s]
// `-` reads the script from stdin so a caller can pass it inline.
static int cmd_run_lua(int pid, const char *script_arg, int timeout_s) {
    char *src = NULL;
    size_t src_len = 0;

    if (strcmp(script_arg, "-") == 0) {
        // Read stdin in bounded chunks; a caller piping a script must not be
        // able to exhaust memory.
        size_t cap = 8192;
        src = (char *)malloc(cap);
        if (!src) { print_error("Out of memory", ENOMEM); return 1; }
        for (;;) {
            if (src_len == cap) {
                if (cap >= LUA_SCRIPT_BYTES_MAX) {
                    free(src);
                    print_error("Script exceeds the size limit", E2BIG);
                    return 1;
                }
                cap *= 2;
                char *grown = (char *)realloc(src, cap);
                if (!grown) { free(src); print_error("Out of memory", ENOMEM); return 1; }
                src = grown;
            }
            ssize_t n = read(STDIN_FILENO, src + src_len, cap - src_len);
            if (n < 0) { if (errno == EINTR) continue; break; }
            if (n == 0) break;
            src_len += (size_t)n;
        }
        src[src_len < cap ? src_len : cap - 1] = '\0';
    } else {
        FILE *f = fopen(script_arg, "rb");
        if (!f) { print_error("Cannot open script file", errno); return 1; }
        if (fseek(f, 0, SEEK_END) == 0) {
            long sz = ftell(f);
            if (sz > 0 && (size_t)sz > LUA_SCRIPT_BYTES_MAX) {
                fclose(f);
                print_error("Script exceeds the size limit", E2BIG);
                return 1;
            }
            rewind(f);
        }
        src = (char *)malloc(LUA_SCRIPT_BYTES_MAX + 1);
        if (!src) { fclose(f); print_error("Out of memory", ENOMEM); return 1; }
        src_len = fread(src, 1, LUA_SCRIPT_BYTES_MAX, f);
        src[src_len] = '\0';
        fclose(f);
    }

    g_lua_pid = pid;
    if (timeout_s <= 0) timeout_s = LUA_TIMEOUT_DEFAULT;
    if (timeout_s > 600) timeout_s = 600;
    g_lua_deadline_ms = now_ms() + (int64_t)timeout_s * 1000;
    g_lua_deadline_hit = 0;

    lua_State *L = luaL_newstate();
    if (!L) { free(src); print_error("Cannot create Lua state", ENOMEM); return 1; }
    // Only pure libraries: no io, no os, no package loader. A script reaches
    // the target exclusively through hm.*.
    luaL_requiref(L, "_G", luaopen_base, 1);  lua_pop(L, 1);
    luaL_requiref(L, LUA_TABLIBNAME, luaopen_table, 1); lua_pop(L, 1);
    luaL_requiref(L, LUA_STRLIBNAME, luaopen_string, 1); lua_pop(L, 1);
    luaL_requiref(L, LUA_MATHLIBNAME, luaopen_math, 1); lua_pop(L, 1);
    luaL_requiref(L, LUA_UTF8LIBNAME, luaopen_utf8, 1); lua_pop(L, 1);

    lua_newtable(L);
    luaL_setfuncs(L, hm_funcs, 0);
    lua_pushinteger(L, pid);
    lua_setfield(L, -2, "pid");
    lua_setglobal(L, "hm");

    // The base library ships functions that reach outside the sandbox:
    // dofile/loadfile read arbitrary files, and load/loadstring compile new
    // chunks at runtime. A script is supposed to touch the target only through
    // hm.*, so those are removed. string.dump is also dropped: it would let a
    // script emit bytecode, which is the route to loading it back.
    //
    // These must be deleted from the _G table itself, not just set to nil via
    // lua_setglobal: luaopen_base installs _G as a self-reference, and a nil
    // written through the registry's global table is not necessarily the same
    // slot the script reads. Deleting from the table is unconditional.
    const char *blocked[] = { "dofile", "loadfile", "load", "loadstring", NULL };
    for (int i = 0; blocked[i]; i++) {
        lua_pushglobaltable(L);
        lua_pushstring(L, blocked[i]);
        lua_pushnil(L);
        lua_rawset(L, -3);
        lua_pop(L, 1);
    }
    lua_getglobal(L, "string");
    if (lua_istable(L, -1)) {
        // Drop the whole bytecode surface: dump writes it, and load can read it.
        lua_pushstring(L, "dump");
        lua_pushnil(L);
        lua_rawset(L, -3);
    }
    lua_pop(L, 1);
    // The package loader is not opened, but a leftover 'package' entry would
    // still let a script search for loaders.
    lua_pushglobaltable(L);
    lua_pushstring(L, "package");
    lua_pushnil(L);
    lua_rawset(L, -3);
    lua_pop(L, 1);

    lua_pushstring(L, "");
    lua_setglobal(L, "__hm_logbuf");

    lua_sethook(L, lua_timeout_hook, LUA_MASKCOUNT, 1000);

    int64_t started_ms = now_ms();
    int rc = luaL_loadbuffer(L, src, src_len, strcmp(script_arg, "-") == 0 ? "=stdin" : script_arg);
    const char *err = NULL;
    if (rc == LUA_OK) {
        // up to 4 return values; a script commonly returns a table to report.
        rc = lua_pcall(L, 0, LUA_MULTRET, 0);
    }
    if (rc != LUA_OK) err = lua_tostring(L, -1);
    double elapsed = (double)(now_ms() - started_ms) / 1000.0;

    printf("{\"status\":\"%s\",\"pid\":%d,\"ok\":%s,\"elapsed_s\":%.1f",
           err ? "error" : "ok", pid, err ? "false" : "true", elapsed);
    if (err) {
        fputs(",\"error\":\"", stdout);
        json_escape(stdout, err, strlen(err));
        fputs("\"", stdout);
        if (g_lua_deadline_hit) fputs(",\"timed_out\":true", stdout);
    } else {
        // A script can wrap the loop in pcall and turn the budget error into a
        // normal return value, so the run then looks successful. Report the
        // budget separately from the error: the caller must be able to tell a
        // complete run from one that was cut short.
        if (g_lua_deadline_hit) fputs(",\"timed_out\":true", stdout);
        // Return values: scalars are emitted as-is, tables/strings are
        // summarised so the response always stays small and valid JSON.
        fputs(",\"returns\":[", stdout);
        int nret = lua_gettop(L);
        for (int i = 1; i <= nret; i++) {
            if (i > 1) fputs(",", stdout);
            int t = lua_type(L, i);
            switch (t) {
                case LUA_TBOOLEAN: fputs(lua_toboolean(L, i) ? "true" : "false", stdout); break;
                case LUA_TNUMBER:
                    if (lua_isinteger(L, i)) printf("%lld", (long long)lua_tointeger(L, i));
                    else printf("%.17g", (double)lua_tonumber(L, i));
                    break;
                case LUA_TSTRING: {
                    size_t n = 0;
                    const char *s = lua_tolstring(L, i, &n);
                    if (n > 4096) n = 4096;
                    fputc('"', stdout);
                    json_escape(stdout, s, n);
                    fputc('"', stdout);
                    break;
                }
                case LUA_TNIL: fputs("null", stdout); break;
                default: {
                    // Describe non-scalars without serialising them.
                    char desc[64];
                    snprintf(desc, sizeof(desc), "<%s>", lua_typename(L, t));
                    printf("\"%s\"", desc);
                }
            }
        }
        fputs("]", stdout);

        lua_getglobal(L, "__hm_logbuf");
        if (lua_isstring(L, -1)) {
            size_t n = 0;
            const char *s = lua_tolstring(L, -1, &n);
            fputs(",\"log\":\"", stdout);
            json_escape(stdout, s, n);
            fputs("\"", stdout);
        }
        lua_pop(L, 1);
    }
    fputs("}\n", stdout);
    fflush(stdout);

    lua_close(L);
    free(src);
    return err ? 1 : 0;
}

static int cmd_processes(void) {
    DIR *d = opendir("/proc");
    if (!d) {
        print_error("Cannot open /proc", errno);
        return 1;
    }

    struct dirent *de;
    bool first = true;
    printf("[");

    while ((de = readdir(d))) {
        if (!isdigit(de->d_name[0])) continue;
        int pid = atoi(de->d_name);
        char cmdline_path[64];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
        FILE *f = fopen(cmdline_path, "r");
        if (f) {
            char cmdline[256] = {0};
            size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);
            fclose(f);
            if (n > 0) {
                // only list android apps / notable daemons
                if (strchr(cmdline, '.') || strstr(cmdline, "app") || strstr(cmdline, "com.")) {
                    if (!first) printf(",");
                    first = false;
                    printf("{\"pid\":%d,\"name\":\"%s\"}", pid, cmdline);
                }
            }
        }
    }
    closedir(d);
    printf("]\n");
    return 0;
}

#include "hwbp.c"

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("HMKPM CLI Utility v1.2\n"
               "Usage:\n"
               "  probe\n"
               "  processes\n"
               "  maps <pid> [filter]\n"
               "  read <pid> <addr_hex> <size>\n"
               "  write <pid> <addr_hex> <hex_data>\n"
               "  read_val <pid> <addr_hex> <i8|u8|i16|u16|i32|u32|i64|u64|f32|f64>\n"
               "  write_val <pid> <addr_hex> <i8|u8|i16|u16|i32|u32|i64|u64|f32|f64> <val>\n"
               "  scan <pid> <i8|u8|i16|u16|i32|u32|i64|u64|f32|f64> <val> [align] [filter_perms]\n"
               "\n"
               "Fuzzy / differential scan sessions (GameGuardian-style):\n"
               "  scan_seed    <pid> <type> <value> [align] [filter_perms]   (fast: exact-value seed)\n"
               "  scan_unknown <pid> <type> [align] [filter_perms]           (slow: snapshot all)\n"
               "  scan_filter  <pid> <type> <gt|lt|eq|ne|changed|unchanged|increased|decreased|range> [arg]\n"
               "  scan_results <pid> <type>\n"
               "  scan_reset   <pid> <type>\n"
               "\n"
               "Lookup / analysis:\n"
               "  read_values  <pid> <type> <addr> [addr ...]\n"
               "  find_string  <pid> <needle> [perms] [limit]\n"
               "  module_base  <pid> <module> [rva]\n"
               "  pointer_chain <pid> <module|0xaddr> <rva> <type> [off ...]  (last offset not dereferenced)\n"
               "  scan_rva     <pid> <module> <type> <value> [align]          (reports offsets, not addresses)\n"
               "  find_instructions <pid> <pattern[/mask]> <module|x-perms> [limit]\n"
               "  dump         <pid> <addr|module:NAME> <size|all> <out_path> [perms]\n"
               "  watch        <pid> <addr> [size=1|2|4|8] [type=w|r|rw|exec] [duration_ms] [max_hits]\n"
               "  thread_suspend <pid> [tid]\n"
               "  thread_resume  <pid> [tid]\n"
               "  step           <pid> [tid] [count]\n"
               "  threads        <pid>\n"
               "  set_reg        <pid> <tid> <reg> <val>\n"
               "\n"
               "Value freezing (detached daemon):\n"
               "  freeze_add    <pid> <type> <value> <interval_ms> [addr ...]  (no addr = use scan session)\n"
               "  freeze_remove <pid> [addr ...]                              (no addr = clear all)\n"
               "  freeze_list   <pid>\n"
               "\n"
               "Scripting:\n"
               "  run_lua      <pid> <script_path|-> [timeout_s]   (hm.* memory API; '-' reads stdin)\n");
        return 0;
    }

    const char *cmd = argv[1];
    if (strcmp(cmd, "probe") == 0) {
        return cmd_probe();
    } else if (strcmp(cmd, "processes") == 0) {
        return cmd_processes();
    } else if (strcmp(cmd, "maps") == 0 && argc >= 3) {
        int pid = atoi(argv[2]);
        const char *filter = argc >= 4 ? argv[3] : NULL;
        return cmd_maps(pid, filter);
    } else if (strcmp(cmd, "read") == 0 && argc >= 5) {
        int pid = atoi(argv[2]);
        uint64_t addr = strtoull(argv[3], NULL, 0);
        size_t sz = (size_t)strtoul(argv[4], NULL, 0);
        return cmd_read(pid, addr, sz);
    } else if (strcmp(cmd, "write") == 0 && argc >= 5) {
        int pid = atoi(argv[2]);
        uint64_t addr = strtoull(argv[3], NULL, 0);
        return cmd_write(pid, addr, argv[4]);
    } else if (strcmp(cmd, "read_val") == 0 && argc >= 5) {
        int pid = atoi(argv[2]);
        uint64_t addr = strtoull(argv[3], NULL, 0);
        return cmd_read_val(pid, addr, argv[4]);
    } else if (strcmp(cmd, "write_val") == 0 && argc >= 6) {
        int pid = atoi(argv[2]);
        uint64_t addr = strtoull(argv[3], NULL, 0);
        return cmd_write_val(pid, addr, argv[4], argv[5]);
    } else if (strcmp(cmd, "scan") == 0 && argc >= 5) {
        int pid = atoi(argv[2]);
        const char *t = argv[3];
        const char *v = argv[4];
        int align_arg = 0;
        const char *fp = NULL;
        if (argc >= 6) {
            if (isdigit(argv[5][0])) {
                align_arg = atoi(argv[5]);
                if (argc >= 7) fp = argv[6];
            } else {
                fp = argv[5];
            }
        }
        return cmd_scan(pid, t, v, align_arg, fp);
    } else if (strcmp(cmd, "scan_unknown") == 0 && argc >= 4) {
        int pid = atoi(argv[2]);
        int align_arg = 0;
        const char *fp = NULL;
        if (argc >= 5) {
            if (isdigit(argv[4][0])) {
                align_arg = atoi(argv[4]);
                if (argc >= 6) fp = argv[5];
            } else {
                fp = argv[4];
            }
        }
        return cmd_scan_unknown(pid, argv[3], align_arg, fp);
    } else if (strcmp(cmd, "scan_seed") == 0 && argc >= 5) {
        int pid = atoi(argv[2]);
        int align_arg = 0;
        const char *fp = NULL;
        if (argc >= 6) {
            if (isdigit(argv[5][0])) {
                align_arg = atoi(argv[5]);
                if (argc >= 7) fp = argv[6];
            } else {
                fp = argv[5];
            }
        }
        return cmd_scan_seed(pid, argv[3], argv[4], align_arg, fp);
    } else if (strcmp(cmd, "scan_filter") == 0 && argc >= 5) {
        int pid = atoi(argv[2]);
        const char *arg = argc >= 6 ? argv[5] : NULL;
        return cmd_scan_filter(pid, argv[3], argv[4], arg);
    } else if (strcmp(cmd, "scan_results") == 0 && argc >= 4) {
        return cmd_scan_results(atoi(argv[2]), argv[3]);
    } else if (strcmp(cmd, "scan_reset") == 0 && argc >= 4) {
        return cmd_scan_reset(atoi(argv[2]), argv[3]);
    } else if (strcmp(cmd, "read_values") == 0 && argc >= 5) {
        return cmd_read_values(atoi(argv[2]), argv[3], argc - 4, &argv[4]);
    } else if (strcmp(cmd, "find_string") == 0 && argc >= 4) {
        // find_string <pid> <needle> [perms] [limit]
        int limit = 100;
        const char *fp = "rw-p";
        if (argc >= 5) {
            if (isdigit(argv[4][0])) limit = atoi(argv[4]);
            else { fp = argv[4]; if (argc >= 6) limit = atoi(argv[5]); }
        }
        return cmd_find_string(atoi(argv[2]), argv[3], fp, limit);
    } else if (strcmp(cmd, "module_base") == 0 && argc >= 4) {
        const char *rva = argc >= 5 ? argv[4] : NULL;
        return cmd_module_base(atoi(argv[2]), argv[3], rva);
    } else if (strcmp(cmd, "pointer_chain") == 0 && argc >= 6) {
        // pointer_chain <pid> <base_module|0xaddr> <rva> <type> [off ...]
        return cmd_pointer_chain(atoi(argv[2]), argv[3], argv[4], argv[5],
                                 argc - 6, &argv[6]);
    } else if (strcmp(cmd, "freeze_add") == 0 && argc >= 6) {
        // freeze_add <pid> <type> <value> <interval_ms> [addr ...]
        return cmd_freeze_add(atoi(argv[2]), argv[3], argv[4], atoi(argv[5]),
                              argc - 6, &argv[6]);
    } else if (strcmp(cmd, "freeze_remove") == 0 && argc >= 3) {
        return cmd_freeze_remove(atoi(argv[2]), argc - 3, &argv[3]);
    } else if (strcmp(cmd, "freeze_list") == 0 && argc >= 3) {
        return cmd_freeze_list(atoi(argv[2]));
    } else if (strcmp(cmd, "_hold") == 0) {
        return cmd_hold(argc >= 3 ? atoi(argv[2]) : 5000);
    } else if (strcmp(cmd, "_freeze_daemon") == 0 && argc >= 4) {
        // Internal: spawned by freeze_add, never called by a user or the MCP.
        return cmd_freeze_daemon(atoi(argv[2]), atoi(argv[3]),
                                 argc >= 5 ? argv[4] : NULL);
    } else if (strcmp(cmd, "dump") == 0 && argc >= 6) {
        // dump <pid> <addr|module:NAME> <size|all> <out_path> [perms]
        return cmd_dump(atoi(argv[2]), argv[3], argv[4], argv[5],
                        argc >= 7 ? argv[6] : NULL);
    } else if (strcmp(cmd, "scan_rva") == 0 && argc >= 6) {
        // scan_rva <pid> <module> <type> <value> [align]
        return cmd_scan_rva(atoi(argv[2]), argv[3], argv[4], argv[5],
                            argc >= 7 ? atoi(argv[6]) : 0);
    } else if (strcmp(cmd, "find_instructions") == 0 && argc >= 5) {
        // find_instructions <pid> <pattern[/mask]> <module|perms> [limit]
        return cmd_find_instructions(atoi(argv[2]), argv[3], argv[4],
                                     argc >= 6 ? atoi(argv[5]) : 100);
    } else if (strcmp(cmd, "watch") == 0 && argc >= 4) {
        // watch <pid> <addr> [size] [type] [duration_ms] [max_hits]
        int pid = atoi(argv[2]);
        uint64_t addr = strtoull(argv[3], NULL, 0);
        size_t sz = argc >= 5 ? (size_t)strtoul(argv[4], NULL, 0) : 4;
        const char *t = argc >= 6 ? argv[5] : "w";
        uint32_t dur = argc >= 7 ? (uint32_t)strtoul(argv[6], NULL, 0) : 2000;
        uint32_t max_hits = argc >= 8 ? (uint32_t)strtoul(argv[7], NULL, 0) : 10;
        return cmd_watch(pid, addr, sz, t, dur, max_hits);
    } else if (strcmp(cmd, "thread_suspend") == 0 && argc >= 3) {
        // thread_suspend <pid> [tid]
        return cmd_thread_suspend(atoi(argv[2]), argc >= 4 ? atoi(argv[3]) : 0);
    } else if (strcmp(cmd, "thread_resume") == 0 && argc >= 3) {
        // thread_resume <pid> [tid]
        return cmd_thread_resume(atoi(argv[2]), argc >= 4 ? atoi(argv[3]) : 0);
    } else if (strcmp(cmd, "step") == 0 && argc >= 3) {
        // step <pid> [tid] [count]
        int pid = atoi(argv[2]);
        int tid = argc >= 4 ? atoi(argv[3]) : 0;
        int steps = argc >= 5 ? atoi(argv[4]) : 1;
        return cmd_step(pid, tid, steps);
    } else if (strcmp(cmd, "threads") == 0 && argc >= 3) {
        // threads <pid>
        return cmd_list_threads(atoi(argv[2]));
    } else if (strcmp(cmd, "set_reg") == 0 && argc >= 6) {
        // set_reg <pid> <tid> <reg> <val>
        return cmd_set_register(atoi(argv[2]), atoi(argv[3]), argv[4], strtoull(argv[5], NULL, 0));
    } else if (strcmp(cmd, "run_lua") == 0 && argc >= 4) {
        // run_lua <pid> <script_path|-> [timeout_s]
        return cmd_run_lua(atoi(argv[2]), argv[3],
                           argc >= 5 ? atoi(argv[4]) : LUA_TIMEOUT_DEFAULT);
    }

    print_error("Unknown command or missing arguments", EINVAL);
    return 1;
}
