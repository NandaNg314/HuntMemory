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

static uint32_t collect_ranges(int pid, const char *perm_req,
                               struct hmkpm_scan_range *ranges, uint32_t max_ranges);

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
    size_t total_len = sizeof(struct hmkpm_req) + size;
    uint8_t *buf = (uint8_t *)calloc(1, total_len);
    if (!buf) {
        print_error("Out of memory", ENOMEM);
        return 1;
    }

    struct hmkpm_req *req = (struct hmkpm_req *)buf;
    req->pid = pid;
    req->addr = addr;
    req->size = size;

    errno = 0;
    long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_READ, buf, total_len);
    if (ret < 0 && ret != 0) {
        print_error("HMKPM read failed", errno ? errno : EFAULT);
        free(buf);
        return 1;
    }

    uint8_t *data = buf + sizeof(struct hmkpm_req);
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
    free(buf);
    return 0;
}

static int cmd_write(int pid, uint64_t addr, const char *hex_str) {
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0 || hex_len == 0) {
        print_error("Hex string length must be even and positive", EINVAL);
        return 1;
    }
    size_t size = hex_len / 2;
    size_t total_len = sizeof(struct hmkpm_req) + size;
    uint8_t *buf = (uint8_t *)calloc(1, total_len);
    if (!buf) {
        print_error("Out of memory", ENOMEM);
        return 1;
    }

    struct hmkpm_req *req = (struct hmkpm_req *)buf;
    req->pid = pid;
    req->addr = addr;
    req->size = size;

    uint8_t *data = buf + sizeof(struct hmkpm_req);
    for (size_t i = 0; i < size; i++) {
        unsigned int byte_val;
        if (sscanf(hex_str + 2 * i, "%02x", &byte_val) != 1) {
            print_error("Invalid hex digit", EINVAL);
            free(buf);
            return 1;
        }
        data[i] = (uint8_t)byte_val;
    }

    errno = 0;
    long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_WRITE, buf, total_len);
    if (ret < 0 && ret != 0) {
        print_error("HMKPM write failed", errno ? errno : EFAULT);
        free(buf);
        return 1;
    }

    printf("{\"status\":\"ok\",\"pid\":%d,\"addr\":\"0x%llx\",\"bytes_written\":%zu}\n",
           pid, (unsigned long long)addr, size);
    free(buf);
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

    size_t total_len = sizeof(struct hmkpm_req) + sz;
    uint8_t *buf = (uint8_t *)calloc(1, total_len);
    struct hmkpm_req *req = (struct hmkpm_req *)buf;
    req->pid = pid;
    req->addr = addr;
    req->size = sz;

    errno = 0;
    long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_READ, buf, total_len);
    if (ret < 0 && ret != 0) {
        print_error("HMKPM read failed", errno ? errno : EFAULT);
        free(buf);
        return 1;
    }

    uint8_t *data = buf + sizeof(struct hmkpm_req);
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
    free(buf);
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

    size_t total_len = sizeof(struct hmkpm_req) + sz;
    uint8_t *buf = (uint8_t *)calloc(1, total_len);
    struct hmkpm_req *req = (struct hmkpm_req *)buf;
    req->pid = pid;
    req->addr = addr;
    req->size = sz;
    memcpy(buf + sizeof(struct hmkpm_req), raw, sz);

    errno = 0;
    long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_WRITE, buf, total_len);
    if (ret < 0 && ret != 0) {
        print_error("HMKPM write failed", errno ? errno : EFAULT);
        free(buf);
        return 1;
    }

    printf("{\"status\":\"ok\",\"pid\":%d,\"addr\":\"0x%llx\",\"type\":\"%s\",\"value\":\"%s\"}\n",
           pid, (unsigned long long)addr, type_name, val_str);
    free(buf);
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

    // Collect readable/writable memory ranges from /proc/<pid>/maps
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        print_error("Cannot open maps for scan", errno);
        return 1;
    }

    #define MAX_RANGES 1024
    struct hmkpm_scan_range ranges[MAX_RANGES];
    uint32_t range_count = 0;
    char line[512];

    const char *perm_req = filter_perms ? filter_perms : "rw-p";

    while (fgets(line, sizeof(line), f) && range_count < MAX_RANGES) {
        uint64_t start = 0, end = 0;
        char perms[8] = {0};
        int c = sscanf(line, "%llx-%llx %7s", (unsigned long long *)&start, (unsigned long long *)&end, perms);
        if (c >= 3) {
            // Check permissions (e.g. must be readable)
            if (perms[0] == 'r' && (!filter_perms || strstr(perms, perm_req))) {
                ranges[range_count].start_va = start;
                ranges[range_count].size = end - start;
                range_count++;
            }
        }
    }
    fclose(f);

    // Print the envelope BEFORE the scan runs. The kernel reports a match count
    // that can exceed the slot array (it keeps counting while capping writes,
    // e.g. 11M zero-i32 hits in a 500 MB dalvik space), and a single-line
    // printf of that much output made the CLI look like it hung for minutes.
    // Streaming the result keeps memory flat and the caller can stop reading.
    #define MAX_MATCHES 2048
    if (range_count == 0) {
        printf("{\"status\":\"ok\",\"matches_found\":0,\"truncated\":false,\"matches\":[]}\n");
        return 0;
    }
    size_t ranges_bytes = range_count * sizeof(struct hmkpm_scan_range);
    size_t matches_bytes = MAX_MATCHES * sizeof(uint64_t);
    size_t total_len = sizeof(struct hmkpm_scan_hdr) + ranges_bytes + matches_bytes;

    uint8_t *buf = (uint8_t *)calloc(1, total_len);
    if (!buf) {
        print_error("Out of memory for scan buffer", ENOMEM);
        return 1;
    }

    struct hmkpm_scan_hdr *hdr = (struct hmkpm_scan_hdr *)buf;
    hdr->pid = pid;
    hdr->type = scan_type;
    hdr->op = HMKPM_SCAN_OP_EXACT;
    hdr->align = align;
    hdr->range_count = range_count;
    hdr->max_matches = MAX_MATCHES;
    hdr->pattern_len = 0;
    hdr->criteria.exact.val = criteria_val;
    hdr->criteria.exact.mask = ~0ULL;
    hdr->matches_found = 0;

    memcpy(buf + sizeof(struct hmkpm_scan_hdr), ranges, ranges_bytes);

    errno = 0;
    long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_SCAN_KERNEL, buf, total_len);
    if (ret < 0 && ret != 0) {
        print_error("HMKPM scan kernel syscall failed", errno ? errno : EFAULT);
        free(buf);
        return 1;
    }

    uint64_t found = hdr->matches_found;
    uint64_t *matches = (uint64_t *)(buf + sizeof(struct hmkpm_scan_hdr) + ranges_bytes);
    uint32_t report_count = found > MAX_MATCHES ? MAX_MATCHES : (uint32_t)found;

    // `matches_found` keeps the full kernel count; `matches` is capped (see
    // "truncated"). Streamed in chunks so a huge count still produces output
    // the caller sees immediately instead of one delayed multi-megabyte line.
    printf("{\"status\":\"ok\",\"matches_found\":%llu,\"truncated\":%s,\"matches\":[",
           (unsigned long long)found, found > MAX_MATCHES ? "true" : "false");
    for (uint32_t i = 0; i < report_count; i++) {
        printf("%s\"0x%llx\"", i ? "," : "", (unsigned long long)matches[i]);
        if ((i & 255) == 255) fflush(stdout);
    }
    printf("]}\n");
    free(buf);
    return 0;
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
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    uint32_t magic = 0x484D4B53; // "HMKS"
    fwrite(&magic, sizeof(magic), 1, f);
    fwrite(&s->pid, sizeof(s->pid), 1, f);
    fwrite(&s->type, sizeof(s->type), 1, f);
    fwrite(&s->elem_size, sizeof(s->elem_size), 1, f);
    fwrite(&s->count, sizeof(s->count), 1, f);
    if (s->count > 0 && s->entries) {
        fwrite(s->entries, sizeof(struct scan_entry), s->count, f);
    }
    fclose(f);
    return 0;
}

static int session_load(int pid, const char *type_name, struct scan_session *s) {
    char path[128];
    session_path(path, sizeof(path), pid, type_name);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    uint32_t magic = 0;
    if (fread(&magic, sizeof(magic), 1, f) != 1 || magic != 0x484D4B53) {
        fclose(f);
        return -1;
    }
    if (fread(&s->pid, sizeof(s->pid), 1, f) != 1) { fclose(f); return -1; }
    if (fread(&s->type, sizeof(s->type), 1, f) != 1) { fclose(f); return -1; }
    if (fread(&s->elem_size, sizeof(s->elem_size), 1, f) != 1) { fclose(f); return -1; }
    if (fread(&s->count, sizeof(s->count), 1, f) != 1) { fclose(f); return -1; }
    s->entries = NULL;
    if (s->count > 0) {
        s->entries = (struct scan_entry *)malloc(sizeof(struct scan_entry) * s->count);
        if (!s->entries) { fclose(f); return -1; }
        size_t got = fread(s->entries, sizeof(struct scan_entry), s->count, f);
        if (got != s->count) { fclose(f); free(s->entries); s->entries = NULL; return -1; }
    }
    fclose(f);
    return 0;
}

static void session_free(struct scan_session *s) {
    if (s->entries) { free(s->entries); s->entries = NULL; }
    s->count = 0;
}

// (Single-address reads go through read_many below: a per-candidate syscall
// loop over millions of addresses is far too slow for a filter pass.)

// Re-read a run of addresses in as few syscalls as possible. `out` receives
// size bytes per address; unreadable slots stay zero-filled and are reported
// through the optional `live` bitmap (1 = the kernel returned the bytes).
// Addresses are handled in windows of at most 4096 slots; a window that the
// kernel refuses (EFAULT, one guard page anywhere in it) is halved until the
// failure is isolated to a single slot, so a stale address costs a handful of
// syscalls instead of aborting the whole pass.
static void read_many(int pid, const uint64_t *addrs, uint32_t n, uint8_t size,
                      uint8_t *out, uint32_t *ok_count, uint8_t *live) {
    *ok_count = 0;
    if (live) memset(live, 0, n);
    if (n == 0) return;

    // Request header lives in the stack buffer so the kernel's copy_to_user
    // targets this frame; page faults inside it then degrade to a zero return.
    struct {
        struct hmkpm_req req;
        uint8_t scratch[4096];
    } buf;
    buf.req.pid = pid;

    // A single-address HMKPM_READ returns EFAULT both for "target page not
    // readable" and for "kernel never wrote our bytes" (copy_to_user failing
    // on our own guard page), so one exact read cannot be trusted. Fall back to
    // reading a page-aligned span of the target and picking the bytes out of
    // it, which only fails when the target memory itself is unreadable.
    if (n == 1) {
        uint64_t start = addrs[0] & ~0xFFFULL;
        size_t off = (size_t)(addrs[0] - start);
        if (off + size > sizeof(buf.scratch)) {
            memset(out, 0, size);
            return;
        }
        buf.req.addr = start;
        buf.req.size = sizeof(buf.scratch);
        errno = 0;
        long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_READ, &buf,
                           sizeof(struct hmkpm_req) + sizeof(buf.scratch));
        if (ret >= 0 || ret == 0) {
            memcpy(out, buf.scratch + off, size);
            if (live) live[0] = 1;
            *ok_count = 1;
        } else {
            memset(out, 0, size);
        }
        return;
    }

    const uint32_t CH = 4096;                       // max addresses per syscall
    uint32_t done = 0;
    while (done < n) {
        uint32_t chunk = (n - done) < CH ? (n - done) : CH;
        if ((size_t)chunk * size > sizeof(buf.scratch)) chunk = 1;
        while (chunk > 0) {
            size_t bytes = (size_t)chunk * size;
            buf.req.addr = addrs[done];
            buf.req.size = bytes;
            errno = 0;
            long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_READ, &buf,
                               sizeof(struct hmkpm_req) + bytes);
            if (ret >= 0 || ret == 0) {
                memcpy(out + (size_t)done * size, buf.scratch, bytes);
                if (live) memset(live + done, 1, chunk);
                *ok_count += chunk;
                done += chunk;
                break;
            }
            if (chunk == 1) {
                // Unreadable slot: leave it zeroed and move on. Without the
                // bitmap callers only see zeros, which is why stale addresses
                // look like "changed from old value to 0".
                done += 1;
                break;
            }
            chunk /= 2;                            // narrow around the bad slot
        }
    }
}

// Collect readable ranges (matches the semantics used by cmd_scan).
static uint32_t collect_ranges(int pid, const char *perm_req,
                               struct hmkpm_scan_range *ranges, uint32_t max_ranges) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    uint32_t range_count = 0;
    const char *pr = perm_req ? perm_req : "rw-p";
    while (fgets(line, sizeof(line), f) && range_count < max_ranges) {
        uint64_t start = 0, end = 0;
        char perms[8] = {0};
        int c = sscanf(line, "%llx-%llx %7s", (unsigned long long *)&start, (unsigned long long *)&end, perms);
        if (c >= 3) {
            if (perms[0] == 'r' && (!perm_req || strstr(perms, pr))) {
                ranges[range_count].start_va = start;
                ranges[range_count].size = end - start;
                range_count++;
            }
        }
    }
    fclose(f);
    return range_count;
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

    uint32_t max_ranges = 1024;
    struct hmkpm_scan_range ranges[1024];
    uint32_t range_count = collect_ranges(pid, filter_perms, ranges, max_ranges);
    if (range_count == 0) {
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
    uint32_t max_ranges = 1024;
    struct hmkpm_scan_range ranges[1024];
    uint32_t range_count = collect_ranges(pid, filter_perms, ranges, max_ranges);
    if (range_count == 0) {
        printf("{\"status\":\"ok\",\"pid\":%d,\"type\":\"%s\",\"count\":0,\"matches_found\":0}\n",
               pid, type_name);
        return 0;
    }

    size_t ranges_bytes = range_count * sizeof(struct hmkpm_scan_range);
    size_t total_len = sizeof(struct hmkpm_scan_hdr) + ranges_bytes + (size_t)cap * sizeof(uint64_t);
    uint8_t *buf = (uint8_t *)calloc(1, total_len);
    if (!buf) { print_error("Out of memory for seed scan", ENOMEM); return 1; }

    struct hmkpm_scan_hdr *hdr = (struct hmkpm_scan_hdr *)buf;
    hdr->pid = pid;
    hdr->type = type;
    hdr->op = HMKPM_SCAN_OP_EXACT;
    hdr->align = align;
    hdr->range_count = range_count;
    hdr->max_matches = cap;
    hdr->pattern_len = 0;
    hdr->criteria.exact.val = criteria_val;
    hdr->criteria.exact.mask = ~0ULL;
    hdr->matches_found = 0;
    memcpy(buf + sizeof(struct hmkpm_scan_hdr), ranges, ranges_bytes);

    errno = 0;
    long ret = syscall(SYS_GETRESUID, HMKPM_MAGIC_SCAN_KERNEL, buf, total_len);
    if (ret < 0 && ret != 0) {
        // errno 7 (E2BIG on arm64) is what hmkpm returns when the request
        // carries more VMAs than its fixed-size range table — i.e. any big
        // modern app (systemui alone has ~6400 maps). Fall back to a userspace
        // exact scan over the same ranges: slower, but unbounded.
        free(buf);
        return scan_exact_userspace(pid, type_name, type, elem_size, align,
                                    criteria_val, filter_perms, cap);
    }
    found = hdr->matches_found;
    uint64_t *matches = (uint64_t *)(buf + sizeof(struct hmkpm_scan_hdr) + ranges_bytes);
    uint64_t kept = found < cap ? found : cap;

    // Everything the kernel matched holds `criteria_val`, so the hit list *is*
    // the baseline. Re-reading each hit is unnecessary (and a single-address
    // HMKPM read is unreliable: it returns EFAULT even for readable pages
    // because the kernel cannot copy into our frame).
    struct scan_session sess;
    sess.pid = pid;
    sess.type = type;
    sess.elem_size = elem_size;
    sess.count = 0;
    sess.entries = (struct scan_entry *)malloc(sizeof(struct scan_entry) * (kept ? kept : 1));
    if (!sess.entries) { print_error("Out of memory", ENOMEM); free(buf); return 1; }
    for (uint64_t i = 0; i < kept; i++) {
        struct scan_entry *e = &sess.entries[sess.count];
        e->addr = matches[i];
        e->val.u = 0;
        memcpy(&e->val, &criteria_val, elem_size);
        sess.count++;
    }
    free(buf);

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

    for (uint32_t i = 0; i < sess.count; i++) {
        struct scan_entry cur;
        uint8_t *slot = raw + (size_t)i * sess.elem_size;
        cur.addr = sess.entries[i].addr;
        decode_value(&cur, type, slot);

        int old_vs_new = compare_entries(&sess.entries[i], &cur, type); // old - new
        bool keep = false;

        if (strcmp(mode, "changed") == 0) {
            keep = (old_vs_new != 0);
        } else if (strcmp(mode, "unchanged") == 0) {
            keep = (old_vs_new == 0);
        } else if (strcmp(mode, "increased") == 0) {
            keep = (old_vs_new < 0); // old < new
        } else if (strcmp(mode, "decreased") == 0) {
            keep = (old_vs_new > 0); // old > new
        } else if (strcmp(mode, "gt") == 0) {
            keep = (entry_as_double(&cur, type) > target);
        } else if (strcmp(mode, "lt") == 0) {
            keep = (entry_as_double(&cur, type) < target);
        } else if (strcmp(mode, "eq") == 0) {
            keep = entry_equals_value(&cur, type, target) == 0;
        } else if (strcmp(mode, "ne") == 0) {
            keep = entry_equals_value(&cur, type, target) != 0;
        } else if (strcmp(mode, "range") == 0) {
            // arg = "min:max"
            double lo = 0, hi = 0;
            sscanf(arg, "%lf:%lf", &lo, &hi);
            double d = entry_as_double(&cur, type);
            keep = (d >= lo && d <= hi);
        } else {
            free(raw);
            free(kept);
            session_free(&sess);
            print_error("Unknown filter mode", EINVAL);
            return 1;
        }

        if (keep) {
            kept[kept_n++] = cur;
        }
    }

    // Persist the narrowed session.
    uint8_t saved_elem = sess.elem_size ? sess.elem_size : elem_size;
    session_free(&sess);
    struct scan_session out;
    out.pid = pid;
    out.type = type;
    out.elem_size = saved_elem;
    out.count = kept_n;
    out.entries = kept;
    session_save(pid, type_name, &out);
    uint32_t scanned = sess.count;
    free(raw);
    free(kept);
    session_free(&sess);

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
               "  scan_reset   <pid> <type>\n");
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
    }

    print_error("Unknown command or missing arguments", EINVAL);
    return 1;
}
