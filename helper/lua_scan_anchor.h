// ---------------------------------------------------------------------------
// lua_scan <pid> --anchor <string> [--max-candidates N]
//
// One command for the whole "find the lua_State" job, driven by a string that
// is known to exist as a Lua string in the target: a global name, a UI label, a
// config key -- anything the game's Lua code stores.
//
// An anchor beats a blind sweep because a Lua string is a GC object with its
// length next to its characters, so a byte match plus a length check yields the
// exact GCstr address. From there two sweeps are enough:
//
//   sweep 1   anchor text  -> GCstr object      (length-verified)
//   sweep 2   every pointer that probes as a lua_State is checked directly:
//             does its globals table have the anchor as a key?
//
// Checking the globals table directly is what keeps this cheap. An earlier
// version tried to hop through "the table that owns the node holding the
// anchor", which was both wrong (a table's node array is not discoverable from
// one slot address) and quadratic (it re-read the whole heap per candidate).
//
// The final confirmation is the same one lua_state uses: the layout must probe
// cleanly and G->mainthread must point back at the candidate, so this command
// cannot report an address that lua_state would reject.
//
// Read-only throughout: no ptrace, no writes.
// ---------------------------------------------------------------------------

#define LSCAN_REGION_MAX  (16ULL * 1024 * 1024)
#define LSCAN_BUDGET      (128ULL * 1024 * 1024)
#define LSCAN_MAX_STATES  8
#define LSCAN_MAX_STRS    8

struct lscan_state {
    uint64_t L, G, registry, globals;
    const char *layout;
    uint64_t span;
};

// Read a whole region under a shared byte budget. Caller frees.
static uint8_t *lscan_region(int pid, const struct vma *v, uint64_t *budget) {
    uint64_t size = v->end - v->start;
    if (size < 0x200 || size > LSCAN_REGION_MAX) return NULL;
    if (*budget + size > LSCAN_BUDGET) return NULL;
    uint8_t *buf = (uint8_t *)malloc((size_t)size);
    if (!buf) return NULL;
    if (!raw_read(pid, v->start, buf, (size_t)size)) { free(buf); return NULL; }
    *budget += size;
    return buf;
}

// Is `str` the GCstr that holds `text`? Both the 5.4 and LuaJIT GC64 string
// layouts are tried; the length must agree with the anchor. `buf` is sized by
// the caller and is at least 97 bytes, matching the anchor limit.
static bool lscan_str_matches(int pid, uint64_t str, const char *text, size_t len,
                              char *buf, size_t cap) {
    if (!lp_is_ptr(str) || len + 1 > cap) return false;
    uint8_t h[0x20];
    if (!raw_read_exact(pid, str, h, sizeof(h))) return false;

    // lua 5.4 short string: shrlen at +0x0b, contents at +0x18.
    if (h[L54_STR_SHRLEN] == len &&
        raw_read_exact(pid, str + L54_STR_CONTENTS, buf, len)) {
        buf[len] = '\0';
        if (memcmp(buf, text, len) == 0) return true;
    }
    // LuaJIT GC64 string: len at +0x0c, contents at +0x10.
    uint32_t lj_len = 0;
    memcpy(&lj_len, h + LJ_STR_LEN, 4);
    if (lj_len == len && raw_read_exact(pid, str + LJ_STR_DATA, buf, len)) {
        buf[len] = '\0';
        if (memcmp(buf, text, len) == 0) return true;
    }
    return false;
}

// Given the address where the anchor text starts, return the owning GCstr for
// each header width that validates (5.4 uses 0x18, LuaJIT 0x10).
static int lscan_strs_at(int pid, uint64_t text_addr, const char *text, size_t len,
                         uint64_t *out, int max) {
    static const int headers[] = { 0x18, 0x10 };
    char buf[128];
    int n = 0;
    for (size_t i = 0; i < sizeof(headers) / sizeof(headers[0]) && n < max; i++) {
        if (text_addr < (uint64_t)headers[i]) continue;
        uint64_t obj = text_addr - (uint64_t)headers[i];
        if (!lscan_str_matches(pid, obj, text, len, buf, sizeof(buf))) continue;
        bool dup = false;
        for (int k = 0; k < n; k++) if (out[k] == obj) dup = true;
        if (!dup) out[n++] = obj;
    }
    return n;
}

static int lua_scan_cmd(int pid, const char *anchor, uint32_t max_cand) {
    if (!anchor || !anchor[0]) {
        print_error("--anchor must not be empty", EINVAL);
        return 1;
    }
    size_t len = strlen(anchor);
    if (len > 96) {
        print_error("--anchor is limited to 96 bytes", E2BIG);
        return 1;
    }
    if (max_cand == 0 || max_cand > 32) max_cand = 8;
    if (max_cand > LSCAN_MAX_STRS) max_cand = LSCAN_MAX_STRS;

    struct vma_table vmas;
    if (!vma_table_load(pid, &vmas)) { print_error("Cannot read maps", errno); return 1; }
    uint64_t budget = 0;

    // ---- sweep 1: the anchor's GCstr object(s) ----------------------------
    uint64_t strs[LSCAN_MAX_STRS];
    int nstr = 0;
    for (uint32_t i = 0; i < vmas.count && nstr < (int)max_cand; i++) {
        const struct vma *v = &vmas.items[i];
        if (!lua_region_interesting(v)) continue;
        uint8_t *buf = lscan_region(pid, v, &budget);
        if (!buf) continue;
        uint64_t size = v->end - v->start;
        for (uint64_t o = 0; o + len <= size && nstr < (int)max_cand; o++) {
            if (memcmp(buf + o, anchor, len) != 0) continue;
            nstr += lscan_strs_at(pid, v->start + o, anchor, len, strs + nstr,
                                  (int)max_cand - nstr);
        }
        free(buf);
    }

    printf("{\"status\":\"ok\",\"pid\":%d,\"anchor\":\"%s\",\"steps\":{"
           "\"anchor_string\":%d", pid, anchor, nstr);
    if (nstr == 0) {
        printf("},\"states\":[],\"count\":0,\"note\":\"anchor not found as a Lua string in "
               "a scanned heap region; check spelling, or it may live in a read-only "
               "region\"}\n");
        vma_table_free(&vmas);
        return 2;
    }

    // ---- sweep 2: states whose globals hold the anchor as a key -----------
    struct lscan_state found[LSCAN_MAX_STATES];
    int nfound = 0;
    for (uint32_t i = 0; i < vmas.count && nfound < LSCAN_MAX_STATES; i++) {
        const struct vma *v = &vmas.items[i];
        if (!lua_region_interesting(v)) continue;
        uint8_t *buf = lscan_region(pid, v, &budget);
        if (!buf) continue;
        uint64_t size = v->end - v->start;
        for (uint64_t o = 0; o + 0x40 <= size && nfound < LSCAN_MAX_STATES; o += 8) {
            uint64_t cand;
            memcpy(&cand, buf + o, 8);
            if (!lp_is_ptr(cand) || (cand & 7)) continue;
            bool dup = false;
            for (int k = 0; k < nfound; k++) if (found[k].L == cand) dup = true;
            if (dup) continue;

            uint64_t G = 0;
            char err[96] = "";
            const char *layout = lua_probe_layout(pid, cand, &G, err, sizeof(err));
            if (!layout || strcmp(layout, "lua54") != 0) continue;

            uint64_t reg = l54_registry(pid, G);
            if (!reg) continue;
            uint64_t globals = l54_globals(pid, reg);
            if (!globals) continue;
            // The anchor must be a key of this state's globals table.
            if (!l54_table_get(pid, globals, anchor, NULL, NULL)) continue;

            uint8_t hb[0x40];
            uint64_t span = 0;
            if (raw_read_exact(pid, cand, hb, sizeof(hb))) {
                uint64_t stack, last;
                memcpy(&stack, hb + L54_LS_STACK, 8);
                memcpy(&last,  hb + L54_LS_STACK_LAST, 8);
                span = last > stack ? last - stack : 0;
            }
            struct lscan_state *s = &found[nfound++];
            s->L = cand; s->G = G; s->registry = reg; s->globals = globals;
            s->layout = layout; s->span = span;
        }
        free(buf);
    }

    printf(",\"states\":%d},\"bytes_read\":%llu,\"results\":[",
           nfound, (unsigned long long)budget);
    for (int i = 0; i < nfound; i++) {
        printf("%s{\"addr\":\"0x%llx\",\"layout\":\"%s\",\"G\":\"0x%llx\","
               "\"registry\":\"0x%llx\",\"globals\":\"0x%llx\"}",
               i ? "," : "", (unsigned long long)found[i].L, found[i].layout,
               (unsigned long long)found[i].G, (unsigned long long)found[i].registry,
               (unsigned long long)found[i].globals);
    }
    printf("],\"count\":%d", nfound);

    if (nfound > 0) {
        int best = 0;
        for (int i = 1; i < nfound; i++)
            if (found[i].span > found[best].span) best = i;
        printf(",\"best\":{\"addr\":\"0x%llx\",\"G\":\"0x%llx\",\"globals\":\"0x%llx\"}",
               (unsigned long long)found[best].L,
               (unsigned long long)found[best].G,
               (unsigned long long)found[best].globals);
    } else {
        printf(",\"note\":\"anchor exists as a string but no lua_State has it as a "
               "globals key; it may be a value rather than a key, or belong to a state "
               "in a language other than lua 5.4\"");
    }
    printf("}\n");

    vma_table_free(&vmas);
    return nfound > 0 ? 0 : 2;
}
