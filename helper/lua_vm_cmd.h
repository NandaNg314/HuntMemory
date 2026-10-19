// ---------------------------------------------------------------------------
// lua_state / lua_walk command bodies, built on lua_vm.h.
//
// The scan is progressive and prints a counter per stage, so a weak filter is
// obvious immediately instead of producing a confident-looking wrong address.
//
//   L1  aligned heap pointers seen while sweeping candidate regions
//   L2  records whose layout probes as a lua_State (5.4 or LuaJIT)
//   L3  records whose global_State validates (mainthread identity / GC pair)
//   L4  records whose registry resolves to a globals table with named keys
//
// Only L4 survivors are reported, and the best one is picked by table richness
// (then stack depth), because several threads can share a globals table.
// ---------------------------------------------------------------------------

struct lua_scan_stats {
    uint64_t l1, l2, l3, l4;
    int regions_read;
    uint64_t bytes_read;
};

struct lua_vm_hit {
    uint64_t L;
    uint64_t G;
    uint64_t registry;
    uint64_t globals;
    int      score;
    uint64_t span;
    const char *layout;
};

#define LUA_REGION_MAX  (16ULL * 1024 * 1024)
#define LUA_READ_BUDGET (256ULL * 1024 * 1024)
#define LUA_HITS_MAX    16

// Regions worth scanning: readable+writable native heap. ART/Dalvik and GPU
// regions reproduce Lua-like pointer patterns by coincidence and are excluded.
static bool lua_region_interesting(const struct vma *v) {
    if (v->perms[0] != 'r' || v->perms[1] != 'w') return false;
    const char *p = v->path;
    if (strstr(p, "dalvik") || strstr(p, "art]") || strstr(p, "boot.")) return false;
    if (strstr(p, "kgsl") || strstr(p, "libv8") || strstr(p, "v8")) return false;
    if (strstr(p, "tls")) return false;
    return true;
}

// Score a globals table by how many standard libraries it exposes. This is the
// semantic confirmation: a random table cannot contain "string" + "table" +
// "math" all at once.
static int lua_globals_confirm(int pid, uint64_t globals, bool lua54) {
    if (!lp_is_ptr(globals)) return 0;
    if (lua54) {
        int n = 0;
        static const char *libs[] = {"string", "table", "math", "os", "io", "coroutine", NULL};
        for (int i = 0; libs[i]; i++) {
            uint64_t v; uint8_t tt;
            if (l54_table_get(pid, globals, libs[i], &v, &tt)) n++;
        }
        return n;
    }
    return 0;   // LuaJIT path: score by key count only
}

static int lua_state_cmd(int pid) {
    struct vma_table vmas;
    if (!vma_table_load(pid, &vmas)) {
        print_error("Cannot read maps", errno);
        return 1;
    }

    struct lua_scan_stats st;
    memset(&st, 0, sizeof(st));
    struct lua_vm_hit hits[LUA_HITS_MAX];
    int nhits = 0;

    for (uint32_t i = 0; i < vmas.count; i++) {
        const struct vma *v = &vmas.items[i];
        if (!lua_region_interesting(v)) continue;
        uint64_t size = v->end - v->start;
        if (size < 0x200 || size > LUA_REGION_MAX) continue;
        if (st.bytes_read + size > LUA_READ_BUDGET) break;

        uint8_t *buf = (uint8_t *)malloc((size_t)size);
        if (!buf) continue;
        if (!raw_read(pid, v->start, buf, (size_t)size)) { free(buf); continue; }
        st.regions_read++;
        st.bytes_read += size;

        for (uint64_t off = 0; off + 0x40 <= size; off += 8) {
            uint64_t cand;
            memcpy(&cand, buf + off, 8);
            if (!lp_is_ptr(cand) || (cand & 7)) continue;
            st.l1++;

            uint64_t G = 0;
            char err[96] = "";
            const char *layout = lua_probe_layout(pid, cand, &G, err, sizeof(err));
            if (!layout) continue;
            st.l2++;

            bool is54 = strcmp(layout, "lua54") == 0;
            uint64_t registry = 0, globals = 0;
            if (is54) {
                registry = l54_registry(pid, G);
                if (registry) globals = l54_globals(pid, registry);
            } else {
                uint64_t reg = 0;
                if (!raw_read_exact(pid, G + LJ_G_REGISTRY, &reg, 8)) continue;
                registry = lp_is_ptr(reg) ? reg : 0;
            }
            if (!registry) continue;
            st.l3++;
            if (!globals) continue;

            int score = is54 ? l54_table_score(pid, globals) : 0;
            int libs = lua_globals_confirm(pid, globals, is54);
            if (score < 4 && libs < 2) continue;
            st.l4++;

            if (nhits < LUA_HITS_MAX) {
                // Several pointers can reference the same state; keep one.
                bool dup = false;
                for (int k = 0; k < nhits; k++) if (hits[k].L == cand) { dup = true; break; }
                if (dup) continue;
                struct lua_vm_hit *h = &hits[nhits++];
                memset(h, 0, sizeof(*h));
                h->L = cand; h->G = G;
                h->registry = registry; h->globals = globals;
                h->score = score + libs * 100;
                h->layout = layout;
                uint8_t hb[0x40];
                if (raw_read_exact(pid, cand, hb, sizeof(hb))) {
                    uint64_t stack, last;
                    memcpy(&stack, hb + (is54 ? L54_LS_STACK : LJ_LS_STACK), 8);
                    memcpy(&last,  hb + (is54 ? L54_LS_STACK_LAST : LJ_LS_STACK_LAST), 8);
                    h->span = last > stack ? last - stack : 0;
                }
            }
        }
        free(buf);
    }

    // Pick the richest globals table, then the deepest stack.
    int best = -1;
    for (int i = 0; i < nhits; i++) {
        if (best < 0 || hits[i].score > hits[best].score ||
            (hits[i].score == hits[best].score && hits[i].span > hits[best].span))
            best = i;
    }

    printf("{\"status\":\"ok\",\"pid\":%d,\"scan\":{\"regions\":%d,\"bytes\":%llu,"
           "\"L1_aligned\":%llu,\"L2_state\":%llu,\"L3_registry\":%llu,"
           "\"L4_globals\":%llu},\"candidates\":[",
           pid, st.regions_read, (unsigned long long)st.bytes_read,
           (unsigned long long)st.l1, (unsigned long long)st.l2,
           (unsigned long long)st.l3, (unsigned long long)st.l4);
    for (int i = 0; i < nhits; i++) {
        printf("%s{\"addr\":\"0x%llx\",\"layout\":\"%s\",\"G\":\"0x%llx\","
               "\"registry\":\"0x%llx\",\"globals\":\"0x%llx\",\"score\":%d,"
               "\"stack_span\":%llu}",
               i ? "," : "", (unsigned long long)hits[i].L, hits[i].layout,
               (unsigned long long)hits[i].G, (unsigned long long)hits[i].registry,
               (unsigned long long)hits[i].globals, hits[i].score,
               (unsigned long long)hits[i].span);
    }
    printf("]");
    if (best >= 0) {
        printf(",\"best\":{\"addr\":\"0x%llx\",\"layout\":\"%s\",\"G\":\"0x%llx\","
               "\"globals\":\"0x%llx\"}",
               (unsigned long long)hits[best].L, hits[best].layout,
               (unsigned long long)hits[best].G, (unsigned long long)hits[best].globals);
        if (strcmp(hits[best].layout, "luajit") == 0) {
            printf(",\"warning\":\"LuaJIT layout is derived from disassembly but has not "
                   "been verified end-to-end on a real game; treat the address as "
                   "experimental\"");
        }
    } else {
        printf(",\"note\":\"no lua_State found; the VM may not be initialised yet, or it "
               "lives in a region excluded by the filter\"");
    }
    printf("}\n");

    vma_table_free(&vmas);
    return best >= 0 ? 0 : 2;
}

// lua_walk: list globals of the reported state.
static int lua_walk_cmd(int pid, const char *filter, uint32_t limit) {
    if (limit == 0 || limit > 4096) limit = 256;

    // Reuse the scan to find the state, then walk its globals table.
    struct vma_table vmas;
    if (!vma_table_load(pid, &vmas)) {
        print_error("Cannot read maps", errno);
        return 1;
    }
    uint64_t best_L = 0, best_G = 0, best_globals = 0;
    const char *best_layout = NULL;
    int best_score = -1;
    uint64_t walk_budget = 0;

    for (uint32_t i = 0; i < vmas.count && !best_globals; i++) {
        const struct vma *v = &vmas.items[i];
        if (!lua_region_interesting(v)) continue;
        uint64_t size = v->end - v->start;
        if (size < 0x200 || size > LUA_REGION_MAX) continue;
        // Same budget rule as lua_state: an unbounded walk over every heap
        // region is what made an earlier version look like a scanner and get
        // the target killed.
        if (walk_budget + size > LUA_READ_BUDGET) break;
        walk_budget += size;

        uint8_t *buf = (uint8_t *)malloc((size_t)size);
        if (!buf) continue;
        if (!raw_read(pid, v->start, buf, (size_t)size)) { free(buf); continue; }

        for (uint64_t off = 0; off + 0x40 <= size; off += 8) {
            uint64_t cand;
            memcpy(&cand, buf + off, 8);
            if (!lp_is_ptr(cand) || (cand & 7)) continue;
            uint64_t G = 0;
            char err[96] = "";
            const char *layout = lua_probe_layout(pid, cand, &G, err, sizeof(err));
            if (!layout) continue;
            bool is54 = strcmp(layout, "lua54") == 0;
            if (!is54) continue;
            uint64_t reg = l54_registry(pid, G);
            if (!reg) continue;
            uint64_t globals = l54_globals(pid, reg);
            if (!globals) continue;
            int score = l54_table_score(pid, globals);
            if (score <= best_score) continue;
            best_score = score;
            best_L = cand; best_G = G; best_globals = globals; best_layout = layout;
        }
        free(buf);
    }
    vma_table_free(&vmas);

    if (!best_globals) {
        printf("{\"status\":\"error\",\"pid\":%d,\"message\":\"no lua_State with a "
               "readable globals table found\"}\n", pid);
        return 2;
    }

    struct lua_entry *entries = (struct lua_entry *)calloc(limit, sizeof(struct lua_entry));
    if (!entries) { print_error("Out of memory", ENOMEM); return 1; }

    uint32_t n = 0;
    uint64_t node = 0;
    if (raw_read_exact(pid, best_globals + L54_TAB_NODE, &node, 8) && lp_is_ptr(node)) {
        for (int i = 0; i < 256 && n < limit; i++) {
            uint64_t kv = 0, vv = 0;
            uint8_t kt = 0, vt = 0;
            if (!l54_node_read(pid, node + (uint64_t)i * L54_NODE_SIZE, &kv, &kt, &vv, &vt))
                break;
            if ((kt & 0x7F) != L54_TT_SHRSTR) continue;
            char key[128];
            if (!l54_str_read(pid, kv, key, sizeof(key))) continue;
            if (filter && filter[0] && strstr(key, filter) == NULL) continue;
            struct lua_entry *e = &entries[n++];
            memset(e, 0, sizeof(*e));
            snprintf(e->key, sizeof(e->key), "%s", key);
            const char *tn = "other";
            switch (vt & 0x7F) {
                case L54_TT_SHRSTR: case L54_TT_LNGSTR: tn = "string"; break;
                case L54_TT_TABLE: tn = "table"; break;
                case L54_TT_LCLOSURE: case L54_TT_CCLOSURE: tn = "function"; break;
                case 0x03: tn = "integer"; break;
                case 0x13: tn = "number"; break;
                case 0x01: tn = "boolean"; break;
                case 0x00: tn = "nil"; break;
                default: break;
            }
            snprintf(e->type, sizeof(e->type), "%s", tn);
            e->value = vv;
        }
    }

    printf("{\"status\":\"ok\",\"pid\":%d,\"state\":\"0x%llx\",\"layout\":\"%s\","
           "\"G\":\"0x%llx\",\"globals\":\"0x%llx\",\"total\":%u,\"entries\":[",
           pid, (unsigned long long)best_L, best_layout ? best_layout : "?",
           (unsigned long long)best_G, (unsigned long long)best_globals, n);
    for (uint32_t i = 0; i < n; i++) {
        printf("%s{\"name\":\"%s\",\"type\":\"%s\",\"value\":\"0x%llx\"}",
               i ? "," : "", entries[i].key, entries[i].type,
               (unsigned long long)entries[i].value);
    }
    printf("]}\n");

    free(entries);
    return 0;
}
