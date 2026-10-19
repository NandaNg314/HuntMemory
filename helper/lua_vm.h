// ---------------------------------------------------------------------------
// Lua VM introspection: lua_state / lua_walk
//
// Two layouts are supported, selected by probing rather than configuration:
//
//   lua54    standard Lua 5.4 (absolute pointers). Offsets generated with
//            offsetof() from helper/vendor/lua; see profiles/lua-5.4-vendored.json.
//            VERIFIED end-to-end on the fixture (tools/fixture_lua54.c): every
//            step below passed with GAME_HEART_BEAT/GAME_SCORE/game_tick.
//
//   luajit   LuaJIT 2.1 GC64. Offsets taken from the disassembly of the target's
//            own lua_newstate/lua_newthread. The offset table is confirmed but
//            the full chain has NOT been verified on a real game, because
//            luaL_newstate runs before a debugger can attach and the target's
//            anti-cheat reacts to ptrace. Marked experimental in the output.
//
// The validation is the important part: a candidate is only returned when it
// satisfies structural invariants, so a scan that latches onto unrelated heap
// data fails closed instead of reporting a plausible-looking wrong address.
// ---------------------------------------------------------------------------

// ---- lua 5.4 offsets (offsetof on vendor/lua headers) ----------------------
#define L54_LS_LG          0x18
#define L54_LS_STACK       0x30
#define L54_LS_STACK_LAST  0x28
#define L54_G_REGISTRY     0x40
#define L54_G_MAINTHREAD   0x108
#define L54_TAB_ARRAY      0x10
#define L54_TAB_NODE       0x18
#define L54_STR_SHRLEN     0x0b
#define L54_STR_CONTENTS   0x18
#define L54_TV_SIZE        16
#define L54_NODE_SIZE      24

// ---- LuaJIT GC64 offsets (disassembly, see profiles/luajit-2.1-gc64.json) --
#define LJ_LS_G            0x10   // luaL_newstate 0xa242e90  ldr x8,[x19,#0x10]
#define LJ_LS_STACK        0x20   // lua_newthread 0xa1ef808  stp x8,x8,[x20,#0x20]
#define LJ_LS_STACK_LAST   0x28   // luaL_newstate 0xa242ef0  ldr x8,[x19,#0x28]
#define LJ_G_REGISTRY      0x88   // lua_newstate  0xa1eefda  stp x19,x9,[x19,#0x88]
#define LJ_STR_LEN         0x0c
#define LJ_STR_DATA        0x10
#define LJ_TAB_NODE        0x30
#define LJ_NODE_SIZE       16

// Bit 6 of a lua 5.4 tag marks a collectable object.
#define L54_BIT_COLLECT    0x40
#define L54_TT_SHRSTR      0x44
#define L54_TT_LNGSTR      0x54
#define L54_TT_TABLE       0x45
#define L54_TT_LCLOSURE    0x46
#define L54_TT_CCLOSURE    0x16

// A Lua heap pointer: heap-backed and even. Pointers on this device may carry
// an MTE tag in bits 55..48, so only the address part is compared.
static bool lp_is_ptr(uint64_t v) {
    uint64_t a = v & 0x0000FFFFFFFFFFFFULL;
    int tag = (int)((v >> 48) & 0xFF);
    return a > 0x10000 && (tag == 0 || tag == 0xB4) && (a & 1) == 0;
}

// Printable ASCII name (Lua identifiers, chunk names, short strings).
static bool lua_is_name(const char *s, size_t n) {
    if (n == 0 || n > 96) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c <= ' ' || c > 126) return false;
    }
    return true;
}

// --- lua 5.4 ---------------------------------------------------------------

// A 5.4 node: value at +0 (tt at +8), key tag at +9, key value at +0x10.
// The buffer is 24 bytes because the key value starts at +0x10; reading only
// 20 bytes would truncate the pointer's high half.
static bool l54_node_read(int pid, uint64_t node, uint64_t *kval, uint8_t *ktt,
                          uint64_t *vval, uint8_t *vtt) {
    uint8_t b[24];
    if (!raw_read_exact(pid, node, b, sizeof(b))) return false;
    memcpy(vval, b, 8);
    *vtt = b[8];
    *ktt = b[9];
    memcpy(kval, b + 0x10, 8);
    return true;
}

static bool l54_str_read(int pid, uint64_t s, char *out, size_t cap) {
    if (!lp_is_ptr(s)) return false;
    uint8_t h[0x20];
    if (!raw_read_exact(pid, s, h, sizeof(h))) return false;
    uint8_t len = h[L54_STR_SHRLEN];
    if (len == 0 || len > 96 || (size_t)len + 1 > cap) return false;
    char buf[128];
    if (!raw_read_exact(pid, s + L54_STR_CONTENTS, buf, len)) return false;
    if (!lua_is_name(buf, len)) return false;
    memcpy(out, buf, len);
    out[len] = '\0';
    return true;
}

// Look up `key` in a 5.4 table. Returns true and fills *vval/*vtt on a hit.
static bool l54_table_get(int pid, uint64_t tab, const char *key,
                          uint64_t *vval, uint8_t *vtt) {
    uint64_t node = 0;
    if (!lp_is_ptr(tab)) return false;
    if (!raw_read_exact(pid, tab + L54_TAB_NODE, &node, 8)) return false;
    if (!lp_is_ptr(node)) return false;
    for (int i = 0; i < 256; i++) {
        uint64_t kv = 0, vv = 0;
        uint8_t kt = 0, vt = 0;
        if (!l54_node_read(pid, node + (uint64_t)i * L54_NODE_SIZE, &kv, &kt, &vv, &vt))
            break;
        if ((kt & 0x7F) != L54_TT_SHRSTR) continue;
        char name[128];
        if (!l54_str_read(pid, kv, name, sizeof(name))) continue;
        if (strcmp(name, key) != 0) continue;
        if (vval) *vval = vv;
        if (vtt) *vtt = vt;
        return true;
    }
    return false;
}

// Count named string keys with non-nil values.
static int l54_table_score(int pid, uint64_t tab) {
    uint64_t node = 0;
    if (!lp_is_ptr(tab)) return -1;
    if (!raw_read_exact(pid, tab + L54_TAB_NODE, &node, 8)) return -1;
    if (!lp_is_ptr(node)) return -1;
    int good = 0;
    for (int i = 0; i < 256; i++) {
        uint64_t kv = 0, vv = 0;
        uint8_t kt = 0, vt = 0;
        if (!l54_node_read(pid, node + (uint64_t)i * L54_NODE_SIZE, &kv, &kt, &vv, &vt)) break;
        if ((vt & 0x7F) == 0) continue;
        if ((kt & 0x7F) != L54_TT_SHRSTR) continue;
        char name[128];
        if (l54_str_read(pid, kv, name, sizeof(name))) good++;
    }
    return good;
}

// Validate a 5.4 lua_State and resolve G.
static bool l54_verify(int pid, uint64_t L, uint64_t *G_out, char *err, size_t cap) {
    uint8_t h[0x40];
    if (!raw_read_exact(pid, L, h, sizeof(h))) {
        snprintf(err, cap, "lua_State unreadable");
        return false;
    }
    uint64_t G, stack, last;
    memcpy(&G,     h + L54_LS_LG,         8);
    memcpy(&stack, h + L54_LS_STACK,      8);
    memcpy(&last,  h + L54_LS_STACK_LAST, 8);
    if (!lp_is_ptr(G))     { snprintf(err, cap, "l_G is not a pointer"); return false; }
    if (!lp_is_ptr(stack)) { snprintf(err, cap, "stack is not a pointer"); return false; }
    if (!lp_is_ptr(last))  { snprintf(err, cap, "stack_last is not a pointer"); return false; }
    if (last < stack)      { snprintf(err, cap, "stack_last < stack"); return false; }
    uint64_t span = last - stack;
    if (span == 0 || span % L54_TV_SIZE != 0) {
        snprintf(err, cap, "stack span is not a whole number of TValues");
        return false;
    }
    uint64_t mt = 0;
    if (!raw_read_exact(pid, G + L54_G_MAINTHREAD, &mt, 8)) {
        snprintf(err, cap, "global_State unreadable");
        return false;
    }
    if (mt != L) { snprintf(err, cap, "G->mainthread != L"); return false; }
    *G_out = G;
    return true;
}

// Registry and globals for 5.4.
static uint64_t l54_registry(int pid, uint64_t G) {
    uint8_t b[16];
    if (!raw_read_exact(pid, G + L54_G_REGISTRY, b, sizeof(b))) return 0;
    uint64_t v;
    memcpy(&v, b, 8);
    return (b[8] & 0x7F) == L54_TT_TABLE ? v : 0;
}

static uint64_t l54_globals(int pid, uint64_t registry) {
    uint64_t array = 0;
    if (!raw_read_exact(pid, registry + L54_TAB_ARRAY, &array, 8)) return 0;
    if (!lp_is_ptr(array)) return 0;
    // LUA_RIDX_GLOBALS is 2 and the array is 1-based: _G is array[1].
    uint8_t b[12];
    if (!raw_read_exact(pid, array + 1 * L54_TV_SIZE, b, sizeof(b))) return 0;
    uint64_t v;
    memcpy(&v, b, 8);
    return (b[8] & 0x7F) == L54_TT_TABLE ? v : 0;
}

// --- LuaJIT GC64 -----------------------------------------------------------

// GC64 TValue: (lo:u32, hi:u32). A pointer is hi<<32|lo, with the heap base
// folded in when bit 47 is set.
static uint64_t lj_ptr(uint32_t lo, uint32_t hi, uint64_t gc_base) {
    uint64_t v = ((uint64_t)hi << 32) | lo;
    if (gc_base && (v & 0x800000000000ULL)) return gc_base | (v & 0x7FFFFFFFFFFFULL);
    return v;
}

// GCstr: len at +0x0c, data at +0x10.
static bool lj_str_read(int pid, uint64_t s, char *out, size_t cap) {
    if (!lp_is_ptr(s)) return false;
    uint8_t h[16];
    if (!raw_read_exact(pid, s, h, sizeof(h))) return false;
    uint32_t len;
    memcpy(&len, h + LJ_STR_LEN, 4);
    if (len == 0 || len > 96 || (size_t)len + 1 > cap) return false;
    char buf[128];
    if (!raw_read_exact(pid, s + LJ_STR_DATA, buf, len)) return false;
    if (!lua_is_name(buf, len)) return false;
    memcpy(out, buf, len);
    out[len] = '\0';
    return true;
}

// Reserved for the LuaJIT globals walk; unused until that layout is verified.
__attribute__((unused))
static int lj_table_score(int pid, uint64_t tab, uint64_t gc_base) {
    uint64_t node = 0;
    if (!lp_is_ptr(tab)) return -1;
    if (!raw_read_exact(pid, tab + LJ_TAB_NODE, &node, 8)) return -1;
    if (!lp_is_ptr(node)) return -1;
    int good = 0;
    for (int i = 0; i < 256; i++) {
        uint8_t b[8];
        if (!raw_read_exact(pid, node + (uint64_t)i * LJ_NODE_SIZE, b, sizeof(b))) break;
        uint32_t lo, hi;
        memcpy(&lo, b, 4);
        memcpy(&hi, b + 4, 4);
        uint64_t k = lj_ptr(lo, hi, gc_base);
        if (!lp_is_ptr(k)) continue;
        char name[128];
        if (lj_str_read(pid, k, name, sizeof(name))) good++;
    }
    return good;
}

// --- detection -------------------------------------------------------------

// Try to interpret L as a lua 5.4 state, then as a LuaJIT state.
// Returns the layout id ("lua54" / "luajit") or NULL.
static const char *lua_probe_layout(int pid, uint64_t L, uint64_t *G_out,
                                    char *err, size_t cap) {
    if (l54_verify(pid, L, G_out, err, cap)) return "lua54";
    // LuaJIT: G at +0x10, and G+0x10/G+0x18 form the GC threshold pair.
    uint8_t h[0x40];
    if (!raw_read_exact(pid, L, h, sizeof(h))) return NULL;
    uint64_t G, stack, last;
    memcpy(&G,     h + LJ_LS_G,          8);
    memcpy(&stack, h + LJ_LS_STACK,      8);
    memcpy(&last,  h + LJ_LS_STACK_LAST, 8);
    if (!lp_is_ptr(G) || !lp_is_ptr(stack) || !lp_is_ptr(last) || last < stack) return NULL;
    uint8_t g[0x20];
    if (!raw_read_exact(pid, G, g, sizeof(g))) return NULL;
    uint64_t ga, gb;
    memcpy(&ga, g + 0x10, 8);
    memcpy(&gb, g + 0x18, 8);
    // GCthreshold/GCdebt: two non-zero, non-pointer byte counts.
    if (ga == 0 || gb == 0 || ga > (1ULL << 34) || gb > (1ULL << 34)) return NULL;
    if (lp_is_ptr(ga) || lp_is_ptr(gb)) return NULL;
    *G_out = G;
    snprintf(err, cap, "luajit");
    return "luajit";
}
