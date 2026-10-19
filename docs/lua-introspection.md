# Lua VM introspection (`lua_state` / `lua_walk`)

Two commands locate a Lua VM inside a running process and enumerate its globals.
Both are read-only.

```
hmkpm_cli lua_state <pid>
hmkpm_cli lua_scan  <pid> --anchor <string> [--max-candidates N]
hmkpm_cli lua_walk  <pid> [name_filter] [limit]
```

### `lua_scan`: the one-step form

When you already know a string that the target's Lua code stores (a global name,
a UI label, a config key), `lua_scan` resolves the whole chain in one call:

```
lua_scan 9351 --anchor GAME_SCORE
```

```json
{"steps":{"anchor_string":1,"tables_with_key":0,"states":1},
 "results":[{"addr":"0xb400007b6ad360a8","layout":"lua54",
             "G":"0xb400007b6ad36170","globals":"0xb4000079fad3b6f0"}],
 "count":1,
 "best":{"addr":"0xb400007b6ad360a8","G":"0xb400007b6ad36170","globals":"0xb4000079fad3b6f0"}}
```

It reads about 11 MB and needs one sweep: a byte match plus a length check gives
the exact GCstr, and the pointer scan finds the table holding it as a key. The
state is then confirmed with the same rules `lua_state` uses, so `lua_scan`
cannot report an address that `lua_state` would reject. Verified against a cold
fixture start: reported `0xb400007983cd89d8`, matching the fixture's own print.

`--max-candidates` bounds how many string hits and states are collected (default
8, cap 32). When the anchor is missing or is a value rather than a key, the
command reports which stage came up empty instead of guessing.

## What is supported today

| Engine | Layout | Status |
|---|---|---|
| Lua 5.4 (`helper/vendor/lua`) | absolute 64-bit pointers | **verified end-to-end** |
| LuaJIT 2.1 GC64 (mini-world) | GC64 compressed pointers | offsets confirmed from disassembly, **chain unverified** |

`lua_state` probes both layouts on every candidate; the reported `layout` field
says which one matched. A LuaJIT hit carries an `experimental` warning because
it has never been confirmed against a live game.

## How the scan converges

The commands print a counter per stage, so a weak filter is visible instead of
producing a confident-looking wrong answer:

```
L1_aligned   aligned heap pointers seen while sweeping native heap regions
L2_state     records whose bytes probe as a lua_State
L3_registry  records whose global_State yields a registry table
L4_globals   records whose registry yields a globals table with named keys
```

Only L4 survivors are reported. When several remain, the winner is the one with
the richest globals table, then the deepest stack.

Measured on the fixture: `2335 → 12 → 12 → 12`, collapsing to a single unique
address.

## Validation rules

A candidate is discarded unless all of these hold:

- `stack_last >= stack` and `(stack_last - stack) % sizeof(TValue) == 0`
- `G->mainthread == L` — the identity that separates a real state from a
  heap word that merely looks like one
- the registry is a table (`tt` 0x45), and so is the globals table
- every pointer is heap-backed and even (MTE tag bits ignored when comparing)

`lua_state` returns nothing rather than an address that fails these checks.

## Offsets and where they come from

Profiles live in `profiles/`:

- `lua-5.4-vendored.json` — generated with `offsetof()` from the headers the
  engine was compiled against. Regenerate with `tools/gen_offsets54.c`.
- `luajit-2.1-gc64.json` — read off the disassembly of the target's own
  `lua_newstate` / `lua_newthread`; each entry cites the instruction.

For a new engine: generate a profile the same way rather than adding a hardcoded
table to the C code.

## Verification

`tools/fixture_lua54.c` builds a stable 5.4 VM with known globals and prints its
`lua_State`, so the scanner can be checked against ground truth:

```sh
# build (from helper/)
make   # or use the NDK cross compiler as in the main README
adb push ... /data/local/tmp/fx54 && adb shell /data/local/tmp/fx54
# fx54 prints: pid=9351 L=0xb400007b6ad360a8

adb shell su -c '/data/local/tmp/hmkpm_cli lua_state 9351'
# candidates[0].addr == 0xb400007b6ad360a8

adb shell su -c '/data/local/tmp/hmkpm_cli lua_walk 9351 GAME'
# GAME_HEART_BEAT string, GAME_SCORE 0x3039 (12345)
```

## Known limits

- **`lua_exec` is disabled.** Running a chunk needs ptrace injection, and the
  target observed in testing exits when a tracer attaches. Use `lua_walk` to
  find a global and `write_memory` to change it.
- **`lua_capture` rarely hits.** `luaL_newstate` runs once within tens of
  milliseconds of the module being mapped, which is usually faster than a
  ptrace attach. It reports a precise hint when it misses.
- **LuaJIT globals are not enumerated yet.** The GC64 table node layout differs
  from 5.4 and needs the same verification the 5.4 path received.
