// Stable Lua 5.4 fixture for validating the introspection chain.
//
// Differences from the real target that matter here:
//   * absolute 64-bit pointers (no GC64 compression), so pointer_codec's
//     abs64 path is exercised;
//   * nothing reallocates after main, so addresses stay valid between calls;
//   * it prints L so a test can cross-check the scanner against ground truth.
//
// The globals planted here are the verification targets:
//   GAME_HEART_BEAT = "beat"   (string, found by text search)
//   GAME_SCORE      = 12345    (integer)
//   game_tick       = function (closure with a Proto)
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

static int game_tick(lua_State *L) {
    lua_pushinteger(L, luaL_checkinteger(L, 1) * 2);
    return 1;
}

int main(void) {
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);

    lua_pushstring(L, "beat");
    lua_setglobal(L, "GAME_HEART_BEAT");
    lua_pushinteger(L, 12345);
    lua_setglobal(L, "GAME_SCORE");
    lua_pushcfunction(L, game_tick);
    lua_setglobal(L, "game_tick");

    printf("pid=%d L=%p\n", (int)getpid(), (void *)L);
    fflush(stdout);

    for (;;) pause();
}
