// Print the vendored Lua 5.4 structure offsets so the profile is generated
// from the header the fixture was built against, not from memory.
#include <stdio.h>
#include <stddef.h>
#include "lstate.h"
#include "lobject.h"
#include "lfunc.h"

int main(void) {
    printf("{\n");
    printf("  \"lua_State\": {\n");
    printf("    \"size\": %zu,\n", sizeof(lua_State));
    printf("    \"next\": %zu, \"tt\": %zu, \"marked\": %zu,\n",
           offsetof(lua_State, next), offsetof(lua_State, tt), offsetof(lua_State, marked));
    printf("    \"status\": %zu,\n", offsetof(lua_State, status));
    printf("    \"top\": %zu, \"l_G\": %zu,\n",
           offsetof(lua_State, top), offsetof(lua_State, l_G));
    printf("    \"ci\": %zu, \"stack_last\": %zu, \"stack\": %zu\n",
           offsetof(lua_State, ci), offsetof(lua_State, stack_last), offsetof(lua_State, stack));
    printf("  },\n");
    printf("  \"global_State\": {\n");
    printf("    \"size\": %zu,\n", sizeof(global_State));
    printf("    \"strt\": %zu, \"l_registry\": %zu, \"mainthread\": %zu\n",
           offsetof(global_State, strt), offsetof(global_State, l_registry),
           offsetof(global_State, mainthread));
    printf("  },\n");
    printf("  \"Table\": { \"size\": %zu, \"node\": %zu, \"alimit\": %zu },\n",
           sizeof(Table), offsetof(Table, node), offsetof(Table, alimit));
    printf("  \"TString\": { \"shrlen\": %zu, \"u\": %zu, \"contents\": %zu },\n",
           offsetof(TString, shrlen), offsetof(TString, u), offsetof(TString, contents));
    printf("  \"Proto\": { \"source\": %zu, \"numparams\": %zu },\n",
           offsetof(Proto, source), offsetof(Proto, numparams));
    printf("  \"sizes\": { \"TValue\": %zu, \"Node\": %zu, \"TString\": %zu, \"Proto\": %zu }\n",
           sizeof(TValue), sizeof(Node), sizeof(TString), sizeof(Proto));
    printf("}\n");
    return 0;
}
