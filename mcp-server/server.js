import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { readFileSync } from "node:fs";
import { makeTools } from "./tools.js";

// Read the version from package.json so a release only has to be bumped in one
// place; a hardcoded string here silently drifts from the published package.
export const VERSION = (() => {
  try {
    const pkg = JSON.parse(
      readFileSync(new URL("./package.json", import.meta.url), "utf8"),
    );
    return pkg.version || "0.0.0";
  } catch {
    return "0.0.0";
  }
})();

const TYPES = ["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64"];

function ok(data) {
  const text = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  let structuredContent = undefined;
  if (data && typeof data === "object") {
    if (Array.isArray(data)) {
      structuredContent = { items: data };
    } else {
      structuredContent = data;
    }
  }
  return {
    content: [{ type: "text", text }],
    ...(structuredContent ? { structuredContent } : {}),
  };
}

function fail(err) {
  return { content: [{ type: "text", text: `Error: ${err.message}` }], isError: true };
}

export function buildServer(options) {
  const tools = makeTools(options);
  const server = new McpServer({
    name: "hmkpm-mcp",
    version: VERSION,
  });

  // 1. hmkpm_probe
  server.registerTool(
    "hmkpm_probe",
    {
      title: "Probe HMKPM/KernelPatch status",
      description:
        "Check whether the KernelPatch (HMKPM) memory service is loaded in the kernel. Returns version, mmap_lock_offset and supported feature bitmask.",
      inputSchema: {},
    },
    async () => {
      try {
        return ok(await tools.probe());
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 2. list_processes
  server.registerTool(
    "list_processes",
    {
      title: "List running processes",
      description:
        "Enumerate running games, apps, and notable processes on the device. Optionally filter by process name substring or PID.",
      inputSchema: {
        filter: z.string().optional().describe("Substring of process name (e.g. package name) or an exact PID."),
      },
    },
    async ({ filter }) => {
      try {
        return ok(await tools.listProcesses({ filter }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // Helper: list_maps
  server.registerTool(
    "list_maps",
    {
      title: "List process memory maps",
      description: "Read /proc/<pid>/maps for a target process, optionally filtering by module name (e.g. libil2cpp.so, dalvik, libc).",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        filter: z.string().optional().describe("Substring filter for map path/name."),
      },
    },
    async ({ pid, filter }) => {
      try {
        return ok(await tools.maps(pid, filter));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 3. read_memory
  server.registerTool(
    "read_memory",
    {
      title: "Read memory bytes",
      description: "Read raw memory from a target process at the specified address. Returns Hex and UTF-8 decoded content.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        address: z.union([z.string(), z.number()]).describe("Memory address as hex string (e.g. \"0x7f12345678\") or number."),
        size: z.number().int().positive().max(16 * 1024 * 1024).describe("Number of bytes to read (max 16MB)."),
      },
    },
    async ({ pid, address, size }) => {
      try {
        return ok(await tools.readMemory(pid, address, size));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 4. read_value
  server.registerTool(
    "read_value",
    {
      title: "Read typed value",
      description: "Read a typed numeric value (i8, u8, i16, u16, i32, u32, i64, u64, f32, f64) from target memory address.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        address: z.union([z.string(), z.number()]).describe("Memory address as hex string or number."),
        type: z.enum(TYPES).describe("Data type: i8, u8, i16, u16, i32, u32, i64, u64, f32, or f64."),
      },
    },
    async ({ pid, address, type }) => {
      try {
        return ok(await tools.readValue(pid, address, type));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 5. write_memory
  server.registerTool(
    "write_memory",
    {
      title: "Write raw memory bytes",
      description: "Write raw bytes (hex string) to target process memory address.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        address: z.union([z.string(), z.number()]).describe("Memory address as hex string or number."),
        hex_data: z.string().describe("Even-length hex string to write, e.g. \"0000803f\" or \"9090\"."),
      },
    },
    async ({ pid, address, hex_data }) => {
      try {
        return ok(await tools.writeMemory(pid, address, hex_data));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 6. write_value
  server.registerTool(
    "write_value",
    {
      title: "Write typed value",
      description: "Write a typed numeric value (e.g. modify coins, hp, float speeds) at target address.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        address: z.union([z.string(), z.number()]).describe("Memory address as hex string or number."),
        type: z.enum(TYPES).describe("Data type: i8, u8, i16, u16, i32, u32, i64, u64, f32, or f64."),
        value: z.union([z.string(), z.number()]).describe("New value to write (e.g. 999999, 100.5, or \"0x1000\")."),
      },
    },
    async ({ pid, address, type, value }) => {
      try {
        return ok(await tools.writeValue(pid, address, type, value));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 7. scan_kernel
  server.registerTool(
    "scan_kernel",
    {
      title: "Kernel-space SIMD value scan",
      description:
        "Execute ultra-fast value scanning directly in kernel space via HMKPM_MAGIC_SCAN_KERNEL (NEON SIMD accelerated). Searches memory maps without userspace overhead.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        value: z.union([z.string(), z.number()]).describe("Value to search for."),
        type: z.enum(TYPES).default("i32").describe("Data type (default i32)."),
        align: z.number().int().positive().optional().describe("Memory alignment in bytes (e.g. 1, 2, 4, 8). Defaults to type size."),
        perms: z.string().default("rw-p").describe("Memory permission filter (e.g. \"rw-p\", \"r--p\"). Default \"rw-p\"."),
      },
    },
    async ({ pid, value, type, align, perms }) => {
      try {
        return ok(await tools.scanKernel({ pid, value, type, align, perms }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 8. scan_seed -- fast exact-value seed for a fuzzy scan session
  server.registerTool(
    "scan_seed",
    {
      title: "Fuzzy scan: seed session with an exact value (fast path)",
      description:
        "Start a scan session by searching for an exact known/near value using the kernel SIMD scan, then store the hits (address+value) into a session keyed by (pid, type). This is the fast, GameGuardian-style path: the candidate set starts small and targeted, unlike scan_unknown which snapshots every slot and can truncate on large processes. After seeding, change the value in-game and call scan_filter to narrow down. NOTE: session is destroyed when the target process restarts.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        value: z.union([z.string(), z.number()]).describe("Exact value to search for."),
        type: z.enum(TYPES).default("i32").describe("Data type (default i32)."),
        align: z.number().int().positive().optional().describe("Memory alignment in bytes (e.g. 1, 2, 4, 8). Defaults to type size."),
        perms: z.string().default("rw-p").describe("Memory permission filter. Default \"rw-p\"."),
      },
    },
    async ({ pid, value, type, align, perms }) => {
      try {
        return ok(await tools.scanSeed({ pid, value, type, align, perms }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 9. scan_unknown -- first pass of a fuzzy / differential scan
  server.registerTool(
    "scan_unknown",
    {
      title: "Fuzzy scan: unknown initial value (first pass)",
      description:
        "Start a GameGuardian-style differential scan session. Snapshots every aligned candidate slot in the target's readable memory and stores address+value into a session keyed by (pid, type). Call this once, then use scan_filter repeatedly while the value changes in-game, and scan_results to list survivors. NOTE: the session is destroyed when the target process restarts.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        type: z.enum(TYPES).default("i32").describe("Data type (default i32)."),
        align: z.number().int().positive().optional().describe("Memory alignment in bytes (e.g. 1, 2, 4, 8). Defaults to type size."),
        perms: z.string().default("rw-p").describe("Memory permission filter. Default \"rw-p\"."),
      },
    },
    async ({ pid, type, align, perms }) => {
      try {
        return ok(await tools.scanUnknown({ pid, type, align, perms }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 9. scan_filter -- narrow the session
  server.registerTool(
    "scan_filter",
    {
      title: "Fuzzy scan: filter candidates (next passes)",
      description:
        "Re-read every candidate from the current scan session and keep only those matching the mode. Modes: gt/lt/eq/ne (compare to value), changed, unchanged, increased, decreased (compare to previous pass), range (value = \"min:max\"). Repeat after changing the value in-game to converge on the right address.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        type: z.enum(TYPES).default("i32").describe("Data type (must match scan_unknown)."),
        mode: z
          .enum(["gt", "lt", "eq", "ne", "changed", "unchanged", "increased", "decreased", "range"])
          .describe("Filter predicate."),
        value: z
          .union([z.string(), z.number()])
          .optional()
          .describe("Comparison value (required for gt/lt/eq/ne; \"min:max\" for range; omit for changed/unchanged/increased/decreased)."),
      },
    },
    async ({ pid, type, mode, value }) => {
      try {
        return ok(await tools.scanFilter({ pid, type, mode, value }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 10. scan_results
  server.registerTool(
    "scan_results",
    {
      title: "Fuzzy scan: list surviving addresses",
      description: "List the candidate addresses remaining in the current scan session (capped), plus the total count.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        type: z.enum(TYPES).default("i32").describe("Data type (must match scan_unknown)."),
      },
    },
    async ({ pid, type }) => {
      try {
        return ok(await tools.scanResults({ pid, type }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 11. scan_reset
  server.registerTool(
    "scan_reset",
    {
      title: "Fuzzy scan: reset session",
      description: "Delete the scan session for (pid, type). Call before starting a fresh scan_unknown.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        type: z.enum(TYPES).default("i32").describe("Data type."),
      },
    },
    async ({ pid, type }) => {
      try {
        return ok(await tools.scanReset({ pid, type }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 12. read_values -- batch read, avoids one process per address
  server.registerTool(
    "read_values",
    {
      title: "Read many typed values at once",
      description:
        "Read the same typed value from many addresses in a single call. Use this to inspect a candidate list from scan_results without paying a process spawn per address. Returns one entry per address with a `readable` flag, so stale/unmapped addresses stay distinguishable from real zeros.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        addresses: z
          .array(z.union([z.string(), z.number()]))
          .min(1)
          .max(4096)
          .describe("Addresses as hex strings or numbers (max 4096)."),
        type: z.enum(TYPES).default("i32").describe("Data type (default i32)."),
      },
    },
    async ({ pid, addresses, type }) => {
      try {
        return ok(await tools.readValues({ pid, addresses, type }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 13. find_string -- literal byte search
  server.registerTool(
    "find_string",
    {
      title: "Search for a literal string in memory",
      description:
        "Search the target's readable memory for a literal byte sequence (UTF-8 text, a config key, a URL, part of a JSON payload). Complements the numeric scans: locate an identifier here, then use read_values or module_base to follow the data. Returns matching addresses.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        pattern: z.string().min(1).describe("Literal byte string to search for."),
        perms: z.string().default("rw-p").describe("Memory permission filter. Default \"rw-p\"."),
        limit: z.number().int().positive().max(5000).default(100).describe("Maximum results (default 100)."),
      },
    },
    async ({ pid, pattern, perms, limit }) => {
      try {
        return ok(await tools.findString({ pid, pattern, perms, limit }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 14. module_base -- load base + RVA resolution
  server.registerTool(
    "module_base",
    {
      title: "Resolve a module load base (optional plus RVA)",
      description:
        "Return the runtime load base of a shared object (e.g. libil2cpp.so, libc.so), optionally with an RVA added. Pointer chains in a native app start from a module base, so this is the entry point for address resolution.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        module: z.string().min(1).describe("Library file name, e.g. \"libil2cpp.so\"."),
        rva: z
          .union([z.string(), z.number()])
          .optional()
          .describe("Optional offset from the base (hex string or number)."),
      },
    },
    async ({ pid, module, rva }) => {
      try {
        return ok(await tools.moduleBase({ pid, module, rva }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 15. pointer_chain -- multi-level pointer resolution
  server.registerTool(
    "pointer_chain",
    {
      title: "Resolve a multi-level pointer chain",
      description:
        "Resolve base+rva -> [off1] -> [off2] -> ... -> final address in a single call. The last offset is added WITHOUT dereferencing, so it names the field itself. The base may be a module name (resolved to its load base, surviving restarts) or an absolute address. Returns every hop with its intermediate pointer, so a broken chain shows exactly which step failed.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        base: z
          .union([z.string(), z.number()])
          .describe("Module name (e.g. \"libil2cpp.so\") or an absolute base address."),
        rva: z
          .union([z.string(), z.number()])
          .default(0)
          .describe("Offset added to the base before the first dereference."),
        offsets: z
          .array(z.union([z.string(), z.number()]))
          .default([])
          .describe("Chain offsets. All but the last are dereferenced; the last is the final field offset."),
        type: z.enum(TYPES).default("i32").describe("Type used to read the final value."),
      },
    },
    async ({ pid, base, rva, offsets, type }) => {
      try {
        return ok(await tools.pointerChain({ pid, base, rva, offsets, type }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 16. freeze_value -- pin addresses to a fixed value
  server.registerTool(
    "freeze_value",
    {
      title: "Freeze addresses at a fixed value",
      description:
        "Keep one or more addresses pinned to a value. A detached daemon on the device rewrites them on an interval, so the app cannot overwrite the value between calls. Omit `addresses` to freeze every survivor of the current scan session (scan_seed / scan_filter). Freezing is per target process and survives MCP restarts until unfreeze_value or a reboot.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        type: z.enum(TYPES).default("i32").describe("Data type."),
        value: z.union([z.string(), z.number()]).describe("Value to hold."),
        addresses: z
          .array(z.union([z.string(), z.number()]))
          .max(256)
          .optional()
          .describe("Addresses to freeze; omit to use the current scan session."),
        intervalMs: z
          .number()
          .int()
          .min(10)
          .max(2000)
          .default(50)
          .describe("Rewrite interval in ms (default 50)."),
      },
    },
    async ({ pid, type, value, addresses, intervalMs }) => {
      try {
        return ok(await tools.freeze({ pid, type, value, addresses, intervalMs }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 17. unfreeze_value
  server.registerTool(
    "unfreeze_value",
    {
      title: "Release frozen addresses",
      description:
        "Stop freezing addresses for this process. With no arguments every freeze is released and the daemon exits; otherwise only the listed addresses are released.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        addresses: z
          .array(z.union([z.string(), z.number()]))
          .optional()
          .describe("Addresses to release; omit to release everything."),
      },
    },
    async ({ pid, addresses }) => {
      try {
        return ok(await tools.unfreeze({ pid, addresses }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 18. list_freezes
  server.registerTool(
    "list_freezes",
    {
      title: "List frozen addresses and daemon status",
      description:
        "Report which addresses are frozen for a process, the bytes being written, and whether the freeze daemon is alive. Use it to confirm a freeze is actually holding before relying on it.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
      },
    },
    async ({ pid }) => {
      try {
        return ok(await tools.freezeList({ pid }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 19. dump_memory
  server.registerTool(
    "dump_memory",
    {
      title: "Dump a memory region or module to a file",
      description:
        "Stream a memory region, or a whole module, to a file on the device instead of returning hex inline. A .txt sidecar is written next to it mapping file offsets to addresses and permissions, so the dump can be loaded in IDA/Ghidra or parsed directly. Passing a module name dumps every segment that belongs to it.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        target: z
          .union([z.string(), z.number()])
          .describe("Module name (e.g. \"libil2cpp.so\") or a start address."),
        size: z
          .union([z.string(), z.number()])
          .default("all")
          .describe("\"all\" to dump every readable region from the start, or a byte count."),
        outPath: z.string().min(1).describe("Destination path on the device."),
        perms: z.string().default("rw-p").describe("Permission filter used when size is \"all\"."),
      },
    },
    async ({ pid, target, size, outPath, perms }) => {
      try {
        return ok(await tools.dump({ pid, target, size, outPath, perms }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 20. scan_rva -- module-relative scan
  server.registerTool(
    "scan_rva",
    {
      title: "Scan inside one module, report RVAs",
      description:
        "Scan a single module's readable segments for a value and report module-relative offsets instead of absolute addresses. Offsets stay valid across restarts and are what a pointer chain or a code patch needs, so prefer this over scan_kernel when the target lives in native code.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        module: z.string().min(1).describe("Library file name, e.g. \"libil2cpp.so\"."),
        type: z.enum(TYPES).default("i32").describe("Data type."),
        value: z.union([z.string(), z.number()]).describe("Value to find."),
        align: z.number().int().positive().optional().describe("Alignment override."),
      },
    },
    async ({ pid, module, type, value, align }) => {
      try {
        return ok(await tools.scanRva({ pid, module, value, type, align }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 21. find_instructions -- ARM64 pattern search
  server.registerTool(
    "find_instructions",
    {
      title: "Search executable memory for ARM64 instructions",
      description:
        "Find an ARM64 instruction by opcode with wildcard bits: pass \"B9000000/FFF00000\" for a 32-bit STR with any registers/offset. Searches one module (e.g. \"libil2cpp.so\") or every segment matching a permission filter. Results include the module and RVA for module hits, so a code patch can be located again after a restart. Common patterns: RET D65F03C0/FFFFFFFF, NOP D503201F/FFFFFFFF, BL 94000000/FC000000, MOVZ 52800000/FF800000.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        pattern: z
          .string()
          .min(1)
          .describe("Instruction and mask as \"hexvalue/hexmask\" (mask defaults to FFFFFFFF)."),
        where: z
          .string()
          .default("r-xp")
          .describe("Module file name, or a permission filter such as \"r-xp\"."),
        limit: z.number().int().positive().max(5000).default(100).describe("Maximum results."),
      },
    },
    async ({ pid, pattern, where, limit }) => {
      try {
        return ok(await tools.findInstructions({ pid, pattern, where, limit }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 25. run_lua -- script multiple operations into one call
  server.registerTool(
    "run_lua",
    {
      title: "Run a Lua script against the target's memory",
      description:
        "Execute a Lua script that reads and writes the target's memory through a synchronous hm.* API, in one call instead of a round trip per operation. Use it for multi-step work: scan, then filter, then confirm, then write, then re-check. The script runs OUTSIDE the target process (it is not injected); it only reaches memory through hm.*. " +
        "API: hm.pid; hm.read(addr,type) -> value|nil,errno; hm.write(addr,type,value) -> true|nil,errno; hm.read_bytes(addr,n) -> string[,unreadable_bytes] (nil,errno only when nothing is readable); hm.write_bytes(addr,str) -> true|nil; " +
        "hm.chain(base_or_module, rva, {off1,off2,...}) -> addr|nil,failed_step (last offset not dereferenced); " +
        "hm.scan(type,value,{align,perms,module,limit}) -> {{addr,value},...} (omit limit to get every hit; a small limit makes the kernel under-report); " +
        "hm.freeze(addr_list,type,value,interval_ms) -> written_count; hm.unfreeze(); hm.module(name) -> {base,stop,vmas}; hm.map(path_filter) -> {{start,stop,size,perms,path}}; " +
        "hm.b64(s); hm.log(...) (captured in the response); hm.sleep(ms). " +
        "Libraries available: string, table, math, utf8. No io, os, require, dofile, load. Scripts are interrupted after timeoutS.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        script: z
          .string()
          .min(1)
          .describe("Lua source. Return values are reported in `returns`; hm.log() output in `log`."),
        timeoutS: z
          .number()
          .int()
          .min(1)
          .max(600)
          .default(30)
          .describe("Wall-clock budget in seconds before the script is interrupted."),
      },
    },
    async ({ pid, script, timeoutS }) => {
      try {
        return ok(await tools.runLua({ pid, script, timeoutS }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 25. trace_watchpoint -- ARM64 hardware watchpoint & execution breakpoint
  server.registerTool(
    "trace_watchpoint",
    {
      title: "Trace memory accesses and execution using ARM64 hardware breakpoints/watchpoints",
      description:
        "Monitor memory read/write hits or instruction execution at a specific address using ARM64 hardware debug registers (DBGBVR/DBGBCR for exec, DBGWVR/DBGWCR for read/write). " +
        "Captures the triggering instruction (e.g. STR W0, [X19, #0x28]), caller return address (LR), " +
        "full unwound call stack, module name and relative offset (RVA), plus complete register snapshots (PC, SP, LR, FP, X0-X30, PSTATE) without modifying target code.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        address: z
          .union([z.string(), z.number()])
          .describe("Target memory address to monitor (e.g. '0x7a81001234' or integer)."),
        size: z
          .number()
          .int()
          .refine((n) => [1, 2, 4, 8].includes(n), { message: "size must be 1, 2, 4, or 8" })
          .default(4)
          .describe("Watchpoint byte size (1, 2, 4, or 8). Default: 4. Ignored for 'exec' breakpoints."),
        type: z
          .enum(["write", "read", "access", "exec"])
          .default("write")
          .describe("Trigger type: 'write' (Store, DBGWVR), 'read' (Load, DBGWVR), 'access' (both, DBGWVR), or 'exec' (Instruction Breakpoint, DBGBVR). Default: 'write'."),
        durationMs: z
          .number()
          .int()
          .min(100)
          .max(30000)
          .default(2000)
          .describe("Monitoring duration in milliseconds (default: 2000ms, max: 30000ms)."),
        maxHits: z
          .number()
          .int()
          .min(1)
          .max(100)
          .default(10)
          .describe("Maximum number of hits to record before auto-stopping (default: 10)."),
      },
    },
    async ({ pid, address, size, type, durationMs, maxHits }) => {
      try {
        return ok(await tools.traceWatchpoint({ pid, address, size, type, durationMs, maxHits }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 26. thread_suspend -- suspend target thread or entire process
  server.registerTool(
    "thread_suspend",
    {
      title: "Suspend target thread or process and capture register state + call stack",
      description: "Suspend a specific thread (or main thread) in the target process. Returns current PC, LR, full registers (X0-X30, SP, FP), and unwound call stack.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        tid: z.number().int().min(0).default(0).describe("Specific thread ID (0 = target main PID)."),
      },
    },
    async ({ pid, tid }) => {
      try {
        return ok(await tools.threadSuspend({ pid, tid }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 27. thread_resume -- resume target thread or entire process
  server.registerTool(
    "thread_resume",
    {
      title: "Resume target thread or process",
      description: "Resume a previously suspended thread or process.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        tid: z.number().int().min(0).default(0).describe("Specific thread ID (0 = target main PID)."),
      },
    },
    async ({ pid, tid }) => {
      try {
        return ok(await tools.threadResume({ pid, tid }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // 28. thread_step -- single-step target thread N instructions
  server.registerTool(
    "thread_step",
    {
      title: "Single-step target thread N instructions",
      description: "Single-step a suspended thread for N instructions, recording PC, disassembled instruction, and register changes at each step.",
      inputSchema: {
        pid: z.number().int().positive().describe("Target process ID."),
        tid: z.number().int().min(0).default(0).describe("Specific thread ID (0 = target main PID)."),
        steps: z.number().int().min(1).max(100).default(1).describe("Number of instructions to step (default: 1, max: 100)."),
      },
    },
    async ({ pid, tid, steps }) => {
      try {
        return ok(await tools.threadStep({ pid, tid, steps }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  return server;
}