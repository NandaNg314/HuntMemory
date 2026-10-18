import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { makeTools } from "./tools.js";

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
    version: "1.0.0",
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

  return server;
}