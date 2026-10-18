import { AdbDevice } from "./device.js";

const TYPES = new Set(["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64"]);

function asHex(v) {
  if (typeof v === "number") return "0x" + Math.trunc(v).toString(16);
  const s = String(v).trim();
  return s.startsWith("0x") || s.startsWith("0X") ? s : "0x" + s;
}

function assertType(t) {
  if (!TYPES.has(t)) {
    throw new Error(`Unsupported type "${t}". Use one of: ${[...TYPES].join(", ")}`);
  }
  return t;
}

// Offsets in a pointer chain can be negative; represent them at full width so
// the CLI's strtoll sees a plain signed value rather than a wrapped hex literal.
function formatOffset(o) {
  if (typeof o === "number") {
    return o < 0 ? String(Math.trunc(o)) : `0x${Math.trunc(o).toString(16)}`;
  }
  const s = String(o).trim();
  // "-0x40" is valid input from a caller; pass it through.
  if (/^-?0x[0-9a-f]+$/i.test(s) || /^-?\d+$/.test(s)) return s;
  throw new Error(`invalid offset "${o}" (use a number or hex string)`);
}

export class HmkpmTools {
  constructor(device) {
    this.device = device;
  }

  // Health check: probe the kernel module AND report how the CLI is reached, so
  // a broken deployment (wrong uid, missing su, stale binary) is diagnosable.
  async probe() {
    const res = await this.device.invoke(["probe"]);
    const info = {
      ...res,
      transport: this.device.isLocal ? "local" : "adb",
      cli: this.device.cliPath,
      useSu: this.device.useSu,
    };
    if (res && res.status === "error") {
      info.hint = this.device.isLocal
        ? "HMKPM needs root: the MCP server must run as uid 0 (su -c) on the tablet."
        : "Check adb devices / root (su) on the device.";
    }
    return info;
  }

  async listProcesses({ filter } = {}) {
    const list = await this.device.invoke(["processes"]);
    if (!Array.isArray(list)) return list;
    if (!filter) return list;
    const needle = filter.toLowerCase();
    return list.filter(
      (p) => p.name.toLowerCase().includes(needle) || String(p.pid) === filter,
    );
  }

  async maps(pid, filter) {
    const args = ["maps", String(pid)];
    if (filter) args.push(filter);
    return this.device.invoke(args);
  }

  async readMemory(pid, address, size) {
    const sz = Number(size);
    if (!Number.isInteger(sz) || sz <= 0 || sz > 16 * 1024 * 1024) {
      throw new Error("size must be an integer between 1 and 16777216");
    }
    const res = await this.device.invoke(["read", String(pid), asHex(address), String(sz)]);
    if (res && res.hex) {
      try {
        res.utf8 = Buffer.from(res.hex, "hex").toString("utf8");
      } catch {
        res.utf8 = null;
      }
    }
    return res;
  }

  async readValue(pid, address, type) {
    assertType(type);
    return this.device.invoke(["read_val", String(pid), asHex(address), type]);
  }

  async writeMemory(pid, address, hexData) {
    const hex = String(hexData).replace(/[^0-9a-fA-F]/g, "");
    if (!hex || hex.length % 2 !== 0) {
      throw new Error("hexData must be a non-empty even-length hex string");
    }
    return this.device.invoke(["write", String(pid), asHex(address), hex]);
  }

  async writeValue(pid, address, type, value) {
    assertType(type);
    return this.device.invoke([
      "write_val",
      String(pid),
      asHex(address),
      type,
      formatValueForCli(type, value),
    ]);
  }

  async scanKernel({ pid, value, type = "i32", align, perms = "rw-p" }) {
    assertType(type);
    const args = ["scan", String(pid), type, formatValueForCli(type, value)];
    if (align !== undefined && align !== null) {
      args.push(String(align));
      if (perms) args.push(perms);
    } else if (perms) {
      args.push(perms);
    }
    return this.device.invoke(args);
  }

  // Fast path: seed a scan session from an exact value (GameGuardian-style).
  async scanSeed({ pid, value, type = "i32", align, perms = "rw-p" }) {
    assertType(type);
    const args = ["scan_seed", String(pid), type, formatValueForCli(type, value)];
    if (align !== undefined && align !== null) {
      args.push(String(align));
      if (perms) args.push(perms);
    } else if (perms) {
      args.push(perms);
    }
    return this.device.invoke(args);
  }

  // First pass of an unknown-value / differential scan session. Snapshots every
  // aligned candidate slot and records address+value into a session file.
  async scanUnknown({ pid, type = "i32", align, perms = "rw-p" }) {
    assertType(type);
    const args = ["scan_unknown", String(pid), type];
    if (align !== undefined && align !== null) {
      args.push(String(align));
      if (perms) args.push(perms);
    } else if (perms) {
      args.push(perms);
    }
    return this.device.invoke(args);
  }

  // Subsequent pass: re-read candidates and keep only those matching the mode.
  async scanFilter({ pid, type = "i32", mode, value }) {
    assertType(type);
    const args = ["scan_filter", String(pid), type, String(mode)];
    if (value !== undefined && value !== null && value !== "") {
      args.push(String(value));
    }
    return this.device.invoke(args);
  }

  async scanResults({ pid, type = "i32" }) {
    assertType(type);
    return this.device.invoke(["scan_results", String(pid), type]);
  }

  async scanReset({ pid, type = "i32" }) {
    assertType(type);
    return this.device.invoke(["scan_reset", String(pid), type]);
  }

  // Batch-read many addresses in one CLI call instead of one process each.
  async readValues({ pid, addresses, type = "i32" }) {
    assertType(type);
    const list = (Array.isArray(addresses) ? addresses : [addresses]).map(asHex);
    if (list.length === 0) throw new Error("addresses must not be empty");
    if (list.length > 4096) throw new Error("at most 4096 addresses per call");
    return this.device.invoke(["read_values", String(pid), type, ...list]);
  }

  // Literal byte-string search across readable memory.
  async findString({ pid, pattern, perms = "rw-p", limit = 100 }) {
    if (!pattern) throw new Error("pattern must not be empty");
    return this.device.invoke([
      "find_string", String(pid), String(pattern), perms, String(limit),
    ]);
  }

  // Load base of a shared object, optionally plus an RVA.
  async moduleBase({ pid, module, rva }) {
    const args = ["module_base", String(pid), String(module)];
    if (rva !== undefined && rva !== null && rva !== "") args.push(asHex(rva));
    return this.device.invoke(args);
  }

  // Walk base+rva -> [off] -> [off] -> ... -> field. The final offset is added
  // without dereferencing, which is the address the caller wants to read/write.
  async pointerChain({ pid, base, rva, offsets = [], type = "i32" }) {
    assertType(type);
    if (!base) throw new Error("base must be a module name or an address");
    const list = (Array.isArray(offsets) ? offsets : [offsets])
      .filter((o) => o !== undefined && o !== null && o !== "");
    const args = [
      "pointer_chain", String(pid),
      typeof base === "number" ? asHex(base) : String(base),
      asHex(rva ?? 0), type,
      ...list.map(formatOffset),
    ];
    return this.device.invoke(args);
  }

  // Freeze one or more addresses at a fixed value. Runs a detached daemon on
  // the device that rewrites the slots continuously.
  async freeze({ pid, type = "i32", value, addresses, intervalMs = 50 }) {
    assertType(type);
    const args = ["freeze_add", String(pid), type, formatValueForCli(type, value), String(intervalMs)];
    for (const a of addresses ?? []) args.push(asHex(a));
    return this.device.invoke(args);
  }

  async unfreeze({ pid, addresses }) {
    const args = ["freeze_remove", String(pid)];
    for (const a of addresses ?? []) args.push(asHex(a));
    return this.device.invoke(args);
  }

  async freezeList({ pid }) {
    return this.device.invoke(["freeze_list", String(pid)]);
  }

  // Stream a memory region to a file on the device.
  async dump({ pid, target, size = "all", outPath, perms = "rw-p" }) {
    if (!outPath) throw new Error("outPath is required (a path on the device)");
    let what = String(target);
    if (/^[0-9]/.test(what) || /^0x/i.test(what)) what = asHex(what);
    else what = `module:${what}`;
    return this.device.invoke([
      "dump", String(pid), what, String(size), String(outPath), perms,
    ]);
  }

  // Scan a single module and report module-relative offsets, which survive a
  // process restart (absolute addresses do not).
  async scanRva({ pid, module, value, type = "i32", align }) {
    assertType(type);
    const args = ["scan_rva", String(pid), String(module), type, formatValueForCli(type, value)];
    if (align !== undefined && align !== null) args.push(String(align));
    return this.device.invoke(args);
  }

  // ARM64 instruction pattern search over executable memory.
  async findInstructions({ pid, pattern, where = "r-xp", limit = 100 }) {
    return this.device.invoke([
      "find_instructions", String(pid), String(pattern), String(where), String(limit),
    ]);
  }

  // Run a Lua script against the target. The source travels over stdin, so
  // multi-line code needs no temp file and no quoting.
  async runLua({ pid, script, timeoutS = 30 }) {
    if (typeof script !== "string" || !script.trim()) {
      throw new Error("script must be a non-empty Lua source string");
    }
    return this.device.invoke(
      ["run_lua", String(pid), "-", String(timeoutS)],
      { stdin: script },
    );
  }

  // Hardware breakpoint / watchpoint: trace read/write/exec hits with register snapshots & call stack.
  async traceWatchpoint({ pid, address, size = 4, type = "write", durationMs = 2000, maxHits = 10 }) {
    const sz = Number(size) || 4;
    const dur = Number(durationMs) || 2000;
    const hits = Number(maxHits) || 10;
    let accessType = "w";
    if (type === "read") accessType = "r";
    else if (type === "access" || type === "rw") accessType = "rw";
    else if (type === "exec" || type === "instruction" || type === "break") accessType = "exec";
    return this.device.invoke([
      "watch",
      String(pid),
      asHex(address),
      String(sz),
      accessType,
      String(dur),
      String(hits),
    ]);
  }

  // Suspend target thread or process and capture register state + call stack
  async threadSuspend({ pid, tid = 0 }) {
    return this.device.invoke(["thread_suspend", String(pid), String(tid || 0)]);
  }

  // Resume target thread or process
  async threadResume({ pid, tid = 0 }) {
    return this.device.invoke(["thread_resume", String(pid), String(tid || 0)]);
  }

  // Single-step target thread N instructions and capture instruction trace
  async threadStep({ pid, tid = 0, steps = 1 }) {
    return this.device.invoke(["step", String(pid), String(tid || 0), String(steps || 1)]);
  }

  // List all threads in target process (TID, thread name, status)
  async listThreads({ pid }) {
    return this.device.invoke(["threads", String(pid)]);
  }

  // Set register value in target thread (PC, SP, LR, FP, X0-X30, W0-W30, PSTATE)
  async setRegister({ pid, tid = 0, reg, value }) {
    return this.device.invoke(["set_reg", String(pid), String(tid || 0), String(reg), asHex(value)]);
  }
}

// The CLI parses numbers with strtol/strtoul base 0 (so "0x.." works) and
// floats with strtof/strtod. Normalize booleans/strings/numbers accordingly.
function formatValueForCli(type, value) {
  switch (type) {
    case "f32":
    case "f64":
      if (typeof value !== "number" && Number.isNaN(Number(value))) {
        throw new Error(`"${value}" is not a valid ${type}`);
      }
      return String(Number(value));
    default:
      if (typeof value === "string" && (value.startsWith("0x") || value.startsWith("0X") || value.startsWith("-0x"))) {
        return value;
      }
      if (!Number.isFinite(Number(value))) {
        throw new Error(`"${value}" is not a valid ${type}`);
      }
      return String(BigInt(Math.trunc(Number(value))));
  }
}

export function makeTools(options) {
  const device = new AdbDevice(options);
  return new HmkpmTools(device);
}
