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
