import { execFile } from "node:child_process";

const DEFAULT_CLI = "/data/local/tmp/hmkpm_cli";

function run(cmd, args, { timeout = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout, maxBuffer: 32 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(`[${cmd}] ${err.message}${stderr ? `\n${stderr}` : ""}`));
        return;
      }
      resolve(stdout);
    });
  });
}

// Parses the JSON output produced by hmkpm_cli.
function parseCliJson(stdout) {
  const line = stdout.trim().split(/\r?\n/).filter(Boolean).pop();
  if (!line) throw new Error("Empty output from hmkpm_cli");
  try {
    return JSON.parse(line);
  } catch {
    throw new Error(`Invalid JSON from hmkpm_cli: ${line.slice(0, 400)}`);
  }
}

export class AdbDevice {
  constructor({
    serial,
    adbPath = "adb",
    cliPath = DEFAULT_CLI,
    useSu = true,
    timeout = 120000,
    isLocal = process.platform === "android" || Boolean(process.env.LOCAL_ANDROID),
  } = {}) {
    this.serial = serial || null;
    this.adbPath = adbPath;
    this.cliPath = cliPath;
    this.useSu = useSu;
    this.timeout = timeout;
    this.isLocal = isLocal;
    // On-device (tablet) runs start from a root service whose PATH is the
    // Android system PATH; the node/su binaries live in Termux's prefix.
    // Pass an explicit binary where PATH cannot be relied on.
    this.suPath = process.env.HMKPM_SU || "su";
    this.nodePath = process.env.HMKPM_NODE || "node";
  }

  baseArgs() {
    const args = [];
    if (this.serial) args.push("-s", this.serial);
    return args;
  }

  // Invoke the on-device CLI, returning the parsed JSON object.
  async invoke(cliArgs) {
    const remote = [this.cliPath, ...cliArgs]
      .map((a) => shellQuote(String(a)))
      .join(" ");

    let stdout;
    if (this.isLocal) {
      // Running directly on Android device (e.g. Termux or native service)
      if (this.useSu) {
        stdout = await run(this.suPath, ["-c", remote], { timeout: this.timeout });
      } else {
        stdout = await run(this.cliPath, cliArgs.map(String), { timeout: this.timeout });
      }
    } else {
      // Running on PC / remote host via ADB
      const inner = this.useSu ? `su -c ${shellQuote(remote)}` : remote;
      stdout = await run(this.adbPath, [...this.baseArgs(), "shell", inner], {
        timeout: this.timeout,
      });
    }
    return parseCliJson(stdout);
  }

  async push(localPath, remotePath) {
    if (this.isLocal) return; // already local
    return run(this.adbPath, [...this.baseArgs(), "push", localPath, remotePath], {
      timeout: 120000,
    });
  }

  async devices() {
    if (this.isLocal) {
      return [{ serial: "local-android", state: "device" }];
    }
    const out = await run(this.adbPath, ["devices"], { timeout: 10000 });
    return out
      .split(/\r?\n/)
      .slice(1)
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [serial, state] = l.split(/\s+/);
        return { serial, state };
      });
  }
}

// POSIX single-quote escaping: safe for passing arbitrary args into `sh -c`.
export function shellQuote(s) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
