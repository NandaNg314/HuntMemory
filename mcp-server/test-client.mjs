import { spawn } from "node:child_process";

const child = spawn("node", ["index.js"], { cwd: import.meta.dirname, stdio: ["pipe", "pipe", "inherit"] });

// When no real device/root is reachable (e.g. CI without hardware), set
// HMKPM_TEST_OFFLINE=1 to only exercise protocol + tool registration.
const OFFLINE = process.env.HMKPM_TEST_OFFLINE === "1";

let buf = "";
const pending = new Map();
child.stdout.on("data", (d) => {
  buf += d.toString();
  let idx;
  while ((idx = buf.indexOf("\n")) !== -1) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id !== undefined && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  }
});

let id = 0;
function rpc(method, params, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const myId = ++id;
    pending.set(myId, resolve);
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: myId, method, params }) + "\n");
    setTimeout(() => { if (pending.has(myId)) { pending.delete(myId); reject(new Error("timeout " + method)); } }, timeoutMs);
  });
}
function notify(method, params) {
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
}

function callTool(name, args = {}, timeoutMs = 30000) {
  return rpc("tools/call", { name, arguments: args }, timeoutMs);
}

let failures = 0;
function check(label, cond, extra = "") {
  if (cond) {
    console.log(`  PASS: ${label}`);
  } else {
    failures++;
    console.log(`  FAIL: ${label} ${extra}`);
  }
}

const run = async () => {
  console.log("=== Initializing ===");
  const init = await rpc("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "test-client", version: "1.0" },
  });
  console.log("Initialize result:", init.result?.serverInfo);
  notify("notifications/initialized", {});

  console.log("\n=== Tools List ===");
  const list = await rpc("tools/list", {});
  const toolNames = (list.result?.tools || []).map((t) => t.name);
  console.log("Registered Tools (" + toolNames.length + "):", toolNames.join(", "));

  const expected = [
    "hmkpm_probe", "list_processes", "list_maps",
    "read_memory", "read_value", "write_memory", "write_value",
    "scan_kernel",
    "scan_unknown", "scan_filter", "scan_results", "scan_reset",
  ];
  for (const t of expected) {
    check(`tool registered: ${t}`, toolNames.includes(t));
  }

  if (OFFLINE) {
    console.log("\n[OFFLINE] Skipping device-dependent calls. Protocol + registration OK.");
    await finish();
    return;
  }

  console.log("\n=== 1. hmkpm_probe ===");
  const probe = await callTool("hmkpm_probe");
  const probeText = probe.result?.content?.[0]?.text || "";
  check("probe returns status ok", probeText.includes('"status": "ok"') || probeText.includes('"status":"ok"'));
  console.log("Probe:", probeText);

  console.log("\n=== 2. list_processes ===");
  const procs = await callTool("list_processes", { filter: "systemui" });
  const procData = JSON.parse(procs.result?.content?.[0]?.text || "[]");
  console.log("Found processes:", procData);
  const pid = procData[0]?.pid || 4041;

  console.log(`\n=== 3. list_maps for PID ${pid} ===`);
  const maps = await callTool("list_maps", { pid, filter: "dalvik-main" });
  const mapList = JSON.parse(maps.result?.content?.[0]?.text || "[]");
  console.log("First dalvik map:", mapList[0]);
  const testAddr = mapList[0]?.start || "0x2000000";

  console.log(`\n=== 4. read_memory at ${testAddr} (16 bytes) ===`);
  const readMem = await callTool("read_memory", { pid, address: testAddr, size: 16 });
  check("read_memory returns hex", readMem.result?.content?.[0]?.text?.includes('"hex"'));

  console.log(`\n=== 5. read_value at ${testAddr} (i32) ===`);
  const readVal = await callTool("read_value", { pid, address: testAddr, type: "i32" });
  check("read_value returns value", readVal.result?.content?.[0]?.text?.includes('"value"'));

  console.log(`\n=== 6. write_value at ${testAddr} ===`);
  const writeVal = await callTool("write_value", { pid, address: testAddr, type: "i32", value: 0 });
  check("write_value returns ok", writeVal.result?.content?.[0]?.text?.includes('"status"'));

  // scan_kernel over a 500MB dalvik space is very slow; gate it behind a flag
  // so the default smoke test stays fast.
  if (process.env.HMKPM_TEST_SCAN_KERNEL === "1") {
    console.log(`\n=== 7. scan_kernel for PID ${pid} (slow; opt-in) ===`);
    const scan = await callTool("scan_kernel", { pid, value: 0, type: "i32", align: 4, perms: "rw-p" }, 120000);
    const scanData = JSON.parse(scan.result?.content?.[0]?.text || "{}");
    console.log(`Scan kernel found ${scanData.matches_found} matches.`);
    check("scan_kernel returns matches array", Array.isArray(scanData.matches));
  } else {
    console.log("\n=== 7. scan_kernel SKIPPED (set HMKPM_TEST_SCAN_KERNEL=1 to enable) ===");
  }

  // --- Fuzzy / differential scan coverage ---------------------------------
  // These exercise the new session-based tools end-to-end against a real tab.
  console.log("\n=== 8. scan_reset (clean slate) ===");
  const reset0 = await callTool("scan_reset", { pid, type: "i32" });
  check("scan_reset ok", reset0.result?.content?.[0]?.text?.includes('"reset": true') ||
                          reset0.result?.content?.[0]?.text?.includes('"reset":true'));

  console.log("\n=== 9. scan_unknown (first pass, may take a while) ===");
  const unknown = await callTool("scan_unknown", { pid, type: "i32" }, 120000);
  const unknownText = unknown.result?.content?.[0]?.text || "";
  console.log("scan_unknown:", unknownText);
  const unknownData = JSON.parse(unknownText || "{}");
  check("scan_unknown returns a count", typeof unknownData.count === "number");

  console.log("\n=== 10. scan_filter changed ===");
  const filt = await callTool("scan_filter", { pid, type: "i32", mode: "changed" });
  const filtText = filt.result?.content?.[0]?.text || "";
  console.log("scan_filter:", filtText);
  check("scan_filter returns count", JSON.parse(filtText || "{}").count !== undefined);

  console.log("\n=== 11. scan_results ===");
  const results = await callTool("scan_results", { pid, type: "i32" });
  const resText = results.result?.content?.[0]?.text || "";
  check("scan_results returns matches[]", resText.includes('"matches"'));

  console.log("\n=== 12. scan_reset (cleanup) ===");
  const reset1 = await callTool("scan_reset", { pid, type: "i32" });
  check("scan_reset ok", reset1.result?.content?.[0]?.text?.includes("reset"));

  await finish();
};

async function finish() {
  console.log("\n=== SUMMARY ===");
  if (failures === 0) {
    console.log("ALL CHECKS PASSED");
  } else {
    console.log(`${failures} CHECK(S) FAILED`);
  }
  child.kill();
  process.exit(failures === 0 ? 0 : 1);
}

run().catch((e) => { console.error("TEST FAILED:", e); child.kill(); process.exit(1); });
