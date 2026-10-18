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
    "scan_seed", "scan_unknown", "scan_filter", "scan_results", "scan_reset",
    "read_values", "find_string", "module_base",
    "pointer_chain", "freeze_value", "unfreeze_value", "list_freezes",
    "dump_memory", "scan_rva", "find_instructions",
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
  check("list_maps returns dalvik maps", mapList.length > 0 && typeof mapList[0].start === "string");

  // Do NOT probe a mapping's base. dalvik-main is a 512 MB reservation whose
  // first pages are not resident, so hmkpm correctly answers EFAULT there.
  // Ask the kernel for an address it just proved readable instead: scan for a
  // common value and use the first hit (reads and writes are then guaranteed
  // to target a resident page). Falls back to +4 KiB into the first rw-p map.
  const kernelProbe = await callTool("scan_kernel", { pid, value: 1, type: "i32", align: 4, perms: "rw-p" }, 120000);
  const probeHits = JSON.parse(kernelProbe.result?.content?.[0]?.text || "{}").matches || [];
  let readAddr = probeHits[0];
  if (!readAddr) {
    const rw = await callTool("list_maps", { pid, filter: "rw-p" });
    const rwMaps = JSON.parse(rw.result?.content?.[0]?.text || "[]");
    readAddr = rwMaps[0] ? `0x${(BigInt(rwMaps[0].start) + 0x1000n).toString(16)}` : "0x10000";
  }
  console.log("readable address:", readAddr);

  console.log(`\n=== 4. read_memory at ${readAddr} (16 bytes) ===`);
  const readMem = await callTool("read_memory", { pid, address: readAddr, size: 16 });
  const readMemText = readMem.result?.content?.[0]?.text || "";
  console.log("read_memory:", readMemText.slice(0, 160));
  check("read_memory returns hex", readMemText.includes('"hex"'));

  console.log(`\n=== 5. read_value at ${readAddr} (i32) ===`);
  const readVal = await callTool("read_value", { pid, address: readAddr, type: "i32" });
  const readValText = readVal.result?.content?.[0]?.text || "";
  console.log("read_value:", readValText.slice(0, 160));
  check("read_value returns value", readValText.includes('"value"'));

  // Only touch processes we own or that are declared safe to write to. Writing
  // into systemui's dalvik head (the old smoke test did) crashes the tablet's UI.
  // Set HMKPM_TEST_WRITE_PID to a throwaway process to exercise write_value.
  // The throwaway has its own address space, so its slots must be found in it,
  // never borrowed from the process under test.
  const writePid = Number(process.env.HMKPM_TEST_WRITE_PID || 0);
  console.log(`\n=== 6. write_value ===`);
  let writeSlot = null;
  const findSlot = async (targetPid) => {
    // A truncated kernel scan can come back with all-zero addresses, so look for
    // the stamped 0x11111111 pattern the target fills its page with: a unique
    // value guarantees an untruncated, trustworthy hit list.
    const hits = JSON.parse(
      (await callTool("scan_kernel", {
        pid: targetPid, value: 0x11111111, type: "i32", perms: "rw-p",
      })).result?.content?.[0]?.text || "{}",
    ).matches || [];
    return hits.find((a) => BigInt(a) !== 0n) || null;
  };
  if (writePid) {
    writeSlot = await findSlot(writePid);
    check("throwaway process has a writable slot", Boolean(writeSlot));
    if (writeSlot) {
      const writeVal = await callTool("write_value", {
        pid: writePid, address: writeSlot, type: "i32", value: 0,
      });
      const wvText = writeVal.result?.content?.[0]?.text || "";
      check("write_value returns ok", wvText.includes('"status"') && !wvText.includes('"error"'));
      const back = JSON.parse(
        (await callTool("read_value", { pid: writePid, address: writeSlot, type: "i32" }))
          .result?.content?.[0]?.text || "{}",
      );
      check("write_value actually lands", Number(back.value) === 0);
    }
  } else {
    console.log("  SKIPPED (set HMKPM_TEST_WRITE_PID=<disposable pid> to enable; never write to system processes)");
  }

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

  console.log("\n=== 9a. scan_seed 1 (fast path, exact value) ===");
  const seed = await callTool("scan_seed", { pid, value: 1, type: "i32" }, 180000);
  const seedText = seed.result?.content?.[0]?.text || "";
  console.log("scan_seed:", seedText);
  const seedData = JSON.parse(seedText || "{}");
  check("scan_seed returns a count", typeof seedData.count === "number");
  const filtSeed = await callTool("scan_filter", { pid, type: "i32", mode: "eq", value: 1 }, 180000);
  const filtSeedText = filtSeed.result?.content?.[0]?.text || "";
  console.log("scan_filter(eq 1):", filtSeedText);
  check("scan_seed session narrows", JSON.parse(filtSeedText || "{}").count !== undefined);
  await callTool("scan_reset", { pid, type: "i32" });

  console.log("\n=== 9. scan_unknown (first pass, may take a while) ===");
  const unknown = await callTool("scan_unknown", { pid, type: "i32" }, 180000);
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

  // --- New lookup tools ----------------------------------------------------
  console.log("\n=== 13. read_values (batch) ===");
  const batch = await callTool("read_values", { pid, addresses: [readAddr], type: "i32" });
  const batchText = batch.result?.content?.[0]?.text || "";
  console.log("read_values:", batchText.slice(0, 200));
  const batchData = JSON.parse(batchText || "{}");
  check("read_values returns values[]", Array.isArray(batchData.values) && batchData.values.length === 1);
  check("read_values marks the slot readable", batchData.values?.[0]?.readable === true);

  console.log("\n=== 14. read_values with an unmapped address ===");
  const missing = await callTool("read_values", { pid, addresses: ["0x10"], type: "i32" });
  const missingData = JSON.parse(missing.result?.content?.[0]?.text || "{}");
  check("read_values flags unreadable slots", missingData.values?.[0]?.readable === false);

  console.log("\n=== 15. find_string ===");
  const strHit = await callTool("find_string", { pid, pattern: "libc.so", perms: "r--p", limit: 20 });
  const strText = strHit.result?.content?.[0]?.text || "";
  console.log("find_string:", strText.slice(0, 200));
  const strData = JSON.parse(strText || "{}");
  check("find_string returns matches[]", Array.isArray(strData.matches));
  check("find_string finds a known library name", (strData.count || 0) > 0);

  console.log("\n=== 16. module_base ===");
  const mod = await callTool("module_base", { pid, module: "libc.so" });
  const modText = mod.result?.content?.[0]?.text || "";
  console.log("module_base:", modText);
  const modData = JSON.parse(modText || "{}");
  check("module_base returns a base", typeof modData.base === "string" && modData.base.startsWith("0x"));
  const modRva = JSON.parse(
    (await callTool("module_base", { pid, module: "libc.so", rva: 0x1000 })).result?.content?.[0]?.text || "{}",
  );
  check("module_base adds the RVA", BigInt(modRva.address) === BigInt(modData.base) + 0x1000n);

  // --- Address resolution and code search ---------------------------------
  // Walk a real two-hop chain: a slot inside libc's data that holds a pointer,
  // then the field at a fixed offset inside the pointed-to object. Locating the
  // slot from a scan keeps the test valid across libc versions.
  console.log("\n=== 17. pointer_chain ===");
  const libBase = BigInt(modData.base);
  const libEnd = BigInt(modData.module_end || modData.base);

  // Find a slot that really holds a pointer into libc. Pointers live in the
  // writable data segment, so probe that first (the i32==0 candidates above are
  // mostly padding in other segments), then fall back to them.
  let chainHop = null;
  const f = (n) => `0x${BigInt(n).toString(16)}`;
  const rwMaps = JSON.parse(
    (await callTool("list_maps", { pid, filter: "libc.so" }))
      .result?.content?.[0]?.text || "[]",
  ).filter((m) => m.perms.startsWith("rw"));
  for (const seg of rwMaps) {
    const start = BigInt(seg.start), end = BigInt(seg.end);
    const addrs = [];
    for (let at = start; at + 8n <= end && addrs.length < 512; at += 8n) addrs.push(f(at));
    if (!addrs.length) continue;
    const res = JSON.parse(
      (await callTool("read_values", { pid, addresses: addrs, type: "u64" }))
        .result?.content?.[0]?.text || "{}",
    );
    for (const [i, item] of (res.values || []).entries()) {
      if (!item.readable) continue;
      const ptr = BigInt(item.value);
      if (ptr >= libBase && ptr < libEnd) {
        chainHop = BigInt(addrs[i]) - libBase;
        break;
      }
    }
    if (chainHop !== null) break;
  }
  check("found a slot holding a module pointer", chainHop !== null);

  if (chainHop) {
    const chain = await callTool("pointer_chain", {
      pid, base: "libc.so", rva: f(chainHop), offsets: [0, 8], type: "i32",
    });
    const chainText = chain.result?.content?.[0]?.text || "";
    console.log("pointer_chain:", chainText.slice(0, 260));
    const chainData = JSON.parse(chainText || "{}");
    check("pointer_chain reports every hop", Array.isArray(chainData.steps) && chainData.steps.length >= 3);
    check("pointer_chain resolves an address", typeof chainData.address === "string");
    // The entry hop must be the requested slot and the final hop must be the
    // dereferenced pointer plus the last offset.
    const entry = BigInt(chainData.steps?.[0]?.addr ?? 0);
    check("pointer_chain entry is base+rva", entry === libBase + BigInt(chainHop));
    if (chainData.steps?.[1]?.pointer) {
      check(
        "pointer_chain final address equals pointer + last offset",
        BigInt(chainData.steps[1].pointer) + 8n === BigInt(chainData.address),
      );
    }
  }

  console.log("\n=== 18. pointer_chain on an invalid base ===");
  const badChain = JSON.parse(
    (await callTool("pointer_chain", { pid, base: 0x10, rva: 0, offsets: [0, 8] }))
      .result?.content?.[0]?.text || "{}",
  );
  check("pointer_chain fails cleanly", badChain.resolved === false && badChain.failed_step === 1);

  console.log("\n=== 19. scan_rva ===");
  const rva = await callTool("scan_rva", { pid, module: "libc.so", value: 0, type: "i32" });
  const rvaText = rva.result?.content?.[0]?.text || "";
  console.log("scan_rva:", rvaText.slice(0, 200));
  const rvaData = JSON.parse(rvaText || "{}");
  check("scan_rva reports rvas[]", Array.isArray(rvaData.rvas) && rvaData.rvas.length > 0);

  console.log("\n=== 20. find_instructions ===");
  const insn = await callTool("find_instructions", {
    pid, pattern: "D65F03C0/FFFFFFFF", where: "libc.so", limit: 5,
  });
  const insnText = insn.result?.content?.[0]?.text || "";
  console.log("find_instructions:", insnText.slice(0, 200));
  const insnData = JSON.parse(insnText || "{}");
  check("find_instructions finds RET", (insnData.count || 0) > 0);
  check("find_instructions includes an RVA", typeof insnData.matches?.[0]?.rva === "string");

  // --- Dump ---------------------------------------------------------------
  console.log("\n=== 21. dump_memory ===");
  const dumpPath = `/data/local/tmp/hmkpm-test-dump-${pid}.bin`;
  const dump = await callTool("dump_memory", {
    pid, target: "libc.so", size: "all", outPath: dumpPath,
  });
  const dumpText = dump.result?.content?.[0]?.text || "";
  console.log("dump_memory:", dumpText);
  const dumpData = JSON.parse(dumpText || "{}");
  check("dump_memory writes bytes", (dumpData.bytes || 0) > 0);
  check("dump_memory writes a sidecar", typeof dumpData.map_file === "string");

  // --- Freeze -------------------------------------------------------------
  // Freezing rewrites a slot continuously, so only run it against a throwaway
  // process: HMKPM_TEST_WRITE_PID is started by the runner for exactly this.
  console.log("\n=== 22. freeze_value ===");
  if (!writePid) {
    console.log("  SKIP: set HMKPM_TEST_WRITE_PID to a throwaway process to test freezing");
  } else {
    // Find a writable slot inside the throwaway process.
    const slot = writeSlot || (await findSlot(writePid));
    check("throwaway process has a writable slot", Boolean(slot));

    if (slot) {
      const fzData = JSON.parse(
        (await callTool("freeze_value", {
          pid: writePid, type: "i32", value: 4242, addresses: [slot], intervalMs: 30,
        })).result?.content?.[0]?.text || "{}",
      );
      console.log("freeze_value:", JSON.stringify(fzData));
      check("freeze_value starts a daemon", fzData.running === true);

      // Overwrite behind the daemon's back, then confirm it wins the slot back.
      await callTool("write_value", { pid: writePid, address: slot, type: "i32", value: 9 });
      // On-device Node has no usable setTimeout/sleep shim; block briefly.
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);
      const held = JSON.parse(
        (await callTool("read_value", { pid: writePid, address: slot, type: "i32" }))
          .result?.content?.[0]?.text || "{}",
      );
      check("freeze_value holds the value after an overwrite", Number(held.value) === 4242);

      console.log("\n=== 23. list_freezes ===");
      const flist = JSON.parse(
        (await callTool("list_freezes", { pid: writePid })).result?.content?.[0]?.text || "{}",
      );
      check("list_freezes reports the slot", (flist.count || 0) >= 1 && flist.running === "true");

      console.log("\n=== 24. unfreeze_value ===");
      const unfz = JSON.parse(
        (await callTool("unfreeze_value", { pid: writePid })).result?.content?.[0]?.text || "{}",
      );
      check("unfreeze_value clears everything", unfz.cleared === true);
      const flist2 = JSON.parse(
        (await callTool("list_freezes", { pid: writePid })).result?.content?.[0]?.text || "{}",
      );
      check("daemon exits after unfreeze", flist2.running === "false" && flist2.count === 0);
    }
  }

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
