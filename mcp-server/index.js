#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import http from "node:http";
import { buildServer, VERSION } from "./server.js";

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const opt = (name, def) => {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : def;
};

const deviceOptions = {
  serial: opt("--serial", process.env.ANDROID_SERIAL || undefined),
  adbPath: opt("--adb", process.env.ADB_PATH || "adb"),
  cliPath: opt("--cli", process.env.HMKPM_CLI || "/data/local/tmp/hmkpm_cli"),
  useSu: opt("--no-su", null) === null,
  timeout: Number(opt("--timeout", "30000")),
  isLocal: has("--local") || process.platform === "android" || Boolean(process.env.LOCAL_ANDROID),
};

const port = Number(opt("--port", "0") || 0) || Number(process.env.PORT || 8799);
const host = opt("--host", process.env.HOST || "0.0.0.0");

async function runStdio() {
  const server = buildServer(deviceOptions);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[hmkpm-mcp] stdio mode ready");
}

async function runHttp() {
  const sseTransports = new Map();

  const httpServer = http.createServer(async (req, res) => {
    // Add CORS headers for web/browser clients and Operit
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-session-id");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

    // Health check endpoint (GET /health or GET /)
    if ((req.method === "GET" || req.method === "HEAD") && (url.pathname === "/health" || url.pathname === "/")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        status: "ok",
        service: "hmkpm-mcp",
        version: VERSION,
        endpoints: {
          sse: "/sse",
          messages: "/messages?sessionId=...",
          streamable: "/mcp",
          health: "/health",
        },
      }, null, 2));
      return;
    }

    // 1. SSE mode: GET /sse (Used by Operit and SSE-based clients)
    if (req.method === "GET" && url.pathname === "/sse") {
      try {
        const sseTransport = new SSEServerTransport("/messages", res);
        const server = buildServer(deviceOptions);
        sseTransports.set(sseTransport.sessionId, sseTransport);

        sseTransport.onclose = () => {
          // Only drop the session here.
          //
          // Calling server.close() from this hook re-enters transport.close(),
          // which invokes onclose again, recursing until the stack overflows.
          // The transport is already closing on its own, so nothing further is
          // required; the per-connection server becomes unreachable with it.
          sseTransports.delete(sseTransport.sessionId);
        };

        // server.connect() already starts the transport; calling start() again
        // throws "SSEServerTransport already started", which used to abort
        // every SSE connection and cascade into a stack overflow.
        await server.connect(sseTransport);
        return;
      } catch (err) {
        console.error("[hmkpm-mcp] SSE connection error:", err);
        if (!res.headersSent) {
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: String(err) }));
        }
        return;
      }
    }

    // 2. SSE messages endpoint: POST /messages?sessionId=...
    if (req.method === "POST" && url.pathname === "/messages") {
      const sessionId = url.searchParams.get("sessionId");
      const transport = sseTransports.get(sessionId);
      if (!transport) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: `Session "${sessionId}" not found` }));
        return;
      }
      try {
        await transport.handlePostMessage(req, res);
      } catch (err) {
        console.error("[hmkpm-mcp] SSE message handler error:", err);
        if (!res.headersSent) {
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: String(err) }));
        }
      }
      return;
    }

    // 3. Streamable HTTP mode: /mcp or POST /
    // Supports both modern Streamable HTTP MCP clients and standard JSON-RPC HTTP clients (like MilkCode).
    if (url.pathname === "/mcp" || (url.pathname === "/" && req.method === "POST")) {
      try {
        // Ensure Accept header includes both required media types so StreamableHTTPServerTransport
        // does not reject standard HTTP JSON clients with a 406 Not Acceptable error.
        const currentAccept = req.headers["accept"] || "";
        if (!currentAccept.includes("text/event-stream")) {
          req.headers["accept"] = currentAccept ? `${currentAccept}, text/event-stream` : "application/json, text/event-stream";
        }
        if (!req.headers["content-type"]) {
          req.headers["content-type"] = "application/json";
        }

        console.error(`[hmkpm-mcp] HTTP MCP request: ${req.method} ${url.pathname}`);
        const server = buildServer(deviceOptions);
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
          enableJsonResponse: true,
        });
        res.on("close", () => {
          transport.close();
          server.close().catch(() => {});
        });
        await server.connect(transport);
        await transport.handleRequest(req, res);
      } catch (err) {
        console.error("[hmkpm-mcp] Streamable HTTP error:", err);
        if (!res.headersSent) {
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32603, message: String(err) }, id: null }));
        }
      }
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "Not Found", path: url.pathname }));
  });

  await new Promise((resolve) => httpServer.listen(port, host, resolve));
  const addr = httpServer.address();
  console.error(`[hmkpm-mcp] HTTP/SSE server listening on http://${addr.address}:${addr.port}`);
  console.error(`  - Operit SSE Endpoint:       http://${addr.address}:${addr.port}/sse`);
  console.error(`  - Streamable HTTP Endpoint: http://${addr.address}:${addr.port}/mcp`);
  console.error(`  - Health check:             http://${addr.address}:${addr.port}/health`);
}

const isHttpMode = has("--http") || has("--sse");

(isHttpMode ? runHttp() : runStdio()).catch((err) => {
  console.error("[hmkpm-mcp] fatal:", err);
  process.exit(1);
});
