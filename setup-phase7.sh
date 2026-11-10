#!/usr/bin/env bash
# Run from the root of your proofofintent repo (after Phase 6).
set -e

mkdir -p apps/proxy-gateway/src

# ================================================================ SSE Gateway
cat > apps/proxy-gateway/src/sse-gateway.ts <<'EOF'
import http from "node:http";
import type { KeyObject } from "node:crypto";
import {
  evaluate,
  RevocationList,
  SpendTracker,
  type JsonRpcRequest,
} from "@poi/policy-engine";
import { POLICY_ERROR_CODE, type SecurityEvent } from "./gateway.js";

export interface SseGatewayOptions {
  upstreamUrl: string; // e.g. http://localhost:3000
  token: string;
  publicKey: KeyObject;
  port: number;
  log?: (e: SecurityEvent) => void;
  revocations?: RevocationList;
  spend?: SpendTracker;
  blockAll?: () => string | null;
}

/**
 * HTTP/SSE Proxy Gateway for remote MCP servers.
 * Intercepts MCP SSE connection and POST message endpoints, enforcing POI policy.
 */
export function runSseGateway(opts: SseGatewayOptions) {
  const log = opts.log ?? (() => {});
  const revocations = opts.revocations ?? new RevocationList();
  const spend = opts.spend ?? new SpendTracker();

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const blockedReason = opts.blockAll?.();

    if (req.method === "POST" && url.pathname.includes("message")) {
      let bodyText = "";
      for await (const chunk of req) {
        bodyText += chunk;
      }

      let msg: any;
      try {
        msg = JSON.parse(bodyText);
      } catch {
        log({ ts: new Date().toISOString(), type: "parse_error", reason: "invalid JSON" });
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }));
        return;
      }

      const checkMsg = (m: any) => {
        if (blockedReason) return { allow: false, reason: blockedReason };
        const isReq = typeof m === "object" && m !== null && typeof m.method === "string";
        if (!isReq) return { allow: true, reason: "non-request" };

        const reqObj = m as JsonRpcRequest;
        const d = evaluate({
          token: opts.token,
          publicKey: opts.publicKey,
          request: reqObj,
          revocations,
          spend,
        });

        if (reqObj.method === "tools/call") {
          log({
            ts: new Date().toISOString(),
            type: d.allow ? "tool_call_allowed" : "tool_call_blocked",
            method: reqObj.method,
            tool: reqObj.params?.name,
            id: reqObj.id ?? null,
            reason: d.reason,
            agent: d.claims?.sub,
            jti: d.claims?.jti,
          });
        }
        return d;
      };

      if (Array.isArray(msg)) {
        for (const m of msg) {
          const d = checkMsg(m);
          if (!d.allow && m.id !== undefined) {
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({
              jsonrpc: "2.0",
              id: m.id,
              error: { code: POLICY_ERROR_CODE, message: `POI policy violation: ${d.reason}` }
            }));
            return;
          }
        }
      } else {
        const d = checkMsg(msg);
        if (!d.allow) {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({
            jsonrpc: "2.0",
            id: msg.id ?? null,
            error: { code: POLICY_ERROR_CODE, message: `POI policy violation: ${d.reason}` }
          }));
          return;
        }
      }

      try {
        const upstreamRes = await fetch(`${opts.upstreamUrl}${url.pathname}${url.search}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: bodyText,
        });
        const respBody = await upstreamRes.text();
        res.writeHead(upstreamRes.status, { "content-type": upstreamRes.headers.get("content-type") || "application/json" });
        res.end(respBody);
      } catch {
        res.writeHead(502, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "Upstream server unreachable" }));
      }
      return;
    }

    try {
      const upstreamRes = await fetch(`${opts.upstreamUrl}${url.pathname}${url.search}`, {
        method: req.method,
        headers: req.headers as Record<string, string>,
      });

      res.writeHead(upstreamRes.status, Object.fromEntries(upstreamRes.headers.entries()));
      if (upstreamRes.body) {
        const reader = upstreamRes.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          res.write(value);
        }
      }
      res.end();
    } catch {
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "Upstream server unreachable" }));
    }
  });

  return {
    server,
    listen: () => new Promise<void>((resolve) => server.listen(opts.port, "127.0.0.1", resolve)),
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
