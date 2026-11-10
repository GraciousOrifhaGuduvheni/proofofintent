import { spawn, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import type { KeyObject } from "node:crypto";
import {
  evaluate,
  RevocationList,
  type JsonRpcRequest,
  type Decision,
  SpendTracker,
} from "@poi/policy-engine";

export interface SecurityEvent {
  ts: string;
  type: "tool_call_allowed" | "tool_call_blocked" | "parse_error";
  method?: string;
  tool?: string;
  id?: string | number | null;
  reason: string;
  agent?: string;
  jti?: string;
}

export interface GatewayOptions {
  command: string; // the real MCP server to launch
  args: string[];
  token: string;
  publicKey: KeyObject;
  input: Readable; // from the agent/client
  output: Writable; // back to the agent/client
  log?: (e: SecurityEvent) => void;
  revocations?: RevocationList;
  /** If this returns a reason, ALL tool calls are blocked (fail-closed). */
  blockAll?: () => string | null;
  /** Cumulative spend per token. A fresh tracker is used if omitted. */
  spend?: SpendTracker;
}

export const POLICY_ERROR_CODE = -32001;

export function runGateway(opts: GatewayOptions): {
  child: ChildProcess;
  done: Promise<number | null>;
} {
  const log = opts.log ?? (() => {});
  const spend = opts.spend ?? new SpendTracker();
  // stdout is the protocol channel, so the server's stderr goes straight through.
  const child = spawn(opts.command, opts.args, {
    stdio: ["pipe", "pipe", "inherit"],
  });

  // Server -> client: pass through untouched.
  child.stdout!.pipe(opts.output, { end: false });

  const reply = (obj: unknown) => opts.output.write(JSON.stringify(obj) + "\n");
  const forward = (obj: unknown) => child.stdin!.write(JSON.stringify(obj) + "\n");

  /** Returns true if the item may be forwarded. */
  function check(item: unknown): boolean {
    const isRequest =
      typeof item === "object" &&
      item !== null &&
      typeof (item as JsonRpcRequest).method === "string";
    if (!isRequest) return true; // client responses etc. pass through

    const req = item as JsonRpcRequest;
    const forced = req.method === "tools/call" ? opts.blockAll?.() : null;
    const d: Decision = forced
      ? { allow: false, reason: forced, elapsedMs: 0 }
      : evaluate({
          token: opts.token,
          publicKey: opts.publicKey,
          request: req,
          revocations: opts.revocations,
          spend,
        });

    if (req.method === "tools/call") {
      log({
        ts: new Date().toISOString(),
        type: d.allow ? "tool_call_allowed" : "tool_call_blocked",
        method: req.method,
        tool: req.params?.name,
        id: req.id ?? null,
        reason: d.reason,
        agent: d.claims?.sub,
        jti: d.claims?.jti,
      });
    }

    if (d.allow) return true;

    // Blocked. Notifications have no id, so there is nobody to answer.
    if (req.id !== undefined) {
      reply({
        jsonrpc: "2.0",
        id: req.id,
        error: {
          code: POLICY_ERROR_CODE,
          message: `POI policy violation: ${d.reason}`,
        },
      });
    }
    return false;
  }

  const rl = createInterface({ input: opts.input });
  rl.on("line", (line) => {
    if (!line.trim()) return;
    let msg: unknown;
    try {
      msg = JSON.parse(line);
    } catch {
      log({ ts: new Date().toISOString(), type: "parse_error", reason: "invalid JSON" });
      reply({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Parse error" },
      });
      return;
    }

    if (Array.isArray(msg)) {
      const allowed = msg.filter(check);
      if (allowed.length > 0) forward(allowed);
    } else if (check(msg)) {
      forward(msg);
    }
  });
  rl.on("close", () => child.stdin!.end());

  const done = new Promise<number | null>((resolve) => {
    child.on("close", (code) => resolve(code));
  });

  return { child, done };
}
