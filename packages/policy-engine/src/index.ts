import type { KeyObject } from "node:crypto";
import {
  verifyIntentToken,
  checkAction,
  type IntentClaims,
  type ToolAction,
} from "@poi/crypto-identity";

/** A JSON-RPC 2.0 request as sent over MCP. */
export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number;
  method: string;
  params?: {
    name?: string;
    arguments?: Record<string, unknown>;
    [k: string]: unknown;
  };
}

export interface Decision {
  allow: boolean;
  reason: string;
  claims?: IntentClaims;
  elapsedMs: number;
}

/** Tracks revoked token ids (backs the "Global Revoke" button). */
export class RevocationList {
  private revoked = new Set<string>();
  revoke(jti: string): void {
    this.revoked.add(jti);
  }
  isRevoked(jti: string): boolean {
    return this.revoked.has(jti);
  }
}

/**
 * Pull the domain and amount out of a tool call's arguments.
 * Looks at `url` (hostname is used) or `domain`, plus `amount`.
 * Returns null if no domain can be determined.
 */
export function extractAction(req: JsonRpcRequest): ToolAction | null {
  const args = req.params?.arguments;
  if (!args || typeof args !== "object") return null;

  let domain: string | undefined;
  if (typeof args.url === "string") {
    try {
      domain = new URL(args.url).hostname;
    } catch {
      return null;
    }
  } else if (typeof args.domain === "string") {
    domain = args.domain;
  }
  if (!domain) return null;

  let amount: number | undefined;
  if (args.amount !== undefined) {
    if (typeof args.amount !== "number" || !Number.isFinite(args.amount) || args.amount < 0) {
      return null; // malformed amount: deny rather than guess
    }
    amount = args.amount;
  }
  return { domain, amount };
}

export interface EvaluateInput {
  token: string;
  publicKey: KeyObject;
  request: JsonRpcRequest;
  revocations?: RevocationList;
  /** If given, enforces a cumulative budget per token on top of the per-call limit. */
  spend?: SpendTracker;
}

/** Decide whether one MCP request may proceed. Deny by default. */
export function evaluate(input: EvaluateInput): Decision {
  const start = performance.now();
  const done = (allow: boolean, reason: string, claims?: IntentClaims): Decision => ({
    allow,
    reason,
    claims,
    elapsedMs: performance.now() - start,
  });

  const v = verifyIntentToken(input.token, input.publicKey);
  if (!v.valid) return done(false, `invalid token: ${v.reason}`);

  if (input.revocations?.isRevoked(v.claims.jti)) {
    return done(false, "token revoked", v.claims);
  }

  // Only tool calls can cause side effects; other MCP methods
  // (initialize, tools/list, ping) pass through.
  if (input.request.method !== "tools/call") {
    return done(true, "non-tool method", v.claims);
  }

  const action = extractAction(input.request);
  if (!action) {
    return done(false, "cannot determine target domain or amount", v.claims);
  }

  const c = checkAction(v.claims, action);
  if (!c.allowed) return done(false, c.reason, v.claims);

  if (input.spend && action.amount) {
    const total = input.spend.spent(v.claims.jti) + action.amount;
    if (total > v.claims.scope.maxSpend) {
      return done(
        false,
        `cumulative spend ${total} would exceed budget ${v.claims.scope.maxSpend}`,
        v.claims,
      );
    }
    // Recorded when allowed, even if the downstream call later fails (conservative).
    input.spend.record(v.claims.jti, action.amount);
  }
  return done(true, "within scope", v.claims);
}

/**
 * Cumulative spend per token id. In memory: it resets if the process restarts
 * and is not shared between gateways (see docs/THREAT_MODEL.md).
 */
export class SpendTracker {
  private totals = new Map<string, number>();
  spent(jti: string): number {
    return this.totals.get(jti) ?? 0;
  }
  record(jti: string, amount: number): void {
    this.totals.set(jti, this.spent(jti) + amount);
  }
}
