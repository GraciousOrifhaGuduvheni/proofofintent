import {
  generateKeyPairSync,
  sign,
  verify,
  randomUUID,
  type KeyObject,
} from "node:crypto";

/** What an agent is allowed to do under one token. */
export interface IntentScope {
  maxSpend: number;
  currency: string;
  domains: string[]; // allowlisted hostnames, exact match
}

export interface IntentClaims {
  jti: string; // unique token id (single-use tracking / revocation)
  sub: string; // agent identity (bound to a parent user/tenant)
  iss: string; // issuer, e.g. the user's device or tenant
  iat: number; // issued-at, unix seconds
  exp: number; // expiry, unix seconds
  scope: IntentScope;
}

/** A tool call an agent wants to make. */
export interface ToolAction {
  domain: string;
  amount?: number;
}

export type VerifyResult =
  | { valid: true; claims: IntentClaims }
  | { valid: false; reason: string };

export type CheckResult = { allowed: true } | { allowed: false; reason: string };

const b64 = (v: Buffer | string): string => Buffer.from(v).toString("base64url");
const unb64 = (s: string): Buffer => Buffer.from(s, "base64url");

export function generateKeyPair(): { publicKey: KeyObject; privateKey: KeyObject } {
  return generateKeyPairSync("ed25519");
}

export interface IssueOptions {
  privateKey: KeyObject;
  agentId: string;
  issuer: string;
  scope: IntentScope;
  ttlSeconds?: number; // default 600 (10 minutes)
  now?: number; // unix seconds, for tests
}

/** Issue a short-lived, Ed25519-signed intent token (JWT format, alg EdDSA). */
export function issueIntentToken(opts: IssueOptions): string {
  const iat = opts.now ?? Math.floor(Date.now() / 1000);
  const claims: IntentClaims = {
    jti: randomUUID(),
    sub: opts.agentId,
    iss: opts.issuer,
    iat,
    exp: iat + (opts.ttlSeconds ?? 600),
    scope: opts.scope,
  };
  const header = b64(JSON.stringify({ alg: "EdDSA", typ: "POI+JWT" }));
  const payload = b64(JSON.stringify(claims));
  const signingInput = `${header}.${payload}`;
  const signature = sign(null, Buffer.from(signingInput), opts.privateKey);
  return `${signingInput}.${b64(signature)}`;
}

/** Verify signature and expiry. Never throws; returns a reason on failure. */
export function verifyIntentToken(
  token: string,
  publicKey: KeyObject,
  now: number = Math.floor(Date.now() / 1000),
): VerifyResult {
  const parts = token.split(".");
  if (parts.length !== 3) return { valid: false, reason: "malformed token" };
  const [h, p, s] = parts;

  try {
    const header = JSON.parse(unb64(h).toString("utf8"));
    if (header.alg !== "EdDSA") return { valid: false, reason: "unsupported alg" };

    const ok = verify(null, Buffer.from(`${h}.${p}`), publicKey, unb64(s));
    if (!ok) return { valid: false, reason: "bad signature" };

    const claims = JSON.parse(unb64(p).toString("utf8")) as IntentClaims;
    if (now >= claims.exp) return { valid: false, reason: "token expired" };
    return { valid: true, claims };
  } catch {
    return { valid: false, reason: "malformed token" };
  }
}

/** Check one tool call against a verified token's scope. Deny by default. */
export function checkAction(claims: IntentClaims, action: ToolAction): CheckResult {
  if (!claims.scope.domains.includes(action.domain)) {
    return { allowed: false, reason: `domain not allowlisted: ${action.domain}` };
  }
  if ((action.amount ?? 0) > claims.scope.maxSpend) {
    return {
      allowed: false,
      reason: `amount ${action.amount} exceeds max ${claims.scope.maxSpend}`,
    };
  }
  return { allowed: true };
}
