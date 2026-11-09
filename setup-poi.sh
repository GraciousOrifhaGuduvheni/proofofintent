#!/usr/bin/env bash
# Run this from INSIDE your cloned proofofintent folder.
set -e

mkdir -p apps/proxy-gateway apps/user-dashboard packages/policy-engine packages/mcp-middleware packages/crypto-identity/src
touch apps/proxy-gateway/.gitkeep apps/user-dashboard/.gitkeep packages/policy-engine/.gitkeep packages/mcp-middleware/.gitkeep

cat > pnpm-workspace.yaml <<'EOF'
packages:
  - "apps/*"
  - "packages/*"
EOF

cat > package.json <<'EOF'
{
  "name": "proofofintent",
  "private": true,
  "version": "0.0.1",
  "scripts": {
    "test": "pnpm -r test"
  },
  "engines": { "node": ">=20" }
}
EOF

cat > .gitignore <<'EOF'
node_modules
dist
.env
*.pem
.DS_Store
EOF

cat > README.md <<'EOF'
# ProofOfIntent Protocol (POI)

Cryptographic identity and intent-bound authorization for autonomous AI agents.

## Status
Phase 1: `packages/crypto-identity` (signed, short-lived intent tokens).

## Dev
```
pnpm install
pnpm test
```
EOF

cat > packages/crypto-identity/package.json <<'EOF'
{
  "name": "@poi/crypto-identity",
  "version": "0.0.1",
  "type": "module",
  "main": "src/index.ts",
  "scripts": {
    "test": "tsx --test src/index.test.ts",
    "typecheck": "tsc --noEmit"
  },
  "devDependencies": {
    "@types/node": "^22.0.0",
    "tsx": "^4.19.0",
    "typescript": "^5.6.0"
  }
}
EOF

cat > packages/crypto-identity/tsconfig.json <<'EOF'
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "noEmit": true
  },
  "include": ["src"]
}
EOF

cat > packages/crypto-identity/src/index.ts <<'EOF'
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
EOF

cat > packages/crypto-identity/src/index.test.ts <<'EOF'
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeyPair,
  issueIntentToken,
  verifyIntentToken,
  checkAction,
} from "./index.js";

const scope = { maxSpend: 500, currency: "USD", domains: ["airline.com"] };

function setup(ttl = 600, now?: number) {
  const { publicKey, privateKey } = generateKeyPair();
  const token = issueIntentToken({
    privateKey,
    agentId: "agent-1",
    issuer: "user-device-1",
    scope,
    ttlSeconds: ttl,
    now,
  });
  return { publicKey, token };
}

test("valid token verifies", () => {
  const { publicKey, token } = setup();
  const r = verifyIntentToken(token, publicKey);
  assert.equal(r.valid, true);
});

test("tampered token is rejected", () => {
  const { publicKey, token } = setup();
  const [h, , s] = token.split(".");
  const evil = Buffer.from(
    JSON.stringify({ sub: "agent-1", exp: 9999999999, scope: { maxSpend: 999999, domains: ["evil.com"] } }),
  ).toString("base64url");
  const r = verifyIntentToken(`${h}.${evil}.${s}`, publicKey);
  assert.equal(r.valid, false);
});

test("wrong key is rejected", () => {
  const { token } = setup();
  const other = generateKeyPair().publicKey;
  assert.equal(verifyIntentToken(token, other).valid, false);
});

test("expired token is rejected", () => {
  const { publicKey, token } = setup(60, 1000);
  assert.equal(verifyIntentToken(token, publicKey, 2000).valid, false);
});

test("policy: $500 ok, $501 blocked, other domain blocked", () => {
  const { publicKey, token } = setup();
  const r = verifyIntentToken(token, publicKey);
  assert.ok(r.valid);
  if (!r.valid) return;
  assert.equal(checkAction(r.claims, { domain: "airline.com", amount: 500 }).allowed, true);
  assert.equal(checkAction(r.claims, { domain: "airline.com", amount: 501 }).allowed, false);
  assert.equal(checkAction(r.claims, { domain: "evil.com", amount: 1 }).allowed, false);
});
EOF

echo "Done. Next: pnpm install && pnpm test"
