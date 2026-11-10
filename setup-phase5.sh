#!/usr/bin/env bash
# Run from the root of your proofofintent repo (after Phase 4).
set -e

# ======================================================== dashboard: store
cat > apps/user-dashboard/src/store.ts <<'EOF'
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

export interface AgentRecord {
  jti: string;
  name: string;
  domains: string[];
  maxSpend: number;
  issuedAt: number; // unix seconds
  expiresAt: number; // unix seconds
  revoked: boolean;
}

export type AgentStatus = "active" | "revoked" | "expired";
export type AgentView = AgentRecord & { status: AgentStatus };

/** Agent and revocation state, persisted to a JSON file with atomic writes. */
export class Store {
  private agents = new Map<string, AgentRecord>();

  constructor(private filePath?: string) {
    if (filePath && existsSync(filePath)) {
      // A corrupt state file throws here on purpose: refuse to start
      // rather than silently forget which tokens were revoked.
      const data = JSON.parse(readFileSync(filePath, "utf8")) as { agents: AgentRecord[] };
      for (const a of data.agents) this.agents.set(a.jti, a);
    }
  }

  private save(): void {
    if (!this.filePath) return;
    const tmp = this.filePath + ".tmp";
    writeFileSync(tmp, JSON.stringify({ agents: [...this.agents.values()] }), { mode: 0o600 });
    renameSync(tmp, this.filePath);
  }

  add(a: AgentRecord): void {
    this.agents.set(a.jti, a);
    this.save();
  }

  revoke(jti: string): boolean {
    const a = this.agents.get(jti);
    if (!a) return false;
    a.revoked = true;
    this.save();
    return true;
  }

  /** Revokes every agent token not already revoked. Returns how many changed. */
  revokeAll(): number {
    let n = 0;
    for (const a of this.agents.values()) {
      if (!a.revoked) {
        a.revoked = true;
        n++;
      }
    }
    if (n > 0) this.save();
    return n;
  }

  revokedIds(): string[] {
    return [...this.agents.values()].filter((a) => a.revoked).map((a) => a.jti);
  }

  list(now: number = Math.floor(Date.now() / 1000)): AgentView[] {
    return [...this.agents.values()]
      .map((a) => ({
        ...a,
        status: (a.revoked ? "revoked" : now >= a.expiresAt ? "expired" : "active") as AgentStatus,
      }))
      .sort((x, y) => y.issuedAt - x.issuedAt);
  }
}
EOF

# ============================================== dashboard: tamper-evident log
cat > apps/user-dashboard/src/audit.ts <<'EOF'
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { createHash, sign, verify, type KeyObject } from "node:crypto";

/**
 * Append-only audit log. Each line is hash-chained to the previous one and
 * signed with the server's Ed25519 key. Editing, deleting or reordering a
 * line in the middle breaks verification. Without the private key, an
 * attacker cannot forge a valid replacement.
 *
 * Known limit: removing the LAST lines is not detectable from the file alone.
 * Record the head hash somewhere else (see audit-verify) to catch that.
 */
export interface AuditEntry {
  seq: number;
  ts: string;
  event: Record<string, unknown>;
  prev: string;
  hash: string;
  sig: string;
}

export const GENESIS = "0".repeat(64);

function hashOf(seq: number, ts: string, event: Record<string, unknown>, prev: string): string {
  return createHash("sha256").update(JSON.stringify([seq, ts, event, prev])).digest("hex");
}

export type AuditVerify =
  | { ok: true; entries: number; head: string }
  | { ok: false; line: number; reason: string };

export function verifyAuditFile(path: string, publicKey: KeyObject): AuditVerify {
  if (!existsSync(path)) return { ok: true, entries: 0, head: GENESIS };
  const lines = readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.length > 0);

  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    const line = i + 1;
    try {
      const e = JSON.parse(lines[i]) as AuditEntry;
      if (e.seq !== line) return { ok: false, line, reason: "sequence gap or reorder" };
      if (e.prev !== prev) return { ok: false, line, reason: "broken hash chain" };
      if (hashOf(e.seq, e.ts, e.event, e.prev) !== e.hash) {
        return { ok: false, line, reason: "entry was modified" };
      }
      const ok = verify(null, Buffer.from(e.hash, "hex"), publicKey, Buffer.from(e.sig, "base64"));
      if (!ok) return { ok: false, line, reason: "bad signature" };
      prev = e.hash;
    } catch {
      return { ok: false, line, reason: "malformed entry" };
    }
  }
  return { ok: true, entries: lines.length, head: prev };
}

export class AuditLog {
  private count = 0;
  private tail: AuditEntry[] = [];
  private head = GENESIS;

  constructor(
    private path: string,
    private privateKey: KeyObject,
    publicKey: KeyObject,
  ) {
    // Refuse to start on a tampered log.
    const v = verifyAuditFile(path, publicKey);
    if (!v.ok) {
      throw new Error(`audit log failed verification at line ${v.line}: ${v.reason}`);
    }
    if (existsSync(path)) {
      const all = readFileSync(path, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l) as AuditEntry);
      this.count = all.length;
      this.tail = all.slice(-500);
    }
    this.head = v.head;
  }

  append(event: Record<string, unknown>): AuditEntry {
    const seq = this.count + 1;
    const ts = new Date().toISOString();
    const hash = hashOf(seq, ts, event, this.head);
    const sig = sign(null, Buffer.from(hash, "hex"), this.privateKey).toString("base64");
    const entry: AuditEntry = { seq, ts, event, prev: this.head, hash, sig };
    appendFileSync(this.path, JSON.stringify(entry) + "\n", { mode: 0o600 });
    this.count = seq;
    this.head = hash;
    this.tail.push(entry);
    if (this.tail.length > 500) this.tail.shift();
    return entry;
  }

  recent(n: number): Record<string, unknown>[] {
    return this.tail
      .slice(-n)
      .reverse()
      .map((e) => ({ ts: e.ts, ...e.event, seq: e.seq }));
  }
}
EOF

cat > apps/user-dashboard/src/audit-verify.ts <<'EOF'
import { readFileSync } from "node:fs";
import { createPublicKey } from "node:crypto";
import { join } from "node:path";
import { verifyAuditFile } from "./audit.js";

// Usage: tsx src/audit-verify.ts [dataDir]
// Needs only the PUBLIC key, so it can be run on a copy of the log elsewhere.
const dir = process.argv[2] ?? process.env.POI_DATA_DIR ?? ".poi-data";
const publicKey = createPublicKey(readFileSync(join(dir, "public.pem")));
const r = verifyAuditFile(join(dir, "audit.log"), publicKey);

if (r.ok) {
  console.log(`OK: ${r.entries} entries. Head hash: ${r.head}`);
  console.log("Store the head hash somewhere separate to detect deleted tail entries.");
} else {
  console.error(`TAMPERED at line ${r.line}: ${r.reason}`);
  process.exit(1);
}
EOF

# ================================================================ dashboard: server
cat > apps/user-dashboard/src/server.ts <<'EOF'
import http from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { readFileSync, mkdirSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";
import {
  generateKeyPair,
  issueIntentToken,
  verifyIntentToken,
} from "@poi/crypto-identity";
import { Store } from "./store.js";
import { AuditLog, verifyAuditFile } from "./audit.js";

export interface DashboardOptions {
  dataDir: string; // holds private.pem, public.pem, state.json, audit.log
  adminKey: string; // full control: issue, revoke, read everything
  gatewayKey: string; // gateways only: read revocations, post events
}

class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

type Role = "admin" | "gateway";
const sha = (s: string) => createHash("sha256").update(s).digest();

export function loadOrCreateKeys(dir: string): { publicKey: KeyObject; privateKey: KeyObject } {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const privPath = join(dir, "private.pem");
  const pubPath = join(dir, "public.pem");

  let privateKey: KeyObject;
  let publicKey: KeyObject;
  if (existsSync(privPath)) {
    privateKey = createPrivateKey(readFileSync(privPath));
    publicKey = createPublicKey(privateKey);
  } else {
    ({ publicKey, privateKey } = generateKeyPair());
    writeFileSync(privPath, privateKey.export({ type: "pkcs8", format: "pem" }) as string, {
      mode: 0o600,
    });
  }
  writeFileSync(pubPath, publicKey.export({ type: "spki", format: "pem" }) as string);
  return { publicKey, privateKey };
}

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(JSON.stringify(body));
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > 65536) throw new HttpError(413, "body too large");
    chunks.push(c as Buffer);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text) return {};
  try {
    const v = JSON.parse(text);
    if (typeof v !== "object" || v === null || Array.isArray(v)) {
      throw new Error("not an object");
    }
    return v as Record<string, unknown>;
  } catch {
    throw new HttpError(400, "invalid JSON object");
  }
}

const MAX_FAILS = 10;
const FAIL_WINDOW_MS = 60_000;

export function createDashboardServer(opts: DashboardOptions) {
  if (opts.adminKey === opts.gatewayKey) {
    throw new Error("adminKey and gatewayKey must be different");
  }
  const { publicKey, privateKey } = loadOrCreateKeys(opts.dataDir);
  const store = new Store(join(opts.dataDir, "state.json"));
  const auditPath = join(opts.dataDir, "audit.log");
  const audit = new AuditLog(auditPath, privateKey, publicKey);

  const adminHash = sha(opts.adminKey);
  const gatewayHash = sha(opts.gatewayKey);
  const indexUrl = new URL("../public/index.html", import.meta.url);

  // Failed-auth limiter, per remote address.
  const fails = new Map<string, { n: number; resetAt: number }>();
  const limited = (ip: string): boolean => {
    const f = fails.get(ip);
    return !!f && f.n >= MAX_FAILS && Date.now() < f.resetAt;
  };
  const recordFail = (ip: string): void => {
    const now = Date.now();
    if (fails.size > 1000) fails.clear();
    const f = fails.get(ip);
    if (!f || now >= f.resetAt) fails.set(ip, { n: 1, resetAt: now + FAIL_WINDOW_MS });
    else f.n++;
  };

  const roleOf = (req: IncomingMessage): Role | null => {
    const h = req.headers.authorization ?? "";
    if (!h.startsWith("Bearer ")) return null;
    const t = sha(h.slice(7));
    const isAdmin = timingSafeEqual(t, adminHash);
    const isGateway = timingSafeEqual(t, gatewayHash);
    return isAdmin ? "admin" : isGateway ? "gateway" : null;
  };

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Blocks DNS-rebinding: only accept requests addressed to localhost.
    const host = (req.headers.host ?? "").replace(/:\d+$/, "");
    if (host !== "127.0.0.1" && host !== "localhost") throw new HttpError(403, "forbidden host");

    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";

    if (method === "GET" && path === "/") {
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "content-security-policy":
          "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "cache-control": "no-store",
      });
      res.end(readFileSync(indexUrl));
      return;
    }

    if (!path.startsWith("/api/")) throw new HttpError(404, "not found");

    const ip = req.socket.remoteAddress ?? "?";
    if (limited(ip)) throw new HttpError(429, "too many failed attempts, try again later");
    const role = roleOf(req);
    if (!role) {
      recordFail(ip);
      throw new HttpError(401, "unauthorized");
    }
    const adminOnly = () => {
      if (role !== "admin") throw new HttpError(403, "forbidden");
    };

    // ---- routes both roles may use (gateways need exactly these two)
    if (method === "GET" && path === "/api/revocations") {
      return send(res, 200, { revoked: store.revokedIds() });
    }
    if (method === "POST" && path === "/api/events") {
      const body = await readJson(req);
      if (JSON.stringify(body).length > 2000) throw new HttpError(413, "event too large");
      audit.append({ ...body, source: role });
      return send(res, 201, { ok: true });
    }

    // ---- admin only
    adminOnly();

    if (method === "GET" && path === "/api/agents") {
      return send(res, 200, { agents: store.list() });
    }

    if (method === "POST" && path === "/api/agents") {
      const body = await readJson(req);
      const name = typeof body.name === "string" ? body.name.trim() : "";
      if (!name || name.length > 64) throw new HttpError(400, "name required (max 64 chars)");

      const domains = Array.isArray(body.domains)
        ? body.domains
            .filter((d): d is string => typeof d === "string")
            .map((d) => d.trim().toLowerCase())
            .filter(Boolean)
        : [];
      if (domains.length === 0 || domains.length > 20) {
        throw new HttpError(400, "1 to 20 domains required");
      }

      const maxSpend = Number(body.maxSpend ?? 0);
      if (!Number.isFinite(maxSpend) || maxSpend < 0) throw new HttpError(400, "invalid maxSpend");

      const ttl = Number(body.ttlSeconds ?? 600);
      if (!Number.isInteger(ttl) || ttl < 1 || ttl > 86400) {
        throw new HttpError(400, "ttlSeconds must be 1 to 86400");
      }

      const token = issueIntentToken({
        privateKey,
        agentId: name,
        issuer: "poi-dashboard",
        scope: { maxSpend, currency: "USD", domains },
        ttlSeconds: ttl,
      });
      const v = verifyIntentToken(token, publicKey);
      if (!v.valid) throw new Error("self-verification failed");

      const record = {
        jti: v.claims.jti,
        name,
        domains,
        maxSpend,
        issuedAt: v.claims.iat,
        expiresAt: v.claims.exp,
        revoked: false,
      };
      store.add(record);
      audit.append({
        type: "agent_issued",
        reason: `issued to ${name}`,
        jti: record.jti,
        domains,
        maxSpend,
        source: "admin",
      });
      // The token itself is returned once and never stored.
      return send(res, 201, { token, agent: record });
    }

    const m = path.match(/^\/api\/agents\/([\w-]+)\/revoke$/);
    if (method === "POST" && m) {
      if (!store.revoke(m[1])) throw new HttpError(404, "unknown agent");
      audit.append({ type: "agent_revoked", reason: `revoked ${m[1]}`, jti: m[1], source: "admin" });
      return send(res, 200, { revoked: m[1] });
    }

    if (method === "POST" && path === "/api/revoke-all") {
      const n = store.revokeAll();
      audit.append({ type: "revoke_all", reason: `revoked ${n} token(s)`, source: "admin" });
      return send(res, 200, { revoked: n });
    }

    if (method === "GET" && path === "/api/events") {
      return send(res, 200, { events: audit.recent(100) });
    }

    if (method === "GET" && path === "/api/audit/verify") {
      return send(res, 200, verifyAuditFile(auditPath, publicKey));
    }

    throw new HttpError(404, "not found");
  }

  const server = http.createServer((req, res) => {
    route(req, res).catch((e: unknown) => {
      if (e instanceof HttpError) return send(res, e.status, { error: e.message });
      console.error(e);
      send(res, 500, { error: "internal error" });
    });
  });

  return { server, store, audit, publicKey };
}
EOF

cat > apps/user-dashboard/src/main.ts <<'EOF'
import { randomBytes } from "node:crypto";
import { createDashboardServer } from "./server.js";

const port = Number(process.env.PORT ?? 8787);
const dataDir = process.env.POI_DATA_DIR ?? ".poi-data";

const adminGenerated = !process.env.POI_ADMIN_KEY;
const gatewayGenerated = !process.env.POI_GATEWAY_KEY;
const adminKey = process.env.POI_ADMIN_KEY ?? randomBytes(16).toString("hex");
const gatewayKey = process.env.POI_GATEWAY_KEY ?? randomBytes(16).toString("hex");

if (adminKey.length < 16 || gatewayKey.length < 16) {
  console.error("POI_ADMIN_KEY and POI_GATEWAY_KEY must each be at least 16 characters.");
  process.exit(1);
}

const { server } = createDashboardServer({ dataDir, adminKey, gatewayKey });

// Bound to localhost only on purpose.
server.listen(port, "127.0.0.1", () => {
  console.log(`POI dashboard: http://127.0.0.1:${port}`);
  console.log(`Public key for gateways: ${dataDir}/public.pem`);
  if (adminGenerated) console.log(`Admin key (new each start): ${adminKey}`);
  if (gatewayGenerated) console.log(`Gateway key (new each start): ${gatewayKey}`);
  if (adminGenerated || gatewayGenerated) {
    console.log("Set POI_ADMIN_KEY / POI_GATEWAY_KEY to keep them stable.");
  }
});
EOF

cat > apps/user-dashboard/package.json <<'EOF'
{
  "name": "@poi/user-dashboard",
  "version": "0.0.1",
  "type": "module",
  "scripts": {
    "start": "tsx src/main.ts",
    "test": "tsx --test src/server.test.ts",
    "audit:verify": "tsx src/audit-verify.ts",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "@poi/crypto-identity": "workspace:*"
  },
  "devDependencies": {
    "@types/node": "^22.0.0",
    "tsx": "^4.19.0",
    "typescript": "^5.6.0"
  }
}
EOF

# ================================================================ dashboard: tests
cat > apps/user-dashboard/src/server.test.ts <<'EOF'
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { verifyIntentToken } from "@poi/crypto-identity";
import { createDashboardServer } from "./server.js";
import { verifyAuditFile } from "./audit.js";

const ADMIN = "admin-key-0123456789";
const GATEWAY = "gateway-key-0123456789";
const stops: Array<() => Promise<void>> = [];
after(async () => {
  for (const s of stops) await s();
});

async function start(dir: string = mkdtempSync(join(tmpdir(), "poi-"))) {
  const s = createDashboardServer({ dataDir: dir, adminKey: ADMIN, gatewayKey: GATEWAY });
  await new Promise<void>((r) => s.server.listen(0, "127.0.0.1", r));
  const port = (s.server.address() as AddressInfo).port;
  const base = `http://127.0.0.1:${port}`;
  const stop = async () => {
    s.server.closeAllConnections();
    await new Promise<void>((r) => s.server.close(() => r()));
  };
  stops.push(stop);
  const api = (path: string, init: RequestInit = {}, key = ADMIN) =>
    fetch(base + path, {
      ...init,
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    });
  const issue = (name = "agent-a") =>
    api("/api/agents", {
      method: "POST",
      body: JSON.stringify({ name, domains: ["Airline.com"], maxSpend: 500, ttlSeconds: 600 }),
    });
  return { ...s, dir, port, base, api, issue, stop };
}

test("page is public; API needs a key; gateway key is limited", async () => {
  const s = await start();
  assert.equal((await fetch(s.base + "/")).status, 200);
  assert.equal((await fetch(s.base + "/api/agents")).status, 401);
  assert.equal((await s.api("/api/agents", {}, "wrong")).status, 401);

  // The gateway key can do only its two jobs.
  assert.equal((await s.api("/api/revocations", {}, GATEWAY)).status, 200);
  assert.equal(
    (await s.api("/api/events", { method: "POST", body: JSON.stringify({ type: "x" }) }, GATEWAY))
      .status,
    201,
  );
  assert.equal((await s.api("/api/agents", {}, GATEWAY)).status, 403);
  assert.equal((await s.api("/api/revoke-all", { method: "POST" }, GATEWAY)).status, 403);
  assert.equal((await s.api("/api/events", {}, GATEWAY)).status, 403);
  assert.equal(
    (await s.api("/api/agents", { method: "POST", body: JSON.stringify({ name: "x", domains: ["a.com"] }) }, GATEWAY)).status,
    403,
  );
});

test("issues a verifiable token scoped to lowercase domains", async () => {
  const s = await start();
  const r = await s.issue();
  assert.equal(r.status, 201);
  const body = await r.json();
  const v = verifyIntentToken(body.token, s.publicKey);
  assert.ok(v.valid);
  if (v.valid) {
    assert.deepEqual(v.claims.scope.domains, ["airline.com"]);
    assert.equal(v.claims.scope.maxSpend, 500);
  }
});

test("rejects bad input", async () => {
  const s = await start();
  const bad = (b: unknown) => s.api("/api/agents", { method: "POST", body: JSON.stringify(b) });
  assert.equal((await bad({ name: "x", domains: [], maxSpend: 1 })).status, 400);
  assert.equal((await bad({ name: "x", domains: ["a.com"], maxSpend: -1 })).status, 400);
  assert.equal((await bad({ name: "", domains: ["a.com"] })).status, 400);
  assert.equal((await bad({ name: "x", domains: ["a.com"], ttlSeconds: 0 })).status, 400);
});

test("single revoke and global revoke", async () => {
  const s = await start();
  const { agent } = await (await s.issue("agent-b")).json();
  assert.equal((await s.api(`/api/agents/${agent.jti}/revoke`, { method: "POST" })).status, 200);
  const rev = await (await s.api("/api/revocations", {}, GATEWAY)).json();
  assert.ok(rev.revoked.includes(agent.jti));
  assert.equal((await s.api("/api/agents/nope/revoke", { method: "POST" })).status, 404);

  await s.issue("agent-c");
  await s.issue("agent-d");
  const out = await (await s.api("/api/revoke-all", { method: "POST" })).json();
  assert.equal(out.revoked, 2);
  const list = await (await s.api("/api/agents")).json();
  assert.ok(list.agents.every((a: { status: string }) => a.status === "revoked"));
});

test("state survives a restart (revocations are not forgotten)", async () => {
  const a = await start();
  const { agent } = await (await a.issue("persist")).json();
  await a.api(`/api/agents/${agent.jti}/revoke`, { method: "POST" });
  await a.stop();

  const b = await start(a.dir);
  const list = await (await b.api("/api/agents")).json();
  assert.equal(list.agents[0].status, "revoked");
  const rev = await (await b.api("/api/revocations", {}, GATEWAY)).json();
  assert.ok(rev.revoked.includes(agent.jti));
  const v = await (await b.api("/api/audit/verify")).json();
  assert.equal(v.ok, true);
  assert.equal(v.entries, 2); // issued + revoked
});

test("audit log records actions and detects edits and deletions", async () => {
  const s = await start();
  await s.issue("a1");
  await s.issue("a2");
  await s.api("/api/events", {
    method: "POST",
    body: JSON.stringify({ type: "tool_call_blocked", reason: "test" }),
  }, GATEWAY);

  const ev = await (await s.api("/api/events")).json();
  assert.equal(ev.events[0].reason, "test");
  assert.equal(ev.events[0].source, "gateway");

  const file = join(s.dir, "audit.log");
  assert.equal(verifyAuditFile(file, s.publicKey).ok, true);

  const orig = readFileSync(file, "utf8").split("\n").filter(Boolean);

  // Edit an entry
  const edited = JSON.parse(orig[0]);
  edited.event.reason = "nothing to see here";
  writeFileSync(file, [JSON.stringify(edited), ...orig.slice(1)].join("\n") + "\n");
  const r1 = verifyAuditFile(file, s.publicKey);
  assert.equal(r1.ok, false);
  if (!r1.ok) assert.equal(r1.line, 1);

  // Delete the first entry
  writeFileSync(file, orig.slice(1).join("\n") + "\n");
  assert.equal(verifyAuditFile(file, s.publicKey).ok, false);

  // Reorder entries
  writeFileSync(file, [orig[1], orig[0], ...orig.slice(2)].join("\n") + "\n");
  assert.equal(verifyAuditFile(file, s.publicKey).ok, false);
});

test("server refuses to start on a tampered audit log", async () => {
  const s = await start();
  await s.issue("t1");
  await s.stop();
  const file = join(s.dir, "audit.log");
  const e = JSON.parse(readFileSync(file, "utf8").split("\n")[0]);
  e.event.maxSpend = 999999;
  writeFileSync(file, JSON.stringify(e) + "\n");
  assert.throws(
    () => createDashboardServer({ dataDir: s.dir, adminKey: ADMIN, gatewayKey: GATEWAY }),
    /audit log failed verification/,
  );
});

test("locks out repeated wrong keys", async () => {
  const s = await start();
  for (let i = 0; i < 10; i++) {
    assert.equal((await s.api("/api/agents", {}, "wrong-key-" + i)).status, 401);
  }
  assert.equal((await s.api("/api/agents")).status, 429); // even the right key
});

test("rejects requests with a foreign Host header", async () => {
  const s = await start();
  const status = await new Promise<number>((resolve, reject) => {
    const r = http.request(
      { host: "127.0.0.1", port: s.port, path: "/", headers: { host: "evil.example.com" } },
      (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      },
    );
    r.on("error", reject);
    r.end();
  });
  assert.equal(status, 403);
});
EOF

# ===================================================== gateway: fail-closed + gateway key
python3 - <<'PY'
p = "apps/proxy-gateway/src/gateway.ts"
s = open(p).read()
if "blockAll" not in s:
    reps = [
        ("  type JsonRpcRequest,\n} from \"@poi/policy-engine\";",
         "  type JsonRpcRequest,\n  type Decision,\n} from \"@poi/policy-engine\";"),
        ("  revocations?: RevocationList;\n}",
         "  revocations?: RevocationList;\n  /** If this returns a reason, ALL tool calls are blocked (fail-closed). */\n  blockAll?: () => string | null;\n}"),
        ("    const d = evaluate({\n      token: opts.token,\n      publicKey: opts.publicKey,\n      request: req,\n      revocations: opts.revocations,\n    });",
         "    const forced = req.method === \"tools/call\" ? opts.blockAll?.() : null;\n    const d: Decision = forced\n      ? { allow: false, reason: forced, elapsedMs: 0 }\n      : evaluate({\n          token: opts.token,\n          publicKey: opts.publicKey,\n          request: req,\n          revocations: opts.revocations,\n        });"),
    ]
    for old, new in reps:
        assert old in s, "gateway.ts does not match Phase 3; patch not applied: " + old[:40]
        s = s.replace(old, new)
    open(p, "w").write(s)
PY

cat > apps/proxy-gateway/src/control-sync.ts <<'EOF'
import type { RevocationList } from "@poi/policy-engine";
import type { SecurityEvent } from "./gateway.js";

export interface ControlSyncOptions {
  /** If set, block all tool calls when the dashboard has been unreachable this long. */
  failClosedAfterMs?: number;
}

/**
 * Polls the dashboard for revoked token ids every 2 seconds and posts
 * security events to it. Use the GATEWAY key here, never the admin key.
 */
export async function startControlSync(
  baseUrl: string,
  key: string,
  revocations: RevocationList,
  options: ControlSyncOptions = {},
) {
  const headers = { authorization: `Bearer ${key}`, "content-type": "application/json" };
  let lastOk = 0;

  const poll = async () => {
    try {
      const r = await fetch(`${baseUrl}/api/revocations`, {
        headers,
        signal: AbortSignal.timeout(3000),
      });
      if (!r.ok) return;
      const body = (await r.json()) as { revoked?: string[] };
      for (const jti of body.revoked ?? []) revocations.revoke(jti);
      lastOk = Date.now();
    } catch {
      /* unreachable: lastOk stays old */
    }
  };

  await poll(); // load existing revocations before serving any traffic
  const timer = setInterval(poll, 2000);
  timer.unref();

  const log = (e: SecurityEvent) => {
    process.stderr.write(JSON.stringify(e) + "\n");
    fetch(`${baseUrl}/api/events`, {
      method: "POST",
      headers,
      body: JSON.stringify(e),
      signal: AbortSignal.timeout(3000),
    }).catch(() => {});
  };

  const blockAll = (): string | null =>
    options.failClosedAfterMs !== undefined && Date.now() - lastOk > options.failClosedAfterMs
      ? "control plane unreachable (fail-closed)"
      : null;

  return { log, blockAll, stop: () => clearInterval(timer) };
}
EOF

cat > apps/proxy-gateway/src/cli.ts <<'EOF'
import { readFileSync } from "node:fs";
import { createPublicKey } from "node:crypto";
import { RevocationList } from "@poi/policy-engine";
import { runGateway, type SecurityEvent } from "./gateway.js";
import { startControlSync } from "./control-sync.js";

// Usage:
//   POI_TOKEN=... POI_PUBLIC_KEY_FILE=path/to/public.pem \
//   [POI_CONTROL_URL=http://127.0.0.1:8787 POI_GATEWAY_KEY=<gateway key> [POI_FAIL_CLOSED=1]] \
//   tsx src/cli.ts <server command> [args...]
const [command, ...args] = process.argv.slice(2);
const token = process.env.POI_TOKEN;
const keyFile = process.env.POI_PUBLIC_KEY_FILE;
const controlUrl = process.env.POI_CONTROL_URL;
const gatewayKey = process.env.POI_GATEWAY_KEY;
const failClosed = process.env.POI_FAIL_CLOSED === "1";

if (!command || !token || !keyFile) {
  process.stderr.write(
    "Usage: POI_TOKEN=... POI_PUBLIC_KEY_FILE=public.pem [POI_CONTROL_URL=... POI_GATEWAY_KEY=... [POI_FAIL_CLOSED=1]] tsx src/cli.ts <server command> [args...]\n",
  );
  process.exit(2);
}

const publicKey = createPublicKey(readFileSync(keyFile));
const revocations = new RevocationList();

let log = (e: SecurityEvent) => process.stderr.write(JSON.stringify(e) + "\n");
let blockAll: (() => string | null) | undefined;

if (controlUrl && gatewayKey) {
  const sync = await startControlSync(controlUrl, gatewayKey, revocations, {
    failClosedAfterMs: failClosed ? 10_000 : undefined,
  });
  log = sync.log;
  blockAll = sync.blockAll;
} else if (failClosed) {
  process.stderr.write("POI_FAIL_CLOSED=1 needs POI_CONTROL_URL and POI_GATEWAY_KEY.\n");
  process.exit(2);
}

const { done } = runGateway({
  command,
  args,
  token,
  publicKey,
  input: process.stdin,
  output: process.stdout,
  log,
  revocations,
  blockAll,
});

done.then((code) => process.exit(code ?? 0));
EOF

if ! grep -q "fail-closed hook" apps/proxy-gateway/src/gateway.test.ts; then
cat >> apps/proxy-gateway/src/gateway.test.ts <<'EOF'

test("fail-closed hook blocks tool calls but not protocol messages", async () => {
  const { publicKey, privateKey } = generateKeyPair();
  const token = issueIntentToken({
    privateKey,
    agentId: "agent-1",
    issuer: "user-1",
    scope: { maxSpend: 500, currency: "USD", domains: ["airline.com"] },
  });
  const input = new PassThrough();
  const output = new PassThrough();
  const { done } = runGateway({
    command: process.execPath,
    args: [fixture],
    token,
    publicKey,
    input,
    output,
    blockAll: () => "control plane unreachable",
  });
  const lines = createInterface({ input: output })[Symbol.asyncIterator]();
  const send = (o: unknown) => input.write(JSON.stringify(o) + "\n");
  const next = async () => JSON.parse((await lines.next()).value as string);

  send({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "book_flight", arguments: { url: "https://airline.com/book", amount: 1 } },
  });
  let r = await next();
  assert.equal(r.error.code, POLICY_ERROR_CODE);
  assert.match(r.error.message, /unreachable/);

  send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  r = await next();
  assert.equal(r.result.count, 1); // the blocked call never reached the server

  input.end();
  await done;
});
EOF
fi

# ============================================================ licensing + policy files
if [ ! -f LICENSE ]; then
  curl -fsSL https://www.gnu.org/licenses/agpl-3.0.txt -o LICENSE \
    || echo "WARNING: could not download the AGPL text. Get it from https://www.gnu.org/licenses/agpl-3.0.txt and save it as LICENSE."
fi

cat > COMMERCIAL.md <<'EOF'
# Commercial licensing

ProofOfIntent is dual-licensed.

**Open source:** AGPL-3.0-or-later (see `LICENSE`). You may use, study and modify it
freely. If you modify it, or offer it to others as a network service, you must
publish your complete source code under the same license.

**Commercial:** if you want to use ProofOfIntent in a closed-source product or
service, embed it without the AGPL obligations, or discuss acquisition or
investment, contact: YOUR_EMAIL@example.com

Copyright (c) 2026 YOUR NAME. All rights reserved except as granted by the license.
EOF

cat > CONTRIBUTING.md <<'EOF'
# Contributing

Thanks for your interest. Because ProofOfIntent is dual-licensed, the maintainer
must hold the right to relicense every contribution.

By submitting a contribution (pull request, patch or otherwise) you confirm that
you wrote it, or have the right to submit it, and you grant YOUR NAME a perpetual,
worldwide, irrevocable, royalty-free license to use, modify, sublicense and
relicense it under any terms, including commercial licenses.

If you do not agree, please do not submit code. Bug reports and ideas are welcome
without this requirement.
EOF

cat > SECURITY.md <<'EOF'
# Security policy

Please report vulnerabilities privately through GitHub's "Report a vulnerability"
button (Security tab) or by email to YOUR_EMAIL@example.com. Do not open public
issues for security problems. Expect an acknowledgement within a few days.
EOF

if ! grep -q "^## License" README.md; then
cat >> README.md <<'EOF'

## License

Dual-licensed: AGPL-3.0-or-later for open-source use, and a commercial license for
closed-source use. See `LICENSE` and `COMMERCIAL.md`.
EOF
fi

python3 - <<'PY'
import json, glob
for p in ["package.json"] + glob.glob("apps/*/package.json") + glob.glob("packages/*/package.json"):
    d = json.load(open(p))
    d["license"] = "AGPL-3.0-or-later"
    open(p, "w").write(json.dumps(d, indent=2) + "\n")
PY

# ============================================================ secret check
echo
echo "Checking that no secrets are tracked by git..."
if git ls-files | grep -E '(\.pem$|\.poi-data|\.env)'; then
  echo "WARNING: the files above are tracked. Remove them with: git rm --cached <file>"
else
  echo "OK: no keys or data files are tracked."
fi

echo
echo "Done. Next: pnpm install && pnpm test"
echo "Then replace YOUR_EMAIL@example.com and YOUR NAME in COMMERCIAL.md, CONTRIBUTING.md and SECURITY.md."
