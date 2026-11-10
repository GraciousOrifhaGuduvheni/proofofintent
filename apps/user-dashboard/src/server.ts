import http from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { readFileSync, mkdirSync, existsSync, writeFileSync, renameSync } from "node:fs";
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
  keyPassphrase?: string; // if set, private.pem is encrypted at rest
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

export function loadOrCreateKeys(
  dir: string,
  passphrase?: string,
): { publicKey: KeyObject; privateKey: KeyObject } {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const privPath = join(dir, "private.pem");
  const pubPath = join(dir, "public.pem");

  // Write to a temp file then rename, so a crash can never leave a half-written key.
  const writePrivate = (key: KeyObject) => {
    const pem = passphrase
      ? key.export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase })
      : key.export({ type: "pkcs8", format: "pem" });
    const tmp = privPath + ".tmp";
    writeFileSync(tmp, pem as string, { mode: 0o600 });
    renameSync(tmp, privPath);
  };

  let privateKey: KeyObject;
  let publicKey: KeyObject;
  if (existsSync(privPath)) {
    const pem = readFileSync(privPath, "utf8");
    const encrypted = pem.includes("ENCRYPTED");
    if (encrypted && !passphrase) {
      throw new Error("private key is encrypted: set POI_KEY_PASSPHRASE");
    }
    privateKey = createPrivateKey(encrypted ? { key: pem, passphrase } : pem);
    publicKey = createPublicKey(privateKey);
    if (passphrase && !encrypted) writePrivate(privateKey); // migrate a plaintext key
  } else {
    ({ publicKey, privateKey } = generateKeyPair());
    writePrivate(privateKey);
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
  const { publicKey, privateKey } = loadOrCreateKeys(opts.dataDir, opts.keyPassphrase);
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
