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

export interface DashboardOptions {
  dataDir: string; // holds private.pem / public.pem
  adminKey: string; // bearer key for every /api route
}

class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

const sha = (s: string) => createHash("sha256").update(s).digest();

export function loadOrCreateKeys(dir: string): { publicKey: KeyObject; privateKey: KeyObject } {
  mkdirSync(dir, { recursive: true });
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

export function createDashboardServer(opts: DashboardOptions) {
  const { publicKey, privateKey } = loadOrCreateKeys(opts.dataDir);
  const store = new Store();
  const adminHash = sha(opts.adminKey);
  const indexUrl = new URL("../public/index.html", import.meta.url);

  const authorized = (req: IncomingMessage): boolean => {
    const h = req.headers.authorization ?? "";
    if (!h.startsWith("Bearer ")) return false;
    return timingSafeEqual(sha(h.slice(7)), adminHash);
  };

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";

    if (method === "GET" && path === "/") {
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "content-security-policy":
          "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
        "x-frame-options": "DENY",
        "cache-control": "no-store",
      });
      res.end(readFileSync(indexUrl));
      return;
    }

    if (!path.startsWith("/api/")) throw new HttpError(404, "not found");
    if (!authorized(req)) throw new HttpError(401, "unauthorized");

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
      // The token itself is returned once and never stored.
      return send(res, 201, { token, agent: record });
    }

    const m = path.match(/^\/api\/agents\/([\w-]+)\/revoke$/);
    if (method === "POST" && m) {
      if (!store.revoke(m[1])) throw new HttpError(404, "unknown agent");
      return send(res, 200, { revoked: m[1] });
    }

    if (method === "POST" && path === "/api/revoke-all") {
      return send(res, 200, { revoked: store.revokeAll() });
    }

    if (method === "GET" && path === "/api/revocations") {
      return send(res, 200, { revoked: store.revokedIds() });
    }

    if (method === "GET" && path === "/api/events") {
      return send(res, 200, { events: store.recentEvents(100) });
    }

    if (method === "POST" && path === "/api/events") {
      const body = await readJson(req);
      if (JSON.stringify(body).length > 2000) throw new HttpError(413, "event too large");
      store.addEvent(body);
      return send(res, 201, { ok: true });
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

  return { server, store, publicKey };
}
