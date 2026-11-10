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
