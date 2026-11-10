import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { verifyIntentToken } from "@poi/crypto-identity";
import { createDashboardServer } from "./server.js";

const dir = mkdtempSync(join(tmpdir(), "poi-"));
const { server, publicKey } = createDashboardServer({ dataDir: dir, adminKey: "secret" });
await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
after(() => server.close());

const api = (path: string, init: RequestInit = {}, key = "secret") =>
  fetch(base + path, {
    ...init,
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
  });

const issue = (name = "agent-a") =>
  api("/api/agents", {
    method: "POST",
    body: JSON.stringify({ name, domains: ["Airline.com"], maxSpend: 500, ttlSeconds: 600 }),
  });

test("serves the page without auth, but API needs the key", async () => {
  assert.equal((await fetch(base + "/")).status, 200);
  assert.equal((await fetch(base + "/api/agents")).status, 401);
  assert.equal((await api("/api/agents", {}, "wrong")).status, 401);
});

test("issues a verifiable token scoped to lowercase domains", async () => {
  const r = await issue();
  assert.equal(r.status, 201);
  const body = await r.json();
  const v = verifyIntentToken(body.token, publicKey);
  assert.ok(v.valid);
  if (v.valid) {
    assert.deepEqual(v.claims.scope.domains, ["airline.com"]);
    assert.equal(v.claims.scope.maxSpend, 500);
  }
});

test("rejects bad input", async () => {
  const bad = (b: unknown) => api("/api/agents", { method: "POST", body: JSON.stringify(b) });
  assert.equal((await bad({ name: "x", domains: [], maxSpend: 1 })).status, 400);
  assert.equal((await bad({ name: "x", domains: ["a.com"], maxSpend: -1 })).status, 400);
  assert.equal((await bad({ name: "", domains: ["a.com"] })).status, 400);
  assert.equal((await bad({ name: "x", domains: ["a.com"], ttlSeconds: 0 })).status, 400);
});

test("single revoke shows up in revocations and the agent list", async () => {
  const { agent } = await (await issue("agent-b")).json();
  assert.equal((await api(`/api/agents/${agent.jti}/revoke`, { method: "POST" })).status, 200);
  const rev = await (await api("/api/revocations")).json();
  assert.ok(rev.revoked.includes(agent.jti));
  const list = await (await api("/api/agents")).json();
  assert.equal(list.agents.find((a: { jti: string }) => a.jti === agent.jti).status, "revoked");
  assert.equal((await api("/api/agents/nope/revoke", { method: "POST" })).status, 404);
});

test("global revoke revokes every agent", async () => {
  await issue("agent-c");
  await issue("agent-d");
  const out = await (await api("/api/revoke-all", { method: "POST" })).json();
  assert.ok(out.revoked >= 2);
  const list = await (await api("/api/agents")).json();
  assert.ok(list.agents.every((a: { status: string }) => a.status === "revoked"));
});

test("events can be posted and read back", async () => {
  await api("/api/events", {
    method: "POST",
    body: JSON.stringify({ type: "tool_call_blocked", reason: "test" }),
  });
  const ev = await (await api("/api/events")).json();
  assert.equal(ev.events[0].reason, "test");
});
