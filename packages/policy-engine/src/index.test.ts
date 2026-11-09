import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, issueIntentToken } from "@poi/crypto-identity";
import { evaluate, RevocationList, type JsonRpcRequest } from "./index.js";

const scope = { maxSpend: 500, currency: "USD", domains: ["airline.com"] };

function setup() {
  const { publicKey, privateKey } = generateKeyPair();
  const token = issueIntentToken({
    privateKey,
    agentId: "agent-1",
    issuer: "user-1",
    scope,
  });
  return { publicKey, token };
}

const call = (args: Record<string, unknown>): JsonRpcRequest => ({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: { name: "book_flight", arguments: args },
});

test("allows in-scope call", () => {
  const { publicKey, token } = setup();
  const d = evaluate({
    token,
    publicKey,
    request: call({ url: "https://airline.com/book", amount: 450 }),
  });
  assert.equal(d.allow, true);
});

test("blocks over-budget call", () => {
  const { publicKey, token } = setup();
  const d = evaluate({
    token,
    publicKey,
    request: call({ url: "https://airline.com/book", amount: 501 }),
  });
  assert.equal(d.allow, false);
});

test("blocks non-allowlisted domain (injection exfil attempt)", () => {
  const { publicKey, token } = setup();
  const d = evaluate({
    token,
    publicKey,
    request: call({ url: "https://evil.com/steal", amount: 1 }),
  });
  assert.equal(d.allow, false);
});

test("blocks lookalike domain", () => {
  const { publicKey, token } = setup();
  const d = evaluate({
    token,
    publicKey,
    request: call({ url: "https://airline.com.evil.com/x" }),
  });
  assert.equal(d.allow, false);
});

test("denies tool call with no determinable domain", () => {
  const { publicKey, token } = setup();
  const d = evaluate({ token, publicKey, request: call({ note: "hi" }) });
  assert.equal(d.allow, false);
});

test("denies negative or non-numeric amount", () => {
  const { publicKey, token } = setup();
  assert.equal(
    evaluate({ token, publicKey, request: call({ url: "https://airline.com", amount: -5 }) }).allow,
    false,
  );
  assert.equal(
    evaluate({ token, publicKey, request: call({ url: "https://airline.com", amount: "10" }) }).allow,
    false,
  );
});

test("passes non-tool methods", () => {
  const { publicKey, token } = setup();
  const d = evaluate({
    token,
    publicKey,
    request: { jsonrpc: "2.0", id: 2, method: "tools/list" },
  });
  assert.equal(d.allow, true);
});

test("revoked token is blocked", () => {
  const { publicKey, token } = setup();
  const revocations = new RevocationList();
  const request = call({ url: "https://airline.com/book", amount: 10 });
  const first = evaluate({ token, publicKey, request, revocations });
  assert.equal(first.allow, true);
  revocations.revoke(first.claims!.jti);
  assert.equal(evaluate({ token, publicKey, request, revocations }).allow, false);
});

test("invalid token is blocked", () => {
  const { publicKey } = setup();
  const d = evaluate({
    token: "a.b.c",
    publicKey,
    request: call({ url: "https://airline.com" }),
  });
  assert.equal(d.allow, false);
});

test("average decision time is under 2ms", () => {
  const { publicKey, token } = setup();
  const request = call({ url: "https://airline.com/book", amount: 100 });
  const n = 500;
  const t0 = performance.now();
  for (let i = 0; i < n; i++) evaluate({ token, publicKey, request });
  const avg = (performance.now() - t0) / n;
  console.log(`avg ${avg.toFixed(3)} ms per decision`);
  assert.ok(avg < 2);
});
