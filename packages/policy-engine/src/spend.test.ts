import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, issueIntentToken } from "@poi/crypto-identity";
import { evaluate, SpendTracker, type JsonRpcRequest } from "./index.js";

const { publicKey, privateKey } = generateKeyPair();
const newToken = () =>
  issueIntentToken({
    privateKey,
    agentId: "a",
    issuer: "u",
    scope: { maxSpend: 500, currency: "USD", domains: ["airline.com"] },
  });

const pay = (amount: number): JsonRpcRequest => ({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: { name: "pay", arguments: { url: "https://airline.com/pay", amount } },
});

test("cumulative budget is enforced across calls", () => {
  const token = newToken();
  const spend = new SpendTracker();
  const run = (n: number) => evaluate({ token, publicKey, request: pay(n), spend });

  assert.equal(run(300).allow, true);
  const second = run(300);
  assert.equal(second.allow, false);
  assert.match(second.reason, /cumulative/);
  assert.equal(run(200).allow, true); // total exactly 500
  assert.equal(run(1).allow, false);
});

test("blocked calls do not consume budget", () => {
  const token = newToken();
  const spend = new SpendTracker();
  assert.equal(evaluate({ token, publicKey, request: pay(600), spend }).allow, false);
  assert.equal(evaluate({ token, publicKey, request: pay(500), spend }).allow, true);
});

test("budgets are tracked per token", () => {
  const spend = new SpendTracker();
  const t1 = newToken();
  const t2 = newToken();
  assert.equal(evaluate({ token: t1, publicKey, request: pay(400), spend }).allow, true);
  assert.equal(evaluate({ token: t2, publicKey, request: pay(400), spend }).allow, true);
});

test("without a tracker only the per-call limit applies", () => {
  const token = newToken();
  for (let i = 0; i < 3; i++) {
    assert.equal(evaluate({ token, publicKey, request: pay(400) }).allow, true);
  }
});
