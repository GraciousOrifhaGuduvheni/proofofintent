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
