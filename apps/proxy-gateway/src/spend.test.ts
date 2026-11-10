import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { generateKeyPair, issueIntentToken } from "@poi/crypto-identity";
import { runGateway, POLICY_ERROR_CODE } from "./gateway.js";

const fixture = fileURLToPath(new URL("./fixtures/fake-server.mjs", import.meta.url));

test("gateway enforces the cumulative budget, not just the per-call limit", async () => {
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
  });
  const lines = createInterface({ input: output })[Symbol.asyncIterator]();
  const send = (o: unknown) => input.write(JSON.stringify(o) + "\n");
  const next = async () => JSON.parse((await lines.next()).value as string);
  const pay = (id: number, amount: number) => ({
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name: "pay", arguments: { url: "https://airline.com/pay", amount } },
  });

  send(pay(1, 300));
  let r = await next();
  assert.equal(r.result.count, 1);

  send(pay(2, 300)); // each call is under 500, but the total would be 600
  r = await next();
  assert.equal(r.error.code, POLICY_ERROR_CODE);
  assert.match(r.error.message, /cumulative/);

  send(pay(3, 200)); // total exactly 500 is fine
  r = await next();
  assert.equal(r.result.count, 2); // the blocked call never reached the server

  input.end();
  await done;
});
