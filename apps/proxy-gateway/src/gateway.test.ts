import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { generateKeyPair, issueIntentToken } from "@poi/crypto-identity";
import { RevocationList } from "@poi/policy-engine";
import { runGateway, POLICY_ERROR_CODE, type SecurityEvent } from "./gateway.js";

const fixture = fileURLToPath(new URL("./fixtures/fake-server.mjs", import.meta.url));

test("gateway forwards allowed calls and blocks violations", async () => {
  const { publicKey, privateKey } = generateKeyPair();
  const token = issueIntentToken({
    privateKey,
    agentId: "agent-1",
    issuer: "user-1",
    scope: { maxSpend: 500, currency: "USD", domains: ["airline.com"] },
  });

  const input = new PassThrough();
  const output = new PassThrough();
  const events: SecurityEvent[] = [];
  const revocations = new RevocationList();

  const { done } = runGateway({
    command: process.execPath,
    args: [fixture],
    token,
    publicKey,
    input,
    output,
    log: (e) => events.push(e),
    revocations,
  });

  const lines = createInterface({ input: output })[Symbol.asyncIterator]();
  const send = (o: unknown) => input.write(JSON.stringify(o) + "\n");
  const next = async () => JSON.parse((await lines.next()).value as string);
  const call = (id: number, args: Record<string, unknown>) => ({
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name: "book_flight", arguments: args },
  });

  // 1. In-scope call reaches the server (server count = 1)
  send(call(1, { url: "https://airline.com/book", amount: 450 }));
  let r = await next();
  assert.equal(r.id, 1);
  assert.equal(r.result.count, 1);

  // 2. tools/list passes through (count = 2)
  send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  r = await next();
  assert.equal(r.result.count, 2);

  // 3. Over budget: blocked with an error; server never sees it
  send(call(3, { url: "https://airline.com/book", amount: 501 }));
  r = await next();
  assert.equal(r.id, 3);
  assert.equal(r.error.code, POLICY_ERROR_CODE);

  // 4. Injection-style exfiltration to another domain: blocked
  send(call(4, { url: "https://evil.com/steal", amount: 1 }));
  r = await next();
  assert.equal(r.error.code, POLICY_ERROR_CODE);

  // 5. Next allowed call: server count is 3, proving 3 and 4 never arrived
  send(call(5, { url: "https://airline.com/book", amount: 10 }));
  r = await next();
  assert.equal(r.result.count, 3);

  // 6. Revoke the token: everything that mutates is now blocked
  revocations.revoke(events[0].jti!);
  send(call(6, { url: "https://airline.com/book", amount: 10 }));
  r = await next();
  assert.equal(r.error.code, POLICY_ERROR_CODE);

  // 7. Garbage input gets a parse error, not a crash
  input.write("not json\n");
  r = await next();
  assert.equal(r.error.code, -32700);

  // Audit log: 2 allowed, 3 blocked tool calls, plus 1 parse error
  assert.equal(events.filter((e) => e.type === "tool_call_allowed").length, 2);
  assert.equal(events.filter((e) => e.type === "tool_call_blocked").length, 3);
  assert.equal(events.filter((e) => e.type === "parse_error").length, 1);

  input.end();
  await done;
});
