import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadOrCreateKeys } from "./server.js";

const PASS = "correct-horse-battery-staple";
const dirOf = () => mkdtempSync(join(tmpdir(), "poi-keys-"));
const pubPem = (k: { publicKey: { export: (o: { type: "spki"; format: "pem" }) => string | Buffer } }) =>
  k.publicKey.export({ type: "spki", format: "pem" }).toString();

test("new key is encrypted at rest and reloads with the passphrase", () => {
  const dir = dirOf();
  const a = loadOrCreateKeys(dir, PASS);
  assert.ok(readFileSync(join(dir, "private.pem"), "utf8").includes("ENCRYPTED"));
  const b = loadOrCreateKeys(dir, PASS);
  assert.equal(pubPem(b), pubPem(a));
});

test("encrypted key cannot be loaded without or with the wrong passphrase", () => {
  const dir = dirOf();
  loadOrCreateKeys(dir, PASS);
  assert.throws(() => loadOrCreateKeys(dir), /encrypted/);
  assert.throws(() => loadOrCreateKeys(dir, "wrong-passphrase-0123456789"));
});

test("an existing plaintext key is migrated to encrypted, keeping the same identity", () => {
  const dir = dirOf();
  const a = loadOrCreateKeys(dir); // plaintext
  assert.ok(!readFileSync(join(dir, "private.pem"), "utf8").includes("ENCRYPTED"));
  const b = loadOrCreateKeys(dir, PASS); // migrates
  assert.equal(pubPem(b), pubPem(a));
  assert.ok(readFileSync(join(dir, "private.pem"), "utf8").includes("ENCRYPTED"));
});
