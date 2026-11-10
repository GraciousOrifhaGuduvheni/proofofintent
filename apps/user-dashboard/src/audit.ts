import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { createHash, sign, verify, type KeyObject } from "node:crypto";

/**
 * Append-only audit log. Each line is hash-chained to the previous one and
 * signed with the server's Ed25519 key. Editing, deleting or reordering a
 * line in the middle breaks verification. Without the private key, an
 * attacker cannot forge a valid replacement.
 *
 * Known limit: removing the LAST lines is not detectable from the file alone.
 * Record the head hash somewhere else (see audit-verify) to catch that.
 */
export interface AuditEntry {
  seq: number;
  ts: string;
  event: Record<string, unknown>;
  prev: string;
  hash: string;
  sig: string;
}

export const GENESIS = "0".repeat(64);

function hashOf(seq: number, ts: string, event: Record<string, unknown>, prev: string): string {
  return createHash("sha256").update(JSON.stringify([seq, ts, event, prev])).digest("hex");
}

export type AuditVerify =
  | { ok: true; entries: number; head: string }
  | { ok: false; line: number; reason: string };

export function verifyAuditFile(path: string, publicKey: KeyObject): AuditVerify {
  if (!existsSync(path)) return { ok: true, entries: 0, head: GENESIS };
  const lines = readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.length > 0);

  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    const line = i + 1;
    try {
      const e = JSON.parse(lines[i]) as AuditEntry;
      if (e.seq !== line) return { ok: false, line, reason: "sequence gap or reorder" };
      if (e.prev !== prev) return { ok: false, line, reason: "broken hash chain" };
      if (hashOf(e.seq, e.ts, e.event, e.prev) !== e.hash) {
        return { ok: false, line, reason: "entry was modified" };
      }
      const ok = verify(null, Buffer.from(e.hash, "hex"), publicKey, Buffer.from(e.sig, "base64"));
      if (!ok) return { ok: false, line, reason: "bad signature" };
      prev = e.hash;
    } catch {
      return { ok: false, line, reason: "malformed entry" };
    }
  }
  return { ok: true, entries: lines.length, head: prev };
}

export class AuditLog {
  private count = 0;
  private tail: AuditEntry[] = [];
  private head = GENESIS;

  constructor(
    private path: string,
    private privateKey: KeyObject,
    publicKey: KeyObject,
  ) {
    // Refuse to start on a tampered log.
    const v = verifyAuditFile(path, publicKey);
    if (!v.ok) {
      throw new Error(`audit log failed verification at line ${v.line}: ${v.reason}`);
    }
    if (existsSync(path)) {
      const all = readFileSync(path, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l) as AuditEntry);
      this.count = all.length;
      this.tail = all.slice(-500);
    }
    this.head = v.head;
  }

  append(event: Record<string, unknown>): AuditEntry {
    const seq = this.count + 1;
    const ts = new Date().toISOString();
    const hash = hashOf(seq, ts, event, this.head);
    const sig = sign(null, Buffer.from(hash, "hex"), this.privateKey).toString("base64");
    const entry: AuditEntry = { seq, ts, event, prev: this.head, hash, sig };
    appendFileSync(this.path, JSON.stringify(entry) + "\n", { mode: 0o600 });
    this.count = seq;
    this.head = hash;
    this.tail.push(entry);
    if (this.tail.length > 500) this.tail.shift();
    return entry;
  }

  recent(n: number): Record<string, unknown>[] {
    return this.tail
      .slice(-n)
      .reverse()
      .map((e) => ({ ts: e.ts, ...e.event, seq: e.seq }));
  }
}
