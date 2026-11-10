import { readFileSync } from "node:fs";
import { createPublicKey } from "node:crypto";
import { join } from "node:path";
import { verifyAuditFile } from "./audit.js";

// Usage: tsx src/audit-verify.ts [dataDir]
// Needs only the PUBLIC key, so it can be run on a copy of the log elsewhere.
const dir = process.argv[2] ?? process.env.POI_DATA_DIR ?? ".poi-data";
const publicKey = createPublicKey(readFileSync(join(dir, "public.pem")));
const r = verifyAuditFile(join(dir, "audit.log"), publicKey);

if (r.ok) {
  console.log(`OK: ${r.entries} entries. Head hash: ${r.head}`);
  console.log("Store the head hash somewhere separate to detect deleted tail entries.");
} else {
  console.error(`TAMPERED at line ${r.line}: ${r.reason}`);
  process.exit(1);
}
