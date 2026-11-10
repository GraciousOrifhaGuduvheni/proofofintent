import { readFileSync } from "node:fs";
import { createPublicKey } from "node:crypto";
import { RevocationList } from "@poi/policy-engine";
import { runGateway, type SecurityEvent } from "./gateway.js";
import { startControlSync } from "./control-sync.js";

// Usage:
//   POI_TOKEN=... POI_PUBLIC_KEY_FILE=path/to/public.pem \
//   [POI_CONTROL_URL=http://127.0.0.1:8787 POI_CONTROL_KEY=<admin key>] \
//   tsx src/cli.ts <server command> [args...]
const [command, ...args] = process.argv.slice(2);
const token = process.env.POI_TOKEN;
const keyFile = process.env.POI_PUBLIC_KEY_FILE;
const controlUrl = process.env.POI_CONTROL_URL;
const controlKey = process.env.POI_CONTROL_KEY;

if (!command || !token || !keyFile) {
  process.stderr.write(
    "Usage: POI_TOKEN=... POI_PUBLIC_KEY_FILE=public.pem [POI_CONTROL_URL=... POI_CONTROL_KEY=...] tsx src/cli.ts <server command> [args...]\n",
  );
  process.exit(2);
}

const publicKey = createPublicKey(readFileSync(keyFile));
const revocations = new RevocationList();

let log = (e: SecurityEvent) => process.stderr.write(JSON.stringify(e) + "\n");
if (controlUrl && controlKey) {
  log = (await startControlSync(controlUrl, controlKey, revocations)).log;
}

const { done } = runGateway({
  command,
  args,
  token,
  publicKey,
  input: process.stdin,
  output: process.stdout,
  log,
  revocations,
});

done.then((code) => process.exit(code ?? 0));
