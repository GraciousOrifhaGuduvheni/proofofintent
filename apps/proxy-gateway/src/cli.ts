import { readFileSync } from "node:fs";
import { createPublicKey } from "node:crypto";
import { RevocationList } from "@poi/policy-engine";
import { runGateway, type SecurityEvent } from "./gateway.js";
import { startControlSync } from "./control-sync.js";

// Usage:
//   POI_TOKEN=... POI_PUBLIC_KEY_FILE=path/to/public.pem \
//   [POI_CONTROL_URL=http://127.0.0.1:8787 POI_GATEWAY_KEY=<gateway key> [POI_FAIL_CLOSED=1]] \
//   tsx src/cli.ts <server command> [args...]
const [command, ...args] = process.argv.slice(2);
const token = process.env.POI_TOKEN;
const keyFile = process.env.POI_PUBLIC_KEY_FILE;
const controlUrl = process.env.POI_CONTROL_URL;
const gatewayKey = process.env.POI_GATEWAY_KEY;
const failClosed = process.env.POI_FAIL_CLOSED === "1";

if (!command || !token || !keyFile) {
  process.stderr.write(
    "Usage: POI_TOKEN=... POI_PUBLIC_KEY_FILE=public.pem [POI_CONTROL_URL=... POI_GATEWAY_KEY=... [POI_FAIL_CLOSED=1]] tsx src/cli.ts <server command> [args...]\n",
  );
  process.exit(2);
}

const publicKey = createPublicKey(readFileSync(keyFile));
const revocations = new RevocationList();

let log: (e: SecurityEvent) => void = (e) => {
  process.stderr.write(JSON.stringify(e) + "\n");
};
let blockAll: (() => string | null) | undefined;

if (controlUrl && gatewayKey) {
  const sync = await startControlSync(controlUrl, gatewayKey, revocations, {
    failClosedAfterMs: failClosed ? 10_000 : undefined,
  });
  log = sync.log;
  blockAll = sync.blockAll;
} else if (failClosed) {
  process.stderr.write("POI_FAIL_CLOSED=1 needs POI_CONTROL_URL and POI_GATEWAY_KEY.\n");
  process.exit(2);
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
  blockAll,
});

done.then((code) => process.exit(code ?? 0));
