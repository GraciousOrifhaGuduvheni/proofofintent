import { readFileSync } from "node:fs";
import { createPublicKey } from "node:crypto";
import { runGateway } from "./gateway.js";

// Usage:
//   POI_TOKEN=... POI_PUBLIC_KEY_FILE=poi-public.pem tsx src/cli.ts <server command> [args...]
const [command, ...args] = process.argv.slice(2);
const token = process.env.POI_TOKEN;
const keyFile = process.env.POI_PUBLIC_KEY_FILE;

if (!command || !token || !keyFile) {
  process.stderr.write(
    "Usage: POI_TOKEN=... POI_PUBLIC_KEY_FILE=poi-public.pem tsx src/cli.ts <server command> [args...]\n",
  );
  process.exit(2);
}

const publicKey = createPublicKey(readFileSync(keyFile));

const { done } = runGateway({
  command,
  args,
  token,
  publicKey,
  input: process.stdin,
  output: process.stdout,
  log: (e) => process.stderr.write(JSON.stringify(e) + "\n"),
});

done.then((code) => process.exit(code ?? 0));
