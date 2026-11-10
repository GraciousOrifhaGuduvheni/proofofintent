import { writeFileSync } from "node:fs";
import { generateKeyPair, issueIntentToken } from "@poi/crypto-identity";

// Dev helper. Usage: tsx src/dev-token.ts [domain] [maxSpend] [ttlSeconds]
// Writes poi-public.pem and prints a token. The private key is discarded.
const [domain = "airline.com", max = "500", ttl = "3600"] = process.argv.slice(2);

const { publicKey, privateKey } = generateKeyPair();
writeFileSync(
  "poi-public.pem",
  publicKey.export({ type: "spki", format: "pem" }) as string,
);

const token = issueIntentToken({
  privateKey,
  agentId: "dev-agent",
  issuer: "dev-user",
  scope: { maxSpend: Number(max), currency: "USD", domains: [domain] },
  ttlSeconds: Number(ttl),
});

console.log(token);
console.error(`wrote poi-public.pem (domain=${domain}, maxSpend=${max}, ttl=${ttl}s)`);
