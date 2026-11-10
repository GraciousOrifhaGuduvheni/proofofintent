import type { RevocationList } from "@poi/policy-engine";
import type { SecurityEvent } from "./gateway.js";

/**
 * Polls the dashboard for revoked token ids every 2 seconds and posts
 * security events to it. If the dashboard is unreachable the gateway keeps
 * its current revocation list (it does not fail closed).
 */
export async function startControlSync(
  baseUrl: string,
  key: string,
  revocations: RevocationList,
) {
  const headers = { authorization: `Bearer ${key}`, "content-type": "application/json" };

  const poll = async () => {
    try {
      const r = await fetch(`${baseUrl}/api/revocations`, { headers });
      if (!r.ok) return;
      const body = (await r.json()) as { revoked?: string[] };
      for (const jti of body.revoked ?? []) revocations.revoke(jti);
    } catch {
      /* dashboard unreachable: keep the current list */
    }
  };

  await poll(); // load existing revocations before serving any traffic
  const timer = setInterval(poll, 2000);
  timer.unref();

  const log = (e: SecurityEvent) => {
    process.stderr.write(JSON.stringify(e) + "\n");
    fetch(`${baseUrl}/api/events`, {
      method: "POST",
      headers,
      body: JSON.stringify(e),
    }).catch(() => {});
  };

  return { log, stop: () => clearInterval(timer) };
}
