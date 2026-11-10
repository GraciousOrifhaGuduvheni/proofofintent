import type { RevocationList } from "@poi/policy-engine";
import type { SecurityEvent } from "./gateway.js";

export interface ControlSyncOptions {
  /** If set, block all tool calls when the dashboard has been unreachable this long. */
  failClosedAfterMs?: number;
}

/**
 * Polls the dashboard for revoked token ids every 2 seconds and posts
 * security events to it. Use the GATEWAY key here, never the admin key.
 */
export async function startControlSync(
  baseUrl: string,
  key: string,
  revocations: RevocationList,
  options: ControlSyncOptions = {},
) {
  const headers = { authorization: `Bearer ${key}`, "content-type": "application/json" };
  let lastOk = 0;

  const poll = async () => {
    try {
      const r = await fetch(`${baseUrl}/api/revocations`, {
        headers,
        signal: AbortSignal.timeout(3000),
      });
      if (!r.ok) return;
      const body = (await r.json()) as { revoked?: string[] };
      for (const jti of body.revoked ?? []) revocations.revoke(jti);
      lastOk = Date.now();
    } catch {
      /* unreachable: lastOk stays old */
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
      signal: AbortSignal.timeout(3000),
    }).catch(() => {});
  };

  const blockAll = (): string | null =>
    options.failClosedAfterMs !== undefined && Date.now() - lastOk > options.failClosedAfterMs
      ? "control plane unreachable (fail-closed)"
      : null;

  return { log, blockAll, stop: () => clearInterval(timer) };
}
