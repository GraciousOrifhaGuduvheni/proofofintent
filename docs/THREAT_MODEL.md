# Threat model

POI limits what an AI agent can do, whatever the agent has been tricked into
attempting. It does **not** stop prompt injection itself. It shrinks the damage to
what the token allows.

## Protected assets
- The user's money and accounts, reachable through agent tool calls.
- The signing key (`.poi-data/private.pem`).
- The integrity of the audit log.

## Threats

| Threat | Status |
|---|---|
| Injected agent calls an attacker's domain | Mitigated: exact-match domain allowlist, lookalike domains rejected |
| Agent overspends | Mitigated: per-call limit and cumulative budget per token (per gateway process, see gaps) |
| Token leaks | Limited: expiry (max 24h), domain scope, budget, revocation within about 2 seconds |
| Compromised gateway host | Cannot issue or list tokens: the gateway key can only read revocations and post events |
| Dashboard key guessing | Mitigated: 10 failures per minute per address, then lockout; constant-time compare |
| DNS rebinding against the local dashboard | Mitigated: Host header must be localhost |
| Editing or deleting audit entries | Detected: hash chain plus signatures; the server refuses to start on a tampered log |
| Signing key stolen from disk | Mitigated if `POI_KEY_PASSPHRASE` is set (encrypted at rest). Plaintext otherwise |

## Known gaps (not covered today)
- **No zero-knowledge proofs.** Tokens are signed claims. The "ZK-NHI" idea in the original concept is not implemented.
- **The agent runtime can see its own token** (it is passed in an environment variable). Anyone who can read it can use it within its scope until it expires or is revoked.
- **Tools must expose their target** in `arguments.url`, `arguments.domain` and `arguments.amount`. Tools that do not are denied. There are no per-tool adapters yet.
- **Spend counters live in gateway memory.** Restarting a gateway resets cumulative spend, and multiple gateways do not share it.
- **Currency is not enforced.**
- **One signing key, no rotation or key ids.** Losing the key means reissuing everything.
- **Single shared admin secret, localhost only, no TLS.** Do not expose the dashboard to a network.
- **Deleting the newest audit lines cannot be detected from the file alone.** Store the head hash printed by `audit:verify` elsewhere.
- **Events are best-effort.** If the dashboard is unreachable, gateway events reach stderr but not the signed log.
- **Revocation fails open** unless `POI_FAIL_CLOSED=1` is set.
- **stdio transport only.**
