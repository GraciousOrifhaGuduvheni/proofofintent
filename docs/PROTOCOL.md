# ProofOfIntent protocol (draft v0.1)

Status: draft. Describes what the code in this repository implements today.

## Intent token

A JWT in compact serialization (`header.payload.signature`, base64url), signed with
Ed25519.

Header: `{"alg":"EdDSA","typ":"POI+JWT"}`

| Claim | Meaning |
|---|---|
| `jti` | Unique token id. Used for revocation and cumulative spend. |
| `sub` | Agent identity. |
| `iss` | Issuer (for example the dashboard). |
| `iat`, `exp` | Issued-at and expiry, unix seconds. Maximum lifetime issued by the dashboard: 24 hours. |
| `scope.maxSpend` | Total budget for this token. |
| `scope.currency` | Carried but **not yet enforced**. |
| `scope.domains` | Allowlisted hostnames, exact match, lowercase. |

## Verification

1. Exactly three parts; header `alg` is `EdDSA`.
2. Signature verifies against the issuer's public key.
3. Current time is before `exp`.

## Evaluating an MCP request

For every JSON-RPC request, in order. Any failure denies the request.

1. Token verifies (above).
2. `jti` is not in the revocation set.
3. If `method` is not `tools/call`, allow (no side effects).
4. Extract the target from `params.arguments`: hostname of `url`, or `domain`; and
   optional `amount` (finite, not negative). If no target can be determined, deny.
5. Target hostname is in `scope.domains` (exact match).
6. `amount` does not exceed `scope.maxSpend`.
7. Previously allowed spend for this `jti` plus `amount` does not exceed
   `scope.maxSpend`. On allow, the amount is recorded.

## Errors

| Code | Meaning |
|---|---|
| `-32001` | POI policy violation. `message` begins `POI policy violation:` and gives the reason. |
| `-32700` | Message was not valid JSON. |

## Revocation

The control plane keeps a set of revoked `jti` values. Gateways poll it (default every
2 seconds). Optional fail-closed mode blocks all tool calls if the control plane has
been unreachable for 10 seconds.

## Audit log entry

One JSON object per line:
`{"seq","ts","event","prev","hash","sig"}` where
`hash = sha256(JSON([seq, ts, event, prev]))` (hex) and `sig` is an Ed25519 signature
over the raw hash bytes (base64). `prev` is the previous entry's hash; the first
entry uses 64 zeros.

## Not yet specified

Key ids and rotation, per-tool allowlists, currency enforcement, budgets shared
across gateways, HTTP/SSE transports.
