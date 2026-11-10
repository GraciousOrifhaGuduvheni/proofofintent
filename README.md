ProofOfIntent (POI Protocol)
A cryptographic identity and policy authorization protocol designed to secure autonomous AI agent tool calls and enforce strict execution boundaries.
Architecture & Monorepo Structure
This project is structured as a pnpm workspace monorepo consisting of core functional packages and application runtimes.
Core Packages
Package
Description
packages/crypto-identity
Generates and verifies ED25519-signed agent session tokens embedding cryptographically hashed action parameters, budget caps, and expiration timestamps.
packages/policy-engine
High-performance policy evaluation engine that validates incoming agent tool calls against signed intent tokens (handling domain allowlists, budgets, and in-memory revocations).
packages/mcp-middleware
Model Context Protocol authentication plugin for seamless integration into agent execution pipelines.

Directory Layout
proofofintent/
├── apps/
│   ├── proxy-gateway/       # Agent execution proxy (MCP interceptor)
│   └── user-dashboard/      # Access control & authorization portal
├── packages/
│   ├── crypto-identity/     # ZK & ED25519 token generation package
│   ├── policy-engine/       # Execution boundary & rule parser package
│   └── mcp-middleware/      # Model Context Protocol authentication plugin
├── pnpm-workspace.yaml
├── package.json
└── README.md
Quickstart & Installation
Prerequisites
Node.js >=18.0.0
pnpm >=9.0.0
1. Clone and Install
git clone https://github.com/GraciousOrifhaGuduvheni/proofofintent.git
cd proofofintent
pnpm install
2. Run the Test Suite
To execute the complete test suite (covering token verification, tamper rejection, expiration checks, and policy boundary enforcement):

pnpm test

Expected Test Output:

✓ valid token verifies
✓ tampered token is rejected
✓ wrong key is rejected
✓ expired token is rejected
✓ policy: $500 ok, $501 blocked, other domain blocked

Tests: 15 pass, 15 total
License
Licensed under the MIT License.

## License

Dual-licensed: AGPL-3.0-or-later for open-source use, and a commercial license for
closed-source use. See `LICENSE` and `COMMERCIAL.md`.
