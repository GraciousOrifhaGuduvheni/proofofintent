import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

export interface AgentRecord {
  jti: string;
  name: string;
  domains: string[];
  maxSpend: number;
  issuedAt: number; // unix seconds
  expiresAt: number; // unix seconds
  revoked: boolean;
}

export type AgentStatus = "active" | "revoked" | "expired";
export type AgentView = AgentRecord & { status: AgentStatus };

/** Agent and revocation state, persisted to a JSON file with atomic writes. */
export class Store {
  private agents = new Map<string, AgentRecord>();

  constructor(private filePath?: string) {
    if (filePath && existsSync(filePath)) {
      // A corrupt state file throws here on purpose: refuse to start
      // rather than silently forget which tokens were revoked.
      const data = JSON.parse(readFileSync(filePath, "utf8")) as { agents: AgentRecord[] };
      for (const a of data.agents) this.agents.set(a.jti, a);
    }
  }

  private save(): void {
    if (!this.filePath) return;
    const tmp = this.filePath + ".tmp";
    writeFileSync(tmp, JSON.stringify({ agents: [...this.agents.values()] }), { mode: 0o600 });
    renameSync(tmp, this.filePath);
  }

  add(a: AgentRecord): void {
    this.agents.set(a.jti, a);
    this.save();
  }

  revoke(jti: string): boolean {
    const a = this.agents.get(jti);
    if (!a) return false;
    a.revoked = true;
    this.save();
    return true;
  }

  /** Revokes every agent token not already revoked. Returns how many changed. */
  revokeAll(): number {
    let n = 0;
    for (const a of this.agents.values()) {
      if (!a.revoked) {
        a.revoked = true;
        n++;
      }
    }
    if (n > 0) this.save();
    return n;
  }

  revokedIds(): string[] {
    return [...this.agents.values()].filter((a) => a.revoked).map((a) => a.jti);
  }

  list(now: number = Math.floor(Date.now() / 1000)): AgentView[] {
    return [...this.agents.values()]
      .map((a) => ({
        ...a,
        status: (a.revoked ? "revoked" : now >= a.expiresAt ? "expired" : "active") as AgentStatus,
      }))
      .sort((x, y) => y.issuedAt - x.issuedAt);
  }
}
