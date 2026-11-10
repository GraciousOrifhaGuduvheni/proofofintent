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

/** In-memory store. Restarting the server clears agents, revocations and events. */
export class Store {
  private agents = new Map<string, AgentRecord>();
  private events: Record<string, unknown>[] = [];

  add(a: AgentRecord): void {
    this.agents.set(a.jti, a);
  }

  revoke(jti: string): boolean {
    const a = this.agents.get(jti);
    if (!a) return false;
    a.revoked = true;
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

  addEvent(e: Record<string, unknown>): void {
    this.events.push(e);
    if (this.events.length > 500) this.events.splice(0, this.events.length - 500);
  }

  recentEvents(n: number): Record<string, unknown>[] {
    return this.events.slice(-n).reverse();
  }
}
