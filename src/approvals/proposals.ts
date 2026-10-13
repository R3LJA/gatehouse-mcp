import { randomBytes } from "node:crypto";
import { audit } from "../audit/log.js";
import { canonical, sha256 } from "../canonical.js";
import { now, type TenantStore } from "../store/db.js";
import { actorOf, type TenantContext } from "../tenancy/context.js";

// Anything that spends money, publishes, or contacts a customer starts life as a proposal.
// A proposal is inert: it records exactly what would happen, and nothing happens until a
// person signs a grant for this exact proposal.
export const ACTIONS = {
  refund: { effect: "spends money" },
  discount: { effect: "spends money" },
  publish_product: { effect: "publishes" },
  send_email: { effect: "contacts a customer" },
} as const;
export type ActionTool = keyof typeof ACTIONS;

export type Proposal = {
  id: string;
  tool: ActionTool;
  args: Record<string, unknown>;
  summary: string;
  amount: number;
  created_at: string;
  created_by: string;
  hash: string;
  status: "pending" | "approved" | "denied" | "executed" | "failed";
  decided_at: string | null;
  decided_by: string | null;
  executed_at: string | null;
  result: string | null;
};

type Row = Omit<Proposal, "args"> & { args: string };

// The hash commits to the tenant, the proposal id, the tool, every argument and the creation time.
// A grant signs this hash, so approving one refund can never authorise a different amount,
// a different order, or the same refund in another tenant.
export function proposalHash(tenantId: string, p: Pick<Proposal, "id" | "tool" | "args" | "created_at">): string {
  return sha256(canonical({ tenant: tenantId, id: p.id, tool: p.tool, args: p.args, created_at: p.created_at }));
}

export class ProposalLimitError extends Error {}

export function createProposal(
  ctx: TenantContext,
  store: TenantStore,
  input: { tool: ActionTool; args: Record<string, unknown>; summary: string; amount?: number },
): Proposal {
  return store.tx(() => {
    const hourAgo = new Date(Date.now() - 3_600_000).toISOString();
    const recent = store.db.prepare("SELECT COUNT(*) AS n FROM proposals WHERE created_at > ?").get(hourAgo) as { n: number };
    if (recent.n >= ctx.tenant.limits.proposals_per_hour)
      throw new ProposalLimitError(`proposal limit reached: ${ctx.tenant.limits.proposals_per_hour} per hour for ${ctx.tenant.name}`);
    const base = { id: `p_${randomBytes(5).toString("hex")}`, tool: input.tool, args: input.args, created_at: now() };
    const p: Proposal = {
      ...base,
      summary: input.summary,
      amount: input.amount ?? 0,
      created_by: ctx.subject,
      hash: proposalHash(ctx.tenant.id, base),
      status: "pending",
      decided_at: null,
      decided_by: null,
      executed_at: null,
      result: null,
    };
    store.db
      .prepare("INSERT INTO proposals (id, tool, args, summary, amount, created_at, created_by, hash, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')")
      .run(p.id, p.tool, canonical(p.args), p.summary, p.amount, p.created_at, p.created_by, p.hash);
    audit(store, actorOf(ctx), "proposal.created", { proposal: p.id, tool: p.tool, summary: p.summary, hash: p.hash });
    return p;
  });
}

export function getProposal(store: TenantStore, id: string): Proposal | null {
  const row = store.db.prepare("SELECT * FROM proposals WHERE id = ?").get(id) as Row | undefined;
  return row ? { ...row, args: JSON.parse(row.args) } : null;
}

export function listProposals(store: TenantStore, status?: Proposal["status"]): Proposal[] {
  const rows = (
    status
      ? store.db.prepare("SELECT * FROM proposals WHERE status = ? ORDER BY created_at DESC LIMIT 100").all(status)
      : store.db.prepare("SELECT * FROM proposals ORDER BY created_at DESC LIMIT 100").all()
  ) as Row[];
  return rows.map((r) => ({ ...r, args: JSON.parse(r.args) }));
}
