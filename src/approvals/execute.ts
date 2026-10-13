import { audit } from "../audit/log.js";
import type { Connector } from "../connectors/commerce.js";
import { ConnectorError } from "../connectors/commerce.js";
import type { Approvers } from "../keys.js";
import { now, type TenantStore } from "../store/db.js";
import { actorOf, type TenantContext } from "../tenancy/context.js";
import { grantSignatureValid, grantTimeProblem, storedGrant } from "./grants.js";
import { getProposal, proposalHash, type Proposal } from "./proposals.js";

export class Refused extends Error {}

// Limits from the manifest, applied to the hashed arguments at the moment of execution. The
// manifest may have tightened since the proposal was made; execution follows today's rules.
function limitProblem(ctx: TenantContext, store: TenantStore, p: Proposal): string | null {
  const l = ctx.tenant.limits;
  if (p.tool === "refund") {
    const amount = Number(p.args.amount);
    if (!(amount > 0)) return "refund amount is not positive";
    if (amount > l.refund_max) return `single refunds are capped at ${l.refund_max}`;
    const today = new Date().toISOString().slice(0, 10);
    const spent = store.db.prepare("SELECT COALESCE(SUM(amount), 0) AS s FROM refunds WHERE substr(at, 1, 10) = ?").get(today) as { s: number };
    if (spent.s + amount > l.refund_daily) return `daily refund budget: ${spent.s} of ${l.refund_daily} already used today`;
  }
  if (p.tool === "discount" && Number(p.args.percent) > l.discount_max_percent) return `discounts are capped at ${l.discount_max_percent}%`;
  return null;
}

// The only code path that changes anything outside the agent's own notes. Every condition is
// checked here, in the server that holds the credentials, inside one write transaction:
//   1. the proposal exists in this tenant's store and is approved (not pending, denied or done);
//   2. the grant verifies against the key of the approver it names;
//   3. the grant names this tenant and this proposal, and the stored proposal still hashes to
//      what was signed, so every argument is exactly what the person saw;
//   4. the approver is still on this tenant's list, and the grant's times are valid and live;
//   5. the grant's nonce has not been used (one approval, one execution);
//   6. today's limits allow it, computed from the hashed arguments.
// Nothing the model says can satisfy these: they are facts about signatures, hashes and rows.
export function executeApproved(ctx: TenantContext, store: TenantStore, approvers: Approvers, connector: Connector, proposalId: string) {
  const actor = actorOf(ctx);
  try {
    return store.tx(() => {
      const p = getProposal(store, proposalId);
      if (!p) throw new Refused("no such proposal in this tenant");
      if (p.status === "executed") throw new Refused("already executed; a grant works once");
      if (p.status !== "approved") throw new Refused(`not approved by a person (status: ${p.status})`);
      const g = storedGrant(store, p.id);
      if (!g) throw new Refused("no grant on file for this proposal");
      if (!grantSignatureValid(approvers, g)) throw new Refused("grant signature does not verify against the named approver's key");
      const b = g.body;
      if (b.tenant !== ctx.tenant.id) throw new Refused("grant is for a different tenant");
      if (b.proposal_id !== p.id) throw new Refused("grant is for a different proposal");
      const hash = proposalHash(ctx.tenant.id, p);
      if (hash !== b.proposal_hash || hash !== p.hash) throw new Refused("proposal changed after it was approved");
      if (!ctx.tenant.approvers.includes(b.approver)) throw new Refused("approver is no longer on this tenant's list");
      const timing = grantTimeProblem(b);
      if (timing) throw new Refused(timing);
      if (store.db.prepare("SELECT 1 FROM used_nonces WHERE nonce = ?").get(b.nonce)) throw new Refused("grant was already used");
      const limit = limitProblem(ctx, store, p);
      if (limit) throw new Refused(limit);
      store.db.prepare("INSERT INTO used_nonces (nonce, used_at) VALUES (?, ?)").run(b.nonce, now());
      const result = connector.apply(p.tool, p.args, p.id);
      store.db.prepare("UPDATE proposals SET status = 'executed', executed_at = ?, result = ? WHERE id = ?").run(now(), JSON.stringify(result), p.id);
      audit(store, actor, "action.executed", { proposal: p.id, tool: p.tool, approver: b.approver, result });
      return { proposal_id: p.id, tool: p.tool, approved_by: b.approver, result };
    });
  } catch (err) {
    // refusals are evidence: record them outside the rolled-back transaction. Anything else
    // (a locked database, a bug) is an error, not a refusal, and is reported as one.
    if (err instanceof Refused || err instanceof ConnectorError) {
      audit(store, actor, "action.refused", { proposal: proposalId, reason: err.message });
      throw err instanceof Refused ? err : new Refused(err.message);
    }
    audit(store, actor, "action.error", { proposal: proposalId, error: (err as Error).message });
    throw err;
  }
}
