import { randomBytes, sign, verify, type KeyObject } from "node:crypto";
import { audit, type Head } from "../audit/log.js";
import { canonical } from "../canonical.js";
import type { Tenant } from "../config.js";
import type { Approvers } from "../keys.js";
import { now, type TenantStore } from "../store/db.js";
import { getProposal, proposalHash } from "./proposals.js";

// A grant is one person's signed "yes" to one proposal. It is bound to the tenant, the proposal
// id and the proposal hash (so to the exact tool and arguments), signed with that person's own
// key, time-boxed, and carries a nonce so it works once. It also carries the audit head the
// approver saw, which anchors the log (see audit/log.ts).
export type GrantBody = {
  v: 1;
  tenant: string;
  proposal_id: string;
  proposal_hash: string;
  approver: string;
  audit_head: Head | null;
  issued_at: string;
  expires_at: string;
  nonce: string;
};
export type Grant = { body: GrantBody; signature: string };

export const MAX_GRANT_MINUTES = 24 * 60;
const CLOCK_SKEW_MS = 5 * 60_000;

export function signGrant(approverKey: KeyObject, body: Omit<GrantBody, "v" | "issued_at" | "expires_at" | "nonce" | "audit_head"> & { audit_head?: Head | null }, ttlMinutes = 30): Grant {
  const issued = new Date();
  const full: GrantBody = {
    v: 1,
    tenant: body.tenant,
    proposal_id: body.proposal_id,
    proposal_hash: body.proposal_hash,
    approver: body.approver,
    audit_head: body.audit_head ?? null,
    issued_at: issued.toISOString(),
    expires_at: new Date(issued.getTime() + ttlMinutes * 60_000).toISOString(),
    nonce: randomBytes(16).toString("hex"),
  };
  return { body: full, signature: sign(null, Buffer.from(canonical(full)), approverKey).toString("base64") };
}

// The signature must come from the key registered for the approver the grant names, so a
// grant proves which person approved, not just that someone with access to the channel did.
export function grantSignatureValid(approvers: Approvers, grant: Grant): boolean {
  const key = approvers.get(grant.body?.approver);
  if (!key) return false;
  try {
    return verify(null, Buffer.from(canonical(grant.body)), key, Buffer.from(grant.signature, "base64"));
  } catch {
    return false;
  }
}

// Times must parse, the grant must still be live, not issued in the future, and not open-ended.
export function grantTimeProblem(b: GrantBody, at = Date.now()): string | null {
  const issued = Date.parse(b.issued_at);
  const expires = Date.parse(b.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires)) return "grant times are not valid dates";
  if (issued > at + CLOCK_SKEW_MS) return "grant was issued in the future";
  if (expires - issued > MAX_GRANT_MINUTES * 60_000) return `grant lives longer than ${MAX_GRANT_MINUTES / 60} hours`;
  if (!(expires > at)) return "grant expired; ask for a new approval";
  return null;
}

export class GrantError extends Error {}

// The approval channel calls this (the CLI here; a Slack button handler in production).
export function recordGrant(store: TenantStore, tenant: Tenant, approvers: Approvers, grant: Grant): void {
  if (!grantSignatureValid(approvers, grant)) throw new GrantError("grant signature is invalid");
  const b = grant.body;
  if (b.tenant !== tenant.id || store.tenantId !== tenant.id) throw new GrantError("grant is for a different tenant");
  if (!tenant.approvers.includes(b.approver)) throw new GrantError(`${b.approver} is not an approver for ${tenant.name}`);
  const timing = grantTimeProblem(b);
  if (timing) throw new GrantError(timing);
  store.tx(() => {
    const p = getProposal(store, b.proposal_id);
    if (!p) throw new GrantError("no such proposal in this tenant");
    // an approved proposal whose grant ran out can be approved again; anything else must be pending
    const previous = storedGrant(store, p.id);
    const reapproval = p.status === "approved" && previous !== null && grantTimeProblem(previous.body) !== null;
    if (p.status !== "pending" && !reapproval) throw new GrantError(`proposal is ${p.status}, not pending`);
    if (proposalHash(tenant.id, p) !== b.proposal_hash || p.hash !== b.proposal_hash) throw new GrantError("proposal changed since it was shown to the approver");
    store.db.prepare("INSERT OR REPLACE INTO grants (proposal_id, body, signature, received_at) VALUES (?, ?, ?, ?)").run(p.id, canonical(b), grant.signature, now());
    store.db.prepare("UPDATE proposals SET status = 'approved', decided_at = ?, decided_by = ? WHERE id = ?").run(b.issued_at, b.approver, p.id);
    audit(store, `human:${b.approver}`, reapproval ? "proposal.reapproved" : "proposal.approved", { proposal: p.id, hash: b.proposal_hash, expires_at: b.expires_at });
  });
}

// Deny a pending proposal, or revoke an approval that has not been executed yet.
export function denyProposal(store: TenantStore, tenant: Tenant, proposalId: string, approver: string, reason: string): "denied" | "revoked" {
  if (!tenant.approvers.includes(approver)) throw new GrantError(`${approver} is not an approver for ${tenant.name}`);
  return store.tx(() => {
    const p = getProposal(store, proposalId);
    if (!p || (p.status !== "pending" && p.status !== "approved")) throw new GrantError("no pending or approved proposal with that id");
    store.db.prepare("UPDATE proposals SET status = 'denied', decided_at = ?, decided_by = ?, result = ? WHERE id = ?").run(now(), approver, reason, p.id);
    const kind = p.status === "approved" ? "revoked" : "denied";
    audit(store, `human:${approver}`, kind === "revoked" ? "approval.revoked" : "proposal.denied", { proposal: p.id, reason });
    return kind;
  });
}

export function storedGrant(store: TenantStore, proposalId: string): Grant | null {
  const row = store.db.prepare("SELECT body, signature FROM grants WHERE proposal_id = ?").get(proposalId) as { body: string; signature: string } | undefined;
  return row ? { body: JSON.parse(row.body), signature: row.signature } : null;
}
