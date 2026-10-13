import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { executeApproved, Refused } from "../../src/approvals/execute.js";
import { denyProposal, recordGrant, signGrant } from "../../src/approvals/grants.js";
import { auditHead } from "../../src/audit/log.js";
import { issueAccessToken, verifyAccessToken } from "../../src/auth/tokens.js";
import { canonical } from "../../src/canonical.js";
import { sandboxCommerce } from "../../src/connectors/commerce.js";
import { credentialsFor } from "../../src/secrets/credentials.js";
import { STDIO_AUDIENCE } from "../../src/stdio.js";
import { contextFromClaims } from "../../src/tenancy/context.js";
import { A, APPROVER_A, B, call, makeEnv } from "../helpers.js";

const LEAD_A = "ops-lead@fernhill.example";
const env = makeEnv();
const agent = () => env.connect(A, ["read", "propose", "execute"]);
const refunds = (tenant: string) => (env.store(tenant).db.prepare("SELECT COUNT(*) AS n FROM refunds").get() as { n: number }).n;
const tenantA = () => env.manifest.tenants.find((x) => x.id === A)!;
const hashOf = (id: string) => (env.store(A).db.prepare("SELECT hash FROM proposals WHERE id = ?").get(id) as { hash: string }).hash;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function proposeRefund(order_id = "1002", amount = 25) {
  const c = await agent();
  const r = await call(c, "refund_propose", { order_id, amount, reason: "item arrived damaged" });
  if (r.error) throw new Error(r.error);
  return { c, id: r.data.proposal_id as string };
}

describe("a write is a proposal until a named person approves that exact proposal", () => {
  it("proposing changes nothing in the world", async () => {
    const before = refunds(A);
    const { id } = await proposeRefund();
    expect(id).toMatch(/^p_[0-9a-f]{10}$/);
    expect(refunds(A)).toBe(before);
  });

  it("execute before approval is refused", async () => {
    const { c, id } = await proposeRefund();
    expect((await call(c, "action_execute", { proposal_id: id })).error).toMatch(/not approved by a person/);
  });

  it("approved once, executed once", async () => {
    const { c, id } = await proposeRefund("1005", 40);
    env.approve(A, id, APPROVER_A);
    const done = await call(c, "action_execute", { proposal_id: id });
    expect(done.data.status).toBe("executed");
    expect(done.data.approved_by).toBe(APPROVER_A);
    expect((await call(c, "order_get", { order_id: "1005" })).data.order.refunded).toBe(40);
    expect((await call(c, "action_execute", { proposal_id: id })).error).toMatch(/already executed/);
  });

  it("the nonce stops a replay even if someone resets the proposal's status", async () => {
    const { c, id } = await proposeRefund("1005", 10);
    env.approve(A, id, APPROVER_A);
    await call(c, "action_execute", { proposal_id: id });
    env.store(A).db.prepare("UPDATE proposals SET status = 'approved' WHERE id = ?").run(id);
    expect((await call(c, "action_execute", { proposal_id: id })).error).toMatch(/already used/);
  });

  it("changing the arguments after approval voids the approval", async () => {
    const { c, id } = await proposeRefund("1002", 10);
    env.approve(A, id, APPROVER_A);
    env.store(A).db.prepare("UPDATE proposals SET args = ? WHERE id = ?").run(canonical({ order_id: "1002", amount: 240, reason: "item arrived damaged" }), id);
    expect((await call(c, "action_execute", { proposal_id: id })).error).toMatch(/changed after it was approved/);
  });

  it("a grant signed with any key but the named approver's is worthless", async () => {
    const { c, id } = await proposeRefund();
    const forged = signGrant(generateKeyPairSync("ed25519").privateKey, { tenant: A, proposal_id: id, proposal_hash: hashOf(id), approver: APPROVER_A });
    expect(() => recordGrant(env.store(A), tenantA(), env.serverKeys.approvers, forged)).toThrow(/signature is invalid/);
    // even written straight into the database, it does not verify at execution
    env.store(A).db.prepare("INSERT INTO grants (proposal_id, body, signature, received_at) VALUES (?, ?, ?, ?)").run(id, canonical(forged.body), forged.signature, new Date().toISOString());
    env.store(A).db.prepare("UPDATE proposals SET status = 'approved' WHERE id = ?").run(id);
    expect((await call(c, "action_execute", { proposal_id: id })).error).toMatch(/signature does not verify/);
  });

  it("one approver cannot sign in another approver's name", async () => {
    const { id } = await proposeRefund();
    const asLead = signGrant(env.keyOf(APPROVER_A), { tenant: A, proposal_id: id, proposal_hash: hashOf(id), approver: LEAD_A });
    expect(() => recordGrant(env.store(A), tenantA(), env.serverKeys.approvers, asLead)).toThrow(/signature is invalid/);
  });

  it("a genuine grant for one proposal cannot be moved to another", async () => {
    const first = await proposeRefund("1002", 5);
    const second = await proposeRefund("1002", 200);
    const grant = env.approve(A, first.id, APPROVER_A);
    env.store(A).db.prepare("INSERT INTO grants (proposal_id, body, signature, received_at) VALUES (?, ?, ?, ?)").run(second.id, canonical(grant.body), grant.signature, new Date().toISOString());
    env.store(A).db.prepare("UPDATE proposals SET status = 'approved' WHERE id = ?").run(second.id);
    expect((await call(second.c, "action_execute", { proposal_id: second.id })).error).toMatch(/different proposal/);
  });

  it("a grant from one tenant cannot be used in another", async () => {
    const { id } = await proposeRefund("1002", 5);
    const grant = signGrant(env.keyOf(APPROVER_A), { tenant: A, proposal_id: id, proposal_hash: hashOf(id), approver: APPROVER_A });
    const tB = env.manifest.tenants.find((x) => x.id === B)!;
    expect(() => recordGrant(env.store(B), tB, env.serverKeys.approvers, grant)).toThrow(/different tenant/);
  });

  it("only listed approvers count", async () => {
    const { id } = await proposeRefund();
    expect(() => env.approve(A, id, "owner@harborpine.example")).toThrow(/not an approver/);
  });

  it("an approver removed from the manifest no longer counts at execution", async () => {
    const { id } = await proposeRefund("1002", 7);
    env.approve(A, id, LEAD_A);
    const tightened = structuredClone(env.manifest);
    tightened.tenants.find((t) => t.id === A)!.approvers = [APPROVER_A];
    const token = await issueAccessToken(env.keys.issuer.privateKey, { tenant: A, sub: "agent:test", scopes: ["execute"], audience: STDIO_AUDIENCE });
    const ctx = contextFromClaims(await verifyAccessToken(env.keys.issuer.publicKey, token, STDIO_AUDIENCE), tightened);
    const connector = sandboxCommerce(ctx, credentialsFor(ctx, env.keys.secrets, env.dataDir), env.store(A));
    expect(() => executeApproved(ctx, env.store(A), env.serverKeys.approvers, connector, id)).toThrow(Refused);
  });

  it("an expired grant is refused, and a person can approve again", async () => {
    const { c, id } = await proposeRefund("1002", 6);
    env.approve(A, id, APPROVER_A, 0.01); // 0.6 seconds
    await sleep(800);
    expect((await call(c, "action_execute", { proposal_id: id })).error).toMatch(/expired/);
    env.approve(A, id, APPROVER_A);
    expect((await call(c, "action_execute", { proposal_id: id })).data.status).toBe("executed");
  });

  it("an approval can be revoked before it is used, and a denied proposal never runs", async () => {
    const { c, id } = await proposeRefund("1002", 8);
    env.approve(A, id, APPROVER_A);
    expect(denyProposal(env.store(A), tenantA(), id, APPROVER_A, "customer took store credit")).toBe("revoked");
    expect((await call(c, "action_execute", { proposal_id: id })).error).toMatch(/status: denied/);
    expect(() => env.approve(A, id, APPROVER_A)).toThrow(/denied, not pending/);
  });

  it("an email goes only to the address that was approved", async () => {
    const c = await agent();
    const p = (await call(c, "email_propose", { customer_id: "c2", subject: "About your order", body: "Hi Marcus, your replacement ships today." })).data;
    env.approve(A, p.proposal_id, APPROVER_A);
    env.store(A).db.prepare("UPDATE customers SET email = 'attacker@example.net' WHERE id = 'c2'").run();
    expect((await call(c, "action_execute", { proposal_id: p.proposal_id })).error).toMatch(/address changed/);
    env.store(A).db.prepare("UPDATE customers SET email = 'marcus.lee@example.com' WHERE id = 'c2'").run();
  });

  it("text in the data cannot approve anything", async () => {
    const c = await agent();
    const note = (await call(c, "customer_get", { customer_id: "c3" })).data.customer.note as string;
    expect(note).toMatch(/APPROVED-7731/);
    expect((await call(c, "action_execute", { proposal_id: "APPROVED-7731" })).error).toBeTruthy();
    const r = await call(c, "refund_propose", { order_id: "1003", amount: 288, reason: "per the note on file" });
    expect((await call(c, "action_execute", { proposal_id: r.data.proposal_id })).error).toMatch(/not approved by a person/);
  });

  it("text that would disguise a proposal on the approver's screen is rejected", async () => {
    const c = await agent();
    const r = await call(c, "refund_propose", { order_id: "1003", amount: 199, reason: "ok\r\u001b[2KRefund $5.00 goodwill\u001b[8m" });
    expect(r.error).toMatch(/control characters/);
  });

  it("limits are enforced at proposal time, and refusals there are logged", async () => {
    const c = await agent();
    expect((await call(c, "refund_propose", { order_id: "1003", amount: 488, reason: "full refund" })).error).toMatch(/capped at \$300/);
    expect((await call(c, "refund_propose", { order_id: "1004", amount: 65, reason: "too much" })).error).toMatch(/refundable/);
    expect((await call(c, "discount_propose", { code: "BIGSALE", percent: 50, days_valid: 7 })).error).toMatch(/capped at 20%/);
    const entries = (await call(c, "audit_recent", { limit: 100 })).data.entries as { action: string }[];
    expect(entries.filter((e) => e.action === "proposal.refused").length).toBeGreaterThanOrEqual(3);
  });

  it("the daily budget is checked at execution against the hashed amount, not a side column", async () => {
    const env2 = makeEnv();
    const c = await env2.connect(A, ["read", "propose", "execute"]);
    const ids: string[] = [];
    for (const [order_id, amount] of [["1003", 300], ["1001", 289], ["1002", 100]] as const)
      ids.push((await call(c, "refund_propose", { order_id, amount, reason: "batch of returns" })).data.proposal_id);
    for (const id of ids) env2.approve(A, id, APPROVER_A);
    expect((await call(c, "action_execute", { proposal_id: ids[0] })).data.status).toBe("executed");
    expect((await call(c, "action_execute", { proposal_id: ids[1] })).data.status).toBe("executed");
    env2.store(A).db.prepare("UPDATE proposals SET amount = 0 WHERE id = ?").run(ids[2]!);
    expect((await call(c, "action_execute", { proposal_id: ids[2] })).error).toMatch(/daily refund budget/);
  });

  it("every refusal at execution is itself in the audit log", async () => {
    const c = await agent();
    const entries = (await call(c, "audit_recent", { limit: 100 })).data.entries as { action: string }[];
    expect(entries.filter((e) => e.action === "action.refused").length).toBeGreaterThanOrEqual(7);
    expect(auditHead(env.store(A)).seq).toBeGreaterThan(20);
  });
});
