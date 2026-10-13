import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { appendAnchor, auditHead, readAnchors, signAnchor, verifyAudit, type Head } from "../../src/audit/log.js";
import { canonical, sha256 } from "../../src/canonical.js";
import type { TenantStore } from "../../src/store/db.js";
import { A, APPROVER_A, B, call, makeEnv } from "../helpers.js";

// What an attacker with write access to the database would do: change a record, then recompute
// every hash after it so the chain is internally consistent again.
function rewriteAndRecompute(store: TenantStore, seq: number, detail: Record<string, unknown>) {
  const rows = store.db.prepare("SELECT * FROM audit ORDER BY seq").all() as { seq: number; at: string; actor: string; action: string; detail: string; prev_hash: string; hash: string }[];
  let prev = "0".repeat(64);
  for (const r of rows) {
    const d = r.seq === seq ? detail : JSON.parse(r.detail);
    const hash = sha256(prev + canonical({ tenant: store.tenantId, seq: r.seq, at: r.at, actor: r.actor, action: r.action, detail: d }));
    store.db.prepare("UPDATE audit SET detail = ?, prev_hash = ?, hash = ? WHERE seq = ?").run(canonical(d), prev, hash, r.seq);
    prev = hash;
  }
}

async function busyEnv() {
  const env = makeEnv();
  const anchors = mkdtempSync(path.join(tmpdir(), "gatehouse-anchors-"));
  const c = await env.connect(A, ["read", "propose", "execute"]);
  const p = (await call(c, "refund_propose", { order_id: "1002", amount: 15, reason: "late delivery" })).data.proposal_id;
  env.approve(A, p, APPROVER_A);
  await call(c, "action_execute", { proposal_id: p });
  // the approval channel anchors the head after the work it signed off
  appendAnchor(anchors, signAnchor(env.keyOf(APPROVER_A), A, auditHead(env.store(A)), APPROVER_A));
  await call(c, "memory_save", { key: "note", value: "x" });
  const heads = (): Head[] => readAnchors(anchors, A, env.serverKeys.approvers, env.manifest.tenants.find((t) => t.id === A)!.approvers).heads;
  return { env, anchors, heads };
}

describe("the audit log is tamper-evident", () => {
  it("an untouched chain verifies, anchors included", async () => {
    const { env, heads } = await busyEnv();
    expect(verifyAudit(env.store(A), heads())).toMatchObject({ ok: true, anchors: 1 });
  });

  it("a clumsy edit breaks the chain at that record", async () => {
    const { env, heads } = await busyEnv();
    env.store(A).db.prepare("UPDATE audit SET detail = ? WHERE seq = 3").run(JSON.stringify({ note: "nothing to see" }));
    expect(verifyAudit(env.store(A), heads())).toMatchObject({ ok: false, brokenAt: 3 });
  });

  it("an edit with every hash recomputed is caught by the approver-signed anchor", async () => {
    const { env, heads } = await busyEnv();
    const executed = env.store(A).db.prepare("SELECT seq FROM audit WHERE action = 'action.executed'").get() as { seq: number };
    rewriteAndRecompute(env.store(A), executed.seq, { note: "nothing happened" });
    expect(verifyAudit(env.store(A))).toMatchObject({ ok: true }); // the chain alone is fooled
    expect(verifyAudit(env.store(A), heads())).toMatchObject({ ok: false, reason: expect.stringMatching(/rewritten/) });
  });

  it("truncating the log back past an anchor is caught", async () => {
    const { env, heads } = await busyEnv();
    const head = heads()[0]!;
    env.store(A).db.prepare("DELETE FROM audit WHERE seq >= ?").run(head.seq);
    expect(verifyAudit(env.store(A))).toMatchObject({ ok: true }); // a shorter chain is still a chain
    expect(verifyAudit(env.store(A), heads())).toMatchObject({ ok: false, reason: expect.stringMatching(/truncated/) });
  });

  it("an anchor signed with the wrong key is reported, not trusted", async () => {
    const { env, anchors } = await busyEnv();
    appendAnchor(anchors, signAnchor(env.keyOf("owner@harborpine.example"), A, auditHead(env.store(A)), APPROVER_A));
    const r = readAnchors(anchors, A, env.serverKeys.approvers, env.manifest.tenants.find((t) => t.id === A)!.approvers);
    expect(r).toMatchObject({ invalid: 1 });
    expect(r.heads).toHaveLength(1);
  });

  it("a chain copied from one tenant into another does not verify there", async () => {
    const { env } = await busyEnv();
    const rows = env.store(A).db.prepare("SELECT * FROM audit ORDER BY seq").all() as Record<string, string | number>[];
    const b = env.store(B);
    b.db.prepare("DELETE FROM audit").run();
    const ins = b.db.prepare("INSERT INTO audit (seq, at, actor, action, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)");
    for (const r of rows) ins.run(r.seq!, r.at!, r.actor!, r.action!, r.detail!, r.prev_hash!, r.hash!);
    expect(verifyAudit(b)).toMatchObject({ ok: false, brokenAt: 1 });
  });
});
