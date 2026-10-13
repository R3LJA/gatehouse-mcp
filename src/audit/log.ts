import { sign, verify, type KeyObject } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { canonical, sha256 } from "../canonical.js";
import { now, type TenantStore } from "../store/db.js";

// Append-only, hash-chained audit log, one chain per tenant. Each entry commits to the one
// before it and to the tenant id.
//
// A chain alone only catches clumsy edits: someone with write access to the database could
// rewrite an entry and recompute every hash after it. So the chain is anchored outside the
// agent path: every time a person approves something, the approval channel signs the current
// head (sequence number and hash) with that person's key and appends it to a file on its side.
// History before an anchor cannot be rewritten or truncated without verify noticing.
export type AuditEntry = { seq: number; at: string; actor: string; action: string; detail: Record<string, unknown>; prev_hash: string; hash: string };
export type Head = { seq: number; hash: string };

const GENESIS = "0".repeat(64);

function entryHash(tenantId: string, e: Omit<AuditEntry, "hash">) {
  return sha256(e.prev_hash + canonical({ tenant: tenantId, seq: e.seq, at: e.at, actor: e.actor, action: e.action, detail: e.detail }));
}

export function audit(store: TenantStore, actor: string, action: string, detail: Record<string, unknown> = {}): AuditEntry {
  // inside a write transaction, so two processes can never take the same sequence number
  return store.tx(() => {
    const last = store.db.prepare("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").get() as Head | undefined;
    const base = { seq: (last?.seq ?? 0) + 1, at: now(), actor, action, detail, prev_hash: last?.hash ?? GENESIS };
    const entry = { ...base, hash: entryHash(store.tenantId, base) };
    store.db
      .prepare("INSERT INTO audit (seq, at, actor, action, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(entry.seq, entry.at, entry.actor, entry.action, canonical(entry.detail), entry.prev_hash, entry.hash);
    return entry;
  });
}

export function auditHead(store: TenantStore): Head {
  return (store.db.prepare("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").get() as Head | undefined) ?? { seq: 0, hash: GENESIS };
}

export function readAudit(store: TenantStore, limit = 50): AuditEntry[] {
  const rows = store.db.prepare("SELECT * FROM audit ORDER BY seq DESC LIMIT ?").all(limit) as Array<Omit<AuditEntry, "detail"> & { detail: string }>;
  return rows.map((r) => ({ ...r, detail: JSON.parse(r.detail) }));
}

export type VerifyResult = { ok: true; entries: number; anchors: number } | { ok: false; brokenAt: number; reason: string };

export function verifyAudit(store: TenantStore, anchors: Head[] = []): VerifyResult {
  const rows = store.db.prepare("SELECT * FROM audit ORDER BY seq ASC").all() as Array<Omit<AuditEntry, "detail"> & { detail: string }>;
  let prev = GENESIS;
  let expectSeq = 1;
  for (const r of rows) {
    if (r.seq !== expectSeq) return { ok: false, brokenAt: expectSeq, reason: "a record is missing" };
    if (r.prev_hash !== prev) return { ok: false, brokenAt: r.seq, reason: "the link to the previous record does not match" };
    if (entryHash(store.tenantId, { ...r, detail: JSON.parse(r.detail) }) !== r.hash) return { ok: false, brokenAt: r.seq, reason: "the record was changed after it was written" };
    prev = r.hash;
    expectSeq++;
  }
  const bySeq = new Map(rows.map((r) => [r.seq, r.hash]));
  for (const a of [...anchors].sort((x, y) => x.seq - y.seq)) {
    if (a.seq === 0) continue;
    const h = bySeq.get(a.seq);
    if (h === undefined) return { ok: false, brokenAt: a.seq, reason: "records signed off by an approver are gone (the log was truncated)" };
    if (h !== a.hash) return { ok: false, brokenAt: a.seq, reason: "history before an approver-signed anchor was rewritten" };
  }
  return { ok: true, entries: rows.length, anchors: anchors.length };
}

// ---------- anchors: signed by an approver, kept on the approval side ----------

export type Anchor = { v: 1; tenant: string; seq: number; hash: string; at: string; by: string };
export type SignedAnchor = { body: Anchor; signature: string };

export function signAnchor(approverKey: KeyObject, tenant: string, head: Head, by: string): SignedAnchor {
  const body: Anchor = { v: 1, tenant, seq: head.seq, hash: head.hash, at: now(), by };
  return { body, signature: sign(null, Buffer.from(canonical(body)), approverKey).toString("base64") };
}

export const anchorFile = (dir: string, tenant: string) => path.join(dir, "anchors", `${tenant}.jsonl`);

export function appendAnchor(dir: string, a: SignedAnchor) {
  mkdirSync(path.join(dir, "anchors"), { recursive: true, mode: 0o700 });
  appendFileSync(anchorFile(dir, a.body.tenant), JSON.stringify(a) + "\n", { mode: 0o600 });
}

// Only anchors whose signature verifies against a listed approver of this tenant count; the rest
// are reported, because a forged or edited anchor file is itself a finding.
export function readAnchors(dir: string, tenant: string, approverKeys: ReadonlyMap<string, KeyObject>, listed: readonly string[]): { heads: Head[]; invalid: number } {
  const file = anchorFile(dir, tenant);
  if (!existsSync(file)) return { heads: [], invalid: 0 };
  const heads: Head[] = [];
  let invalid = 0;
  for (const line of readFileSync(file, "utf8").split("\n").filter(Boolean)) {
    try {
      const a = JSON.parse(line) as SignedAnchor;
      const key = approverKeys.get(a.body.by);
      const good = !!key && listed.includes(a.body.by) && a.body.tenant === tenant && verify(null, Buffer.from(canonical(a.body)), key, Buffer.from(a.signature, "base64"));
      if (good) heads.push({ seq: a.body.seq, hash: a.body.hash });
      else invalid++;
    } catch {
      invalid++;
    }
  }
  return { heads, invalid };
}
