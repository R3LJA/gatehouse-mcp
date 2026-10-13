import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { grantSignatureValid, grantTimeProblem, signGrant } from "../../src/approvals/grants.js";
import { proposalHash } from "../../src/approvals/proposals.js";
import { canonical } from "../../src/canonical.js";

describe("canonical JSON", () => {
  it("is independent of key order", () => {
    expect(canonical({ b: 1, a: { d: [1, { y: 2, x: 1 }], c: "z" } })).toBe(canonical({ a: { c: "z", d: [1, { x: 1, y: 2 }] }, b: 1 }));
  });
  it("refuses values that have no stable form", () => {
    expect(() => canonical({ a: Number.NaN })).toThrow();
  });
});

describe("proposal hash", () => {
  const p = { id: "p_0123456789", tool: "refund" as const, args: { order_id: "1001", amount: 10, reason: "late" }, created_at: "2026-10-13T10:00:00.000Z" };
  it("changes with any argument, the tool, or the tenant", () => {
    const h = proposalHash("fernhill", p);
    expect(proposalHash("fernhill", { ...p, args: { ...p.args, amount: 11 } })).not.toBe(h);
    expect(proposalHash("fernhill", { ...p, tool: "discount" })).not.toBe(h);
    expect(proposalHash("harbor-pine", p)).not.toBe(h);
  });
});

describe("grant signatures", () => {
  const maya = generateKeyPairSync("ed25519");
  const lead = generateKeyPairSync("ed25519");
  const registry = new Map([
    ["maya@fernhill.example", maya.publicKey],
    ["ops-lead@fernhill.example", lead.publicKey],
  ]);
  const g = signGrant(maya.privateKey, { tenant: "fernhill", proposal_id: "p_0123456789", proposal_hash: "a".repeat(64), approver: "maya@fernhill.example" });
  it("verify against the named approver's own key", () => expect(grantSignatureValid(registry, g)).toBe(true));
  it("fail when any field is edited", () => {
    for (const field of ["tenant", "proposal_id", "proposal_hash", "expires_at", "nonce"] as const)
      expect(grantSignatureValid(registry, { ...g, body: { ...g.body, [field]: `${g.body[field]}x` } }), field).toBe(false);
  });
  it("fail when one approver signs in another approver's name", () => {
    const impersonation = signGrant(maya.privateKey, { tenant: "fernhill", proposal_id: "p_0123456789", proposal_hash: "a".repeat(64), approver: "ops-lead@fernhill.example" });
    expect(grantSignatureValid(registry, impersonation)).toBe(false);
  });
  it("fail for an approver with no registered key", () => {
    const stranger = signGrant(generateKeyPairSync("ed25519").privateKey, { tenant: "fernhill", proposal_id: "p_0123456789", proposal_hash: "a".repeat(64), approver: "x@example.com" });
    expect(grantSignatureValid(registry, stranger)).toBe(false);
  });
});

describe("grant times", () => {
  const base = signGrant(generateKeyPairSync("ed25519").privateKey, { tenant: "t", proposal_id: "p_0123456789", proposal_hash: "a".repeat(64), approver: "a@b.co" }).body;
  it("reject dates that do not parse, instead of treating them as never expiring", () => {
    expect(grantTimeProblem({ ...base, expires_at: "never" })).toMatch(/not valid dates/);
  });
  it("reject open-ended and future-dated grants", () => {
    expect(grantTimeProblem({ ...base, expires_at: new Date(Date.now() + 3 * 86_400_000).toISOString() })).toMatch(/longer than/);
    expect(grantTimeProblem({ ...base, issued_at: new Date(Date.now() + 3_600_000).toISOString(), expires_at: new Date(Date.now() + 7_200_000).toISOString() })).toMatch(/future/);
  });
});
