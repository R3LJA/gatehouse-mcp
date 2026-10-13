import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { sandboxCommerce } from "../../src/connectors/commerce.js";
import { SEEDS } from "../../src/fixtures.js";
import { credentialsFor } from "../../src/secrets/credentials.js";
import { A, B, call, makeEnv } from "../helpers.js";

const env = makeEnv();
const emails = (tenant: string) => new Set(SEEDS[tenant]!.customers.map((c) => c.email));

describe("tenant isolation", () => {
  it("the same order id resolves to each tenant's own order", async () => {
    const a = await env.connect(A, ["read"]);
    const b = await env.connect(B, ["read"]);
    const oa = (await call(a, "order_get", { order_id: "1001" })).data.order;
    const ob = (await call(b, "order_get", { order_id: "1001" })).data.order;
    expect(oa.customer.name).toBe("Dana Whitfield");
    expect(ob.customer.name).toBe("Ines Okafor");
  });

  it("list tools never return another tenant's records", async () => {
    const a = await env.connect(A, ["read"]);
    const orders = (await call(a, "orders_search", { limit: 50 })).data.orders as { id: string; customer_id: string }[];
    expect(orders).toHaveLength(SEEDS[A]!.orders.length);
    const products = (await call(a, "products_search", {})).data.products as { id: string }[];
    const bProducts = new Set(SEEDS[B]!.products.map((p) => p.id));
    for (const p of products) expect(bProducts.has(p.id)).toBe(false);
  });

  it("another tenant's customer is simply not found (no existence leak)", async () => {
    const a = await env.connect(A, ["read"]);
    for (const email of emails(B)) {
      const r = await call(a, "customer_get", { email });
      expect(r.error).toMatch(/^Not found/);
    }
  });

  it("memory saved in one tenant never surfaces in another", async () => {
    const a = await env.connect(A, ["read", "propose"]);
    const b = await env.connect(B, ["read"]);
    await call(a, "memory_save", { key: "vip-dana", value: "Dana gets store credit, never cash refunds" });
    expect((await call(a, "memory_recall", { query: "dana" })).data.notes).toHaveLength(1);
    expect((await call(b, "memory_recall", { query: "dana" })).data.notes).toHaveLength(0);
    expect((await call(b, "memory_recall", {})).data.notes).toHaveLength(0);
  });

  it("a proposal made in one tenant is invisible and unexecutable from another", async () => {
    const a = await env.connect(A, ["read", "propose"]);
    const b = await env.connect(B, ["read", "propose", "execute"]);
    const p = (await call(a, "refund_propose", { order_id: "1002", amount: 20, reason: "late delivery" })).data;
    env.approve(A, p.proposal_id, "maya@fernhill.example");
    expect((await call(b, "proposals_list", {})).data.proposals).toHaveLength(0);
    expect((await call(b, "action_execute", { proposal_id: p.proposal_id })).error).toMatch(/no such proposal in this tenant/);
  });

  it("a sealed credential copied into another tenant's slot will not open", async () => {
    const fromB = path.join(env.dataDir, B, "credentials.enc");
    const intoA = path.join(env.dataDir, A, "credentials.enc");
    const original = readFileSync(intoA, "utf8");
    writeFileSync(intoA, readFileSync(fromB, "utf8"));
    const ctxA = await env.context(A, ["execute"]);
    expect(() => credentialsFor(ctxA, env.keys.secrets, env.dataDir)).toThrow(/could not be opened/);
    writeFileSync(intoA, original);
    expect(credentialsFor(ctxA, env.keys.secrets, env.dataDir).commerce_api_key).toMatch(/^sk_test_fernhill_/);
  });

  it("the connector refuses a key that belongs to another store", async () => {
    const ctxA = await env.context(A, ["execute"]);
    expect(() => sandboxCommerce(ctxA, { commerce_api_key: "sk_test_harbor-pine_x" }, env.store(A))).toThrow(/different store/);
  });

  it("each tenant keeps its own audit chain", async () => {
    const a = await env.connect(A, ["read"]);
    const b = await env.connect(B, ["read"]);
    const ea = (await call(a, "audit_recent", { limit: 100 })).data.entries as { action: string; detail: Record<string, unknown> }[];
    const eb = (await call(b, "audit_recent", { limit: 100 })).data.entries as { action: string; detail: Record<string, unknown> }[];
    expect(eb.some((e) => JSON.stringify(e).includes("vip-dana") || JSON.stringify(e).includes("late delivery"))).toBe(false);
    expect(ea.length).toBeGreaterThan(0);
  });
});
