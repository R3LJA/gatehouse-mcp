import { describe, expect, it } from "vitest";
import { A, makeEnv } from "../helpers.js";

const env = makeEnv();
const READ_TOOLS = ["audit_recent", "customer_get", "memory_recall", "order_get", "orders_search", "products_search", "proposals_list"];
const PROPOSE_TOOLS = ["discount_propose", "email_propose", "memory_save", "product_publish_propose", "refund_propose"];

describe("tool surface follows the token's scopes", () => {
  it("a read-only token sees only read tools", async () => {
    const c = await env.connect(A, ["read"]);
    const names = (await c.listTools()).tools.map((t) => t.name).sort();
    expect(names).toEqual(READ_TOOLS);
  });

  it("a read+propose token can draft actions but has no way to execute them", async () => {
    const c = await env.connect(A, ["read", "propose"]);
    const names = (await c.listTools()).tools.map((t) => t.name).sort();
    expect(names).toEqual([...READ_TOOLS, ...PROPOSE_TOOLS].sort());
    expect(names).not.toContain("action_execute");
  });

  it("only the execute scope adds action_execute", async () => {
    const c = await env.connect(A, ["read", "propose", "execute"]);
    expect((await c.listTools()).tools.map((t) => t.name)).toContain("action_execute");
  });

  it("no tool takes a tenant: which company a call reaches comes from the credential only", async () => {
    const c = await env.connect(A, ["read", "propose", "execute"]);
    for (const tool of (await c.listTools()).tools) {
      const props = Object.keys((tool.inputSchema.properties ?? {}) as Record<string, unknown>);
      for (const p of props) expect(p, `${tool.name}.${p}`).not.toMatch(/tenant|company|org|account_id|store_id/i);
    }
  });

  it("read tools say they are read-only; write-path tools do not", async () => {
    const c = await env.connect(A, ["read", "propose", "execute"]);
    for (const tool of (await c.listTools()).tools) {
      const readOnly = tool.annotations?.readOnlyHint === true;
      expect(readOnly, tool.name).toBe(READ_TOOLS.includes(tool.name));
    }
    const exec = (await c.listTools()).tools.find((t) => t.name === "action_execute");
    expect(exec?.annotations?.destructiveHint).toBe(true);
  });
});
