import { request } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { signGrant } from "../../src/approvals/grants.js";
import { issueAccessToken } from "../../src/auth/tokens.js";
import { createGateway } from "../../src/http.js";
import { A, APPROVER_A, B, call, makeEnv } from "../helpers.js";

const env = makeEnv();
const port = 41000 + Math.floor(Math.random() * 2000);
const base = `http://127.0.0.1:${port}`;
const resource = `${base}/mcp`;
const gateway = createGateway(env.deps, { baseUrl: base, log: () => {} });

beforeAll(() => new Promise<void>((r) => gateway.listen(port, "127.0.0.1", () => r())));
afterAll(() => new Promise<void>((r) => gateway.close(() => r())));

const token = (tenant: string, scopes: ("read" | "propose" | "execute")[], audience = resource, ttlSeconds = 600) =>
  issueAccessToken(env.keys.issuer.privateKey, { tenant, sub: "agent:http-test", scopes, audience, ttlSeconds });

async function connect(bearer: string) {
  const transport = new StreamableHTTPClientTransport(new URL(resource), { requestInit: { headers: { Authorization: `Bearer ${bearer}` } } });
  const client = new Client({ name: "http-test", version: "0" });
  await client.connect(transport);
  return { client, transport };
}

const rpc = (bearer: string | null, body: unknown, extra: Record<string, string> = {}) =>
  fetch(resource, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(bearer ? { authorization: `Bearer ${bearer}` } : {}), ...extra },
    body: JSON.stringify(body),
  });

describe("Streamable HTTP gateway", () => {
  it("answers malformed JSON with 400, not a server error", async () => {
    const r = await fetch(resource, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${await token(A, ["read"])}` }, body: "{not json" });
    expect(r.status).toBe(400);
  });

  it("serves protected resource metadata", async () => {
    const r = await fetch(`${base}/.well-known/oauth-protected-resource`);
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ resource, scopes_supported: ["read", "propose", "execute"] });
  });

  it("answers a missing token with 401, a pointer to the metadata and the scopes, and no error code (RFC 6750)", async () => {
    const r = await rpc(null, { jsonrpc: "2.0", id: 1, method: "tools/list" });
    expect(r.status).toBe(401);
    const h = r.headers.get("www-authenticate") ?? "";
    expect(h).toContain(`resource_metadata="${base}/.well-known/oauth-protected-resource"`);
    expect(h).toContain('scope="read propose execute"');
    expect(h).not.toContain("error=");
  });

  it("answers a bad token with invalid_token", async () => {
    const r = await rpc(await token(A, ["read"], "gatehouse:stdio"), { jsonrpc: "2.0", id: 1, method: "tools/list" });
    expect(r.headers.get("www-authenticate")).toContain('error="invalid_token"');
  });

  it("refuses an oversized body with 413", async () => {
    const r = await fetch(resource, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${await token(A, ["read"])}` }, body: JSON.stringify({ pad: "x".repeat(1_100_000) }) });
    expect(r.status).toBe(413);
  });

  it("rejects a token minted for another audience", async () => {
    const r = await rpc(await token(A, ["read"], "gatehouse:stdio"), { jsonrpc: "2.0", id: 1, method: "tools/list" });
    expect(r.status).toBe(401);
  });

  it("rejects an expired token", async () => {
    const r = await rpc(await token(A, ["read"], resource, -5), { jsonrpc: "2.0", id: 1, method: "tools/list" });
    expect(r.status).toBe(401);
  });

  it("rejects a token for a tenant that does not exist", async () => {
    const r = await rpc(await token("ghost-co", ["read"]), { jsonrpc: "2.0", id: 1, method: "tools/list" });
    expect(r.status).toBe(401);
  });

  it("runs real MCP sessions, each pinned to its tenant", async () => {
    const a = await connect(await token(A, ["read"]));
    const b = await connect(await token(B, ["read"]));
    expect((await call(a.client, "order_get", { order_id: "1001" })).data.order.customer.name).toBe("Dana Whitfield");
    expect((await call(b.client, "order_get", { order_id: "1001" })).data.order.customer.name).toBe("Ines Okafor");
    await a.client.close();
    await b.client.close();
  });

  it("refuses a session id presented with another tenant's token", async () => {
    const a = await connect(await token(A, ["read"]));
    const sessionId = a.transport.sessionId!;
    expect(sessionId).toBeTruthy();
    const hijack = await rpc(await token(B, ["read"]), { jsonrpc: "2.0", id: 9, method: "tools/list" }, { "mcp-session-id": sessionId });
    expect(hijack.status).toBe(403);
    await a.client.close();
  });

  it("refuses a session reused with a token that has different scopes", async () => {
    const a = await connect(await token(A, ["read"]));
    const wider = await rpc(await token(A, ["read", "propose", "execute"]), { jsonrpc: "2.0", id: 9, method: "tools/list" }, { "mcp-session-id": a.transport.sessionId! });
    expect(wider.status).toBe(403);
    await a.client.close();
  });

  it("accepts grants only when the approver key signed them", async () => {
    const a = await connect(await token(A, ["read", "propose", "execute"]));
    const p = (await call(a.client, "refund_propose", { order_id: "1002", amount: 12, reason: "missing item" })).data;
    const body = { tenant: A, proposal_id: p.proposal_id, proposal_hash: p.hash, approver: APPROVER_A };
    const forged = signGrant(env.keyOf("ops-lead@fernhill.example"), body); // a real approver's key, but not Maya's
    const bad = await fetch(`${base}/approvals`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ grant: forged }) });
    expect(bad.status).toBe(400);
    const unknown = await fetch(`${base}/approvals`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ grant: { ...forged, body: { ...forged.body, tenant: "ghost-co" } } }) });
    expect(await unknown.json()).toEqual(await (await fetch(`${base}/approvals`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ grant: forged }) })).json());
    const good = await fetch(`${base}/approvals`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ grant: signGrant(env.keyOf(APPROVER_A), body) }) });
    expect(good.status).toBe(201);
    expect((await call(a.client, "action_execute", { proposal_id: p.proposal_id })).data.status).toBe("executed");
    await a.client.close();
  });
});

describe("gateway hardening", () => {
  const port2 = port + 1;
  const base2 = `http://127.0.0.1:${port2}`;
  const strict = createGateway(env.deps, { baseUrl: base2, allowedHosts: [`127.0.0.1:${port2}`], rateLimitPerMinute: 3, log: () => {} });
  beforeAll(() => new Promise<void>((r) => strict.listen(port2, "127.0.0.1", () => r())));
  afterAll(() => new Promise<void>((r) => strict.close(() => r())));

  it("refuses a request whose Host header is not allowed (DNS rebinding)", async () => {
    const status = await new Promise<number>((resolve, reject) => {
      const req = request({ host: "127.0.0.1", port: port2, path: "/healthz", headers: { host: "evil.example:80" } }, (res) => resolve(res.statusCode ?? 0));
      req.on("error", reject);
      req.end();
    });
    expect(status).toBe(403);
  });

  it("rate-limits a principal", async () => {
    const t = await issueAccessToken(env.keys.issuer.privateKey, { tenant: A, sub: "agent:flood", scopes: ["read"], audience: `${base2}/mcp` });
    const send = () => fetch(`${base2}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${t}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
    const statuses = [];
    for (let i = 0; i < 5; i++) statuses.push((await send()).status);
    expect(statuses).toContain(429);
  });
});
