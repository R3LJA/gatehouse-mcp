import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { recordGrant, signGrant } from "../src/approvals/grants.js";
import { auditHead } from "../src/audit/log.js";
import { getProposal } from "../src/approvals/proposals.js";
import { issueAccessToken, verifyAccessToken } from "../src/auth/tokens.js";
import { loadManifest } from "../src/config.js";
import { generateKeys, serverKeysFrom } from "../src/keys.js";
import { writeCredentials } from "../src/secrets/credentials.js";
import { buildServer, type Deps } from "../src/server.js";
import { operatorStore } from "../src/store/db.js";
import { seedTenant } from "../src/store/seed.js";
import { contextFromClaims, type Scope, type TenantContext } from "../src/tenancy/context.js";
import { STDIO_AUDIENCE } from "../src/stdio.js";

export const A = "fernhill";
export const B = "harbor-pine";
export const APPROVER_A = "maya@fernhill.example";
export const APPROVER_B = "owner@harborpine.example";

// A fresh world per test file: its own keys, its own data directory, both tenants seeded.
export function makeEnv() {
  const dataDir = mkdtempSync(path.join(tmpdir(), "gatehouse-"));
  const manifest = loadManifest(path.resolve("config/tenants.json"));
  const k = generateKeys([...new Set(manifest.tenants.flatMap((t) => t.approvers))]);
  const keys = serverKeysFrom(k);
  for (const t of manifest.tenants) {
    seedTenant(operatorStore(t.id, dataDir));
    writeCredentials(k.secrets, t.id, { commerce_api_key: `sk_test_${t.id}_${t.id.length}abc` }, dataDir);
  }
  const deps: Deps = { manifest, keys, dataDir };

  // A context the only way the agent path can get one: from a verified token.
  async function context(tenant: string, scopes: Scope[], sub = "agent:test"): Promise<TenantContext> {
    const token = await issueAccessToken(k.issuer.privateKey, { tenant, sub, scopes, audience: STDIO_AUDIENCE });
    return contextFromClaims(await verifyAccessToken(k.issuer.publicKey, token, STDIO_AUDIENCE), manifest);
  }

  // The full agent path: issue a token, verify it, build the context, connect a real MCP client.
  async function connect(tenant: string, scopes: Scope[], sub = "agent:test") {
    const ctx = await context(tenant, scopes, sub);
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await buildServer(ctx, deps).connect(serverSide);
    const client = new Client({ name: "test", version: "0" });
    await client.connect(clientSide);
    return client;
  }

  // The human side: that approver signs a grant with their own key and hands it to the approval channel.
  const keyOf = (email: string) => {
    const pair = k.approvers.get(email);
    if (!pair) throw new Error(`no key for ${email}`);
    return pair.privateKey;
  };
  function approve(tenant: string, proposalId: string, approver: string, ttlMinutes = 30) {
    const store = operatorStore(tenant, dataDir);
    const p = getProposal(store, proposalId);
    if (!p) throw new Error("no such proposal");
    const t = manifest.tenants.find((x) => x.id === tenant)!;
    const grant = signGrant(keyOf(approver), { tenant, proposal_id: p.id, proposal_hash: p.hash, approver, audit_head: auditHead(store) }, ttlMinutes);
    recordGrant(store, t, keys.approvers, grant);
    return grant;
  }

  return { dataDir, deps, keys: k, serverKeys: keys, manifest, connect, context, approve, keyOf, store: (tenant: string) => operatorStore(tenant, dataDir) };
}

type CallResult = { isError?: boolean; content: { type: string; text?: string }[] };

// Calls a tool and returns the parsed JSON body, or the error text when the server refused.
export async function call(client: Client, name: string, args: Record<string, unknown> = {}) {
  const r = (await client.callTool({ name, arguments: args })) as CallResult;
  const text = r.content.map((c) => c.text ?? "").join("");
  if (r.isError) return { error: text, data: undefined as never };
  return { error: undefined, data: JSON.parse(text) };
}
