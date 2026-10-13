import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { describe, expect, it } from "vitest";
import { issueAccessToken } from "../../src/auth/tokens.js";
import { loadIssuerKey, loadServerKeys, writeKeys } from "../../src/keys.js";
import { loadManifest } from "../../src/config.js";
import { writeCredentials } from "../../src/secrets/credentials.js";
import { operatorStore } from "../../src/store/db.js";
import { seedTenant } from "../../src/store/seed.js";
import { STDIO_AUDIENCE } from "../../src/stdio.js";
import { A, call } from "../helpers.js";

// The same server over stdio, as Claude Code or Claude Desktop would start it.
describe("stdio transport", () => {
  const root = mkdtempSync(path.join(tmpdir(), "gatehouse-stdio-"));
  const keysDir = path.join(root, "keys");
  const dataDir = path.join(root, "data");
  writeKeys(["maya@fernhill.example"], keysDir, path.join(root, "approvers"));
  const { secrets } = loadServerKeys(keysDir);
  for (const t of loadManifest(path.resolve("config/tenants.json")).tenants) {
    seedTenant(operatorStore(t.id, dataDir));
    writeCredentials(secrets, t.id, { commerce_api_key: `sk_test_${t.id}_stdio` }, dataDir);
  }

  async function start(token: string) {
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [path.resolve("node_modules/tsx/dist/cli.mjs"), path.resolve("src/cli.ts"), "serve-stdio"],
      env: { ...process.env, GATEHOUSE_TOKEN: token, GATEHOUSE_KEYS_DIR: keysDir, GATEHOUSE_DATA_DIR: dataDir, GATEHOUSE_MANIFEST: path.resolve("config/tenants.json") } as Record<string, string>,
      stderr: "pipe",
    });
    const client = new Client({ name: "stdio-test", version: "0" });
    await client.connect(transport);
    return client;
  }

  it("serves one tenant, chosen by the token", async () => {
    const token = await issueAccessToken(loadIssuerKey(keysDir), { tenant: A, sub: "agent:stdio", scopes: ["read"], audience: STDIO_AUDIENCE });
    const client = await start(token);
    expect((await client.listTools()).tools.map((t) => t.name)).toContain("orders_search");
    expect((await call(client, "order_get", { order_id: "1001" })).data.order.customer.name).toBe("Dana Whitfield");
    await client.close();
  });

  it("will not start with a token for another audience", async () => {
    const token = await issueAccessToken(loadIssuerKey(keysDir), { tenant: A, sub: "agent:stdio", scopes: ["read"], audience: "http://localhost:8787/mcp" });
    await expect(start(token)).rejects.toThrow();
  });
});
