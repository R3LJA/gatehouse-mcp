#!/usr/bin/env node
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";
import { denyProposal, recordGrant, signGrant } from "./approvals/grants.js";
import { getProposal, listProposals } from "./approvals/proposals.js";
import { appendAnchor, auditHead, readAnchors, readAudit, signAnchor, verifyAudit } from "./audit/log.js";
import { issueAccessToken } from "./auth/tokens.js";
import { dataDir, keysDir, loadManifest, type Tenant } from "./config.js";
import { createGateway } from "./http.js";
import { addApprover, approverDir, loadApproverKey, loadIssuerKey, loadServerKeys, writeKeys } from "./keys.js";
import { writeCredentials } from "./secrets/credentials.js";
import { serveStdio, STDIO_AUDIENCE } from "./stdio.js";
import { operatorStore } from "./store/db.js";
import { seedTenant } from "./store/seed.js";
import type { Scope } from "./tenancy/context.js";

const HELP = `gatehouse: a multi-tenant MCP server where every write waits for a human

  keys init                                   issuer and secrets keys in ./keys; one key per approver
                                              (private: ~/.gatehouse/approvers, public: ./keys/approvers)
  keys add-approver --as EMAIL                key for an approver added to the manifest later
  seed                                        load the demo tenants and their sandbox credentials
  token --tenant ID --sub NAME --scopes read,propose[,execute] [--stdio | --aud URL] [--ttl SECONDS]
  serve-http [--port 8787] [--base-url URL]   Streamable HTTP gateway (multi-tenant)
  serve-stdio                                 one tenant over stdio (token in GATEHOUSE_TOKEN)
  proposals --tenant ID [--status pending]    what is waiting for a person
  approve --tenant ID --proposal P --as EMAIL [--yes] [--ttl MINUTES]
  deny --tenant ID --proposal P --as EMAIL --reason TEXT      (also revokes an unexecuted approval)
  audit --tenant ID [--verify] [--limit N]
  audit anchor --tenant ID --as EMAIL         sign the current head of the audit chain
`;

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    tenant: { type: "string" },
    sub: { type: "string" },
    scopes: { type: "string" },
    stdio: { type: "boolean" },
    aud: { type: "string" },
    ttl: { type: "string" },
    port: { type: "string" },
    "base-url": { type: "string" },
    status: { type: "string" },
    proposal: { type: "string" },
    as: { type: "string" },
    yes: { type: "boolean" },
    reason: { type: "string" },
    verify: { type: "boolean" },
    limit: { type: "string" },
    help: { type: "boolean", short: "h" },
  },
});

const fail = (msg: string): never => {
  console.error(`gatehouse: ${msg}`);
  process.exit(1);
};
const need = (v: string | undefined, name: string) => v ?? fail(`--${name} is required`);

function tenantArg(): Tenant {
  const id = need(values.tenant, "tenant");
  return loadManifest().tenants.find((t) => t.id === id) ?? fail(`unknown tenant ${id}`);
}

async function main() {
  const [cmd, sub] = positionals;
  if (!cmd || values.help) return console.log(HELP);

  switch (cmd) {
    case "keys": {
      if (sub === "add-approver") {
        addApprover(need(values.as, "as"));
        return console.log(`approver key for ${values.as}: private in ${approverDir()}, public in ${keysDir()}/approvers`);
      }
      if (sub !== "init") fail("usage: gatehouse keys init | keys add-approver --as EMAIL");
      const emails = [...new Set(loadManifest().tenants.flatMap((t) => t.approvers))];
      writeKeys(emails);
      return console.log(`server keys in ${keysDir()}; ${emails.length} approver keys in ${approverDir()} (keep that folder off agent hosts)`);
    }

    case "seed": {
      const { secrets } = loadServerKeys();
      for (const t of loadManifest().tenants) {
        const seeded = seedTenant(operatorStore(t.id));
        if (!existsSync(path.join(dataDir(), t.id, "credentials.enc")))
          writeCredentials(secrets, t.id, { commerce_api_key: `sk_test_${t.id}_${randomBytes(12).toString("hex")}` });
        console.log(`${t.id}: ${seeded ? "seeded" : "already has data"}`);
      }
      return;
    }

    case "token": {
      const t = tenantArg();
      const scopes = need(values.scopes, "scopes").split(",").map((s) => s.trim()) as Scope[];
      const audience = values.stdio ? STDIO_AUDIENCE : (values.aud ?? `http://localhost:${values.port ?? 8787}/mcp`);
      const token = await issueAccessToken(loadIssuerKey(), { tenant: t.id, sub: need(values.sub, "sub"), scopes, audience, ttlSeconds: Number(values.ttl ?? 3600) });
      return console.log(token);
    }

    case "serve-http": {
      const port = Number(values.port ?? process.env.PORT ?? 8787);
      const baseUrl = values["base-url"] ?? process.env.GATEHOUSE_BASE_URL ?? `http://localhost:${port}`;
      const gateway = createGateway({ manifest: loadManifest(), keys: loadServerKeys(), dataDir: dataDir() }, { baseUrl, allowedHosts: [new URL(baseUrl).host, `localhost:${port}`, `127.0.0.1:${port}`] });
      gateway.listen(port, () => console.error(`[gatehouse] http on ${baseUrl}/mcp`));
      return;
    }

    case "serve-stdio":
      return serveStdio({ manifest: loadManifest(), keys: loadServerKeys(), dataDir: dataDir() }, process.env.GATEHOUSE_TOKEN);

    case "proposals": {
      const t = tenantArg();
      const rows = listProposals(operatorStore(t.id), values.status as never);
      if (!rows.length) return console.log("no proposals");
      for (const p of rows) console.log(`${p.id}  ${p.status.padEnd(8)}  ${p.created_at.slice(0, 16)}  ${p.summary}`);
      return;
    }

    case "approve": {
      const t = tenantArg();
      const store = operatorStore(t.id);
      const p = getProposal(store, need(values.proposal, "proposal")) ?? fail("no such proposal in this tenant");
      const approver = need(values.as, "as");
      if (!t.approvers.includes(approver)) fail(`${approver} is not an approver for ${t.name}`);
      // show what is signed, from the hashed arguments, with any control characters escaped
      const clean = (x: string) => x.replace(/[\u0000-\u001f\u007f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
      console.log(`\n${t.name} · ${p.id} · ${p.status}\n${clean(p.summary)}\n\nexact action (this is what you sign): ${p.tool} ${JSON.stringify(p.args, null, 2)}\nproposed by ${clean(p.created_by)} at ${p.created_at}\nhash ${p.hash}\n`);
      if (!values.yes) {
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        const answer = await rl.question(`Approve as ${approver}? [y/N] `);
        rl.close();
        if (answer.trim().toLowerCase() !== "y") return console.log("not approved");
      }
      const key = loadApproverKey(approver);
      const head = auditHead(store);
      const grant = signGrant(key, { tenant: t.id, proposal_id: p.id, proposal_hash: p.hash, approver, audit_head: head }, Number(values.ttl ?? 30));
      recordGrant(store, t, loadServerKeys().approvers, grant);
      // the approval also anchors the audit chain, on the approval side
      appendAnchor(approverDir(), signAnchor(key, t.id, head, approver));
      return console.log(`approved ${p.id}; the grant expires ${grant.body.expires_at} and works once`);
    }

    case "deny": {
      const t = tenantArg();
      const kind = denyProposal(operatorStore(t.id), t, need(values.proposal, "proposal"), need(values.as, "as"), need(values.reason, "reason"));
      return console.log(kind === "revoked" ? "approval revoked; it can no longer be executed" : "denied");
    }

    case "audit": {
      const t = tenantArg();
      const store = operatorStore(t.id);
      if (sub === "anchor") {
        const by = need(values.as, "as");
        if (!t.approvers.includes(by)) fail(`${by} is not an approver for ${t.name}`);
        const head = auditHead(store);
        appendAnchor(approverDir(), signAnchor(loadApproverKey(by), t.id, head, by));
        return console.log(`anchored ${t.id} at entry ${head.seq}`);
      }
      if (values.verify) {
        const { heads, invalid } = readAnchors(approverDir(), t.id, loadServerKeys().approvers, t.approvers);
        if (invalid) console.error(`warning: ${invalid} anchor(s) in the anchor file do not verify`);
        const r = verifyAudit(store, heads);
        if (!r.ok) fail(`audit chain broken at entry ${r.brokenAt}: ${r.reason}`);
        return console.log(`audit chain intact: ${r.ok && r.entries} entries, ${r.ok && r.anchors} approver-signed anchors hold`);
      }
      for (const e of readAudit(store, Number(values.limit ?? 20)).reverse()) console.log(`${String(e.seq).padStart(4)}  ${e.at.slice(0, 19)}  ${e.actor.padEnd(30)}  ${e.action}  ${JSON.stringify(e.detail)}`);
      return;
    }

    default:
      fail(`unknown command ${cmd}\n\n${HELP}`);
  }
}

main().catch((err) => fail(err instanceof Error ? err.message : String(err)));
