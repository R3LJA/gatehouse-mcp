# Runbook

Commands assume the repo root, with `npm run cli --` in front of each one (or `npx gatehouse` after `npm run build`).

## First setup

```bash
npm ci
npm run cli -- keys init      # keys/issuer.*, keys/secrets.key, keys/approvers/*.pub; private approver keys in ~/.gatehouse/approvers
npm run cli -- seed           # demo tenants plus sealed sandbox credentials
npm test                      # the conformance suite must be green before anything ships
```

The private approver keys in `~/.gatehouse/approvers` (or `GATEHOUSE_APPROVER_DIR`) belong to the approval channel. Never copy them to a host that runs agents. The same folder holds `anchors/<tenant>.jsonl`, the signed audit anchors.

## Add a tenant

1. Add an entry to `config/tenants.json`: id, name, currency, approvers and limits. Merge it through review. Agents cannot change the manifest.
   For each new approver, run `npm run cli -- keys add-approver --as person@company.example` and deploy the new public key in `keys/approvers/`.
2. Seal its connector credentials. Use `writeCredentials` in a one-off script; `seed` does it for the demo tenants.
3. Issue the tenant's job tokens with the narrowest scopes the job needs:
   ```bash
   npm run cli -- token --tenant fernhill --sub agent:daily-ops --scopes read,propose --aud https://gatehouse.example.com/mcp --ttl 3600
   ```
4. Run `npm test`, then a smoke job against staging.

## Approve or deny

```bash
npm run cli -- proposals --tenant fernhill --status pending
npm run cli -- approve --tenant fernhill --proposal p_1a2b3c4d5e --as maya@fernhill.example
npm run cli -- deny --tenant fernhill --proposal p_1a2b3c4d5e --as maya@fernhill.example --reason "store credit instead"
```

- `approve` prints the exact action and its hash before asking, signs with that approver's own key, and appends a signed anchor of the audit head.
- A grant expires after 30 minutes (`--ttl` changes it; 24 hours at most) and works once. An expired approval can be approved again.
- `deny` on an approved proposal revokes the approval, as long as it has not been executed.
- A remote approval service posts signed grants to `POST /approvals` on the gateway.

## Check the audit log

```bash
npm run cli -- audit --tenant fernhill --limit 50
npm run cli -- audit --tenant fernhill --verify     # chain plus approver-signed anchors; exits 1 and names the first broken entry
npm run cli -- audit anchor --tenant fernhill --as maya@fernhill.example   # anchor the head now (e.g. nightly)
```

If verify fails:
1. Freeze the tenant's jobs: stop issuing tokens.
2. Keep the database file as evidence.
3. Restore from the last backup whose chain verifies.

## Rotate keys

| Key | What happens | Steps |
|---|---|---|
| Issuer | Every outstanding token stops working | Generate a new pair, deploy the public key, re-issue job tokens. |
| One approver's key | That person's grants and anchors stop verifying: their approved but unexecuted proposals need approving again, and their old anchors report as invalid | Run `keys add-approver` for them, deploy the new public key, then run `audit anchor` with the new key so the log is anchored again. |
| Secrets | Credentials must be re-sealed | Re-seal every tenant's credentials with the new key, then deploy. |

## Revoke an agent

Tokens are short-lived (1 hour by default). To cut a job off sooner, rotate the issuer key, or remove the tenant's tool scopes in the issuer.

## Before every deploy

- `npm run typecheck && npm test` must pass on Node 22 and 24. CI enforces this.
- If a change touches `src/approvals`, `src/http.ts` or `src/tenancy`, add a test to `test/conformance` that would have failed without it.
