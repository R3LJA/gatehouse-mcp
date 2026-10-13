import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { dataDir } from "../config.js";
import type { TenantContext } from "../tenancy/context.js";

// One SQLite file per tenant. Isolation is physical: a query in one tenant's store has no way
// to name a row in another's, even when both use the same ids (both seed order "1001").
const SCHEMA = `
CREATE TABLE IF NOT EXISTS customers (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, note TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, title TEXT NOT NULL, price REAL NOT NULL, status TEXT NOT NULL, description TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id), placed_at TEXT NOT NULL, status TEXT NOT NULL, total REAL NOT NULL, refunded REAL NOT NULL DEFAULT 0, items TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memory (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS proposals (
  id TEXT PRIMARY KEY, tool TEXT NOT NULL, args TEXT NOT NULL, summary TEXT NOT NULL, amount REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, created_by TEXT NOT NULL, hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'executed')),
  decided_at TEXT, decided_by TEXT, executed_at TEXT, result TEXT
);
CREATE TABLE IF NOT EXISTS grants (proposal_id TEXT PRIMARY KEY REFERENCES proposals(id), body TEXT NOT NULL, signature TEXT NOT NULL, received_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS used_nonces (nonce TEXT PRIMARY KEY, used_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS refunds (id TEXT PRIMARY KEY, order_id TEXT NOT NULL, amount REAL NOT NULL, at TEXT NOT NULL, proposal_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS discounts (code TEXT PRIMARY KEY, percent INTEGER NOT NULL, expires_at TEXT NOT NULL, proposal_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS published (product_id TEXT NOT NULL, description TEXT NOT NULL, at TEXT NOT NULL, proposal_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, to_email TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL, at TEXT NOT NULL, proposal_id TEXT NOT NULL);
`;

export type TenantStore = { readonly tenantId: string; readonly db: DatabaseSync; tx<T>(fn: () => T): T };

const open = new Map<string, TenantStore>();

function openFile(tenantId: string, dir: string): TenantStore {
  const file = path.join(dir, tenantId, "store.db");
  const cached = open.get(file);
  if (cached) return cached;
  mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 3000;");
  db.exec(SCHEMA);
  let depth = 0;
  const store: TenantStore = {
    tenantId,
    db,
    // BEGIN IMMEDIATE takes the write lock up front, so check-then-act (budgets, nonces, the next
    // audit sequence number) is atomic even across processes. Nested calls join the outer one.
    tx<T>(fn: () => T): T {
      if (depth > 0) return fn();
      db.exec("BEGIN IMMEDIATE");
      depth++;
      try {
        const out = fn();
        db.exec("COMMIT");
        return out;
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      } finally {
        depth--;
      }
    },
  };
  open.set(file, store);
  return store;
}

// The agent path: the store is chosen by the verified tenant context, never by an argument.
export function storeFor(ctx: TenantContext, dir = dataDir()): TenantStore {
  return openFile(ctx.tenant.id, dir);
}

// The operator path (CLI: seeding, approvals, audit checks). Not reachable from any MCP tool.
export function operatorStore(tenantId: string, dir = dataDir()): TenantStore {
  return openFile(tenantId, dir);
}

export function closeAll() {
  for (const s of open.values()) s.db.close();
  open.clear();
}

export const now = () => new Date().toISOString();
