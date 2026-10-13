import { SEEDS } from "../fixtures.js";
import { audit } from "../audit/log.js";
import type { TenantStore } from "./db.js";

// Loads the fictional fixtures into an empty tenant store. Safe to call twice.
export function seedTenant(store: TenantStore): boolean {
  const seed = SEEDS[store.tenantId];
  if (!seed) throw new Error(`no fixture data for tenant ${store.tenantId}`);
  const has = store.db.prepare("SELECT COUNT(*) AS n FROM customers").get() as { n: number };
  if (has.n > 0) return false;
  store.tx(() => {
    const c = store.db.prepare("INSERT INTO customers (id, name, email, note) VALUES (?, ?, ?, ?)");
    for (const x of seed.customers) c.run(x.id, x.name, x.email, x.note ?? "");
    const p = store.db.prepare("INSERT INTO products (id, title, price, status, description) VALUES (?, ?, ?, ?, ?)");
    for (const x of seed.products) p.run(x.id, x.title, x.price, x.status, x.description ?? "");
    const o = store.db.prepare("INSERT INTO orders (id, customer_id, placed_at, status, total, items) VALUES (?, ?, ?, ?, ?, ?)");
    for (const x of seed.orders) o.run(x.id, x.customer_id, x.placed_at, x.status, x.total, JSON.stringify(x.items));
    audit(store, "system", "tenant.seeded", { customers: seed.customers.length, products: seed.products.length, orders: seed.orders.length });
  });
  return true;
}
