import { now, type TenantStore } from "./db.js";

// Read queries. Every one runs against the store of the caller's tenant and nothing else.
export type Customer = { id: string; name: string; email: string; note: string };
export type Product = { id: string; title: string; price: number; status: string; description: string };
export type Order = { id: string; customer_id: string; placed_at: string; status: string; total: number; refunded: number; items: { sku: string; qty: number; price: number }[] };

type OrderRow = Omit<Order, "items"> & { items: string };
const order = (r: OrderRow): Order => ({ ...r, items: JSON.parse(r.items) });

export function searchOrders(s: TenantStore, f: { status?: string; customer_email?: string; limit?: number }): Order[] {
  const where: string[] = [];
  const params: (string | number)[] = [];
  if (f.status) {
    where.push("o.status = ?");
    params.push(f.status);
  }
  if (f.customer_email) {
    where.push("lower(c.email) = lower(?)");
    params.push(f.customer_email);
  }
  const sql = `SELECT o.* FROM orders o JOIN customers c ON c.id = o.customer_id ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY o.placed_at DESC LIMIT ?`;
  return (s.db.prepare(sql).all(...params, f.limit ?? 20) as OrderRow[]).map(order);
}

export function getOrder(s: TenantStore, id: string): (Order & { customer: Customer }) | null {
  const r = s.db.prepare("SELECT * FROM orders WHERE id = ?").get(id) as OrderRow | undefined;
  if (!r) return null;
  const customer = s.db.prepare("SELECT * FROM customers WHERE id = ?").get(r.customer_id) as Customer;
  return { ...order(r), customer };
}

export function getCustomer(s: TenantStore, by: { id?: string; email?: string }): (Customer & { orders: string[] }) | null {
  const c = (by.id
    ? s.db.prepare("SELECT * FROM customers WHERE id = ?").get(by.id)
    : s.db.prepare("SELECT * FROM customers WHERE lower(email) = lower(?)").get(by.email ?? "")) as Customer | undefined;
  if (!c) return null;
  const orders = (s.db.prepare("SELECT id FROM orders WHERE customer_id = ? ORDER BY placed_at DESC").all(c.id) as { id: string }[]).map((o) => o.id);
  return { ...c, orders };
}

export function searchProducts(s: TenantStore, f: { query?: string; status?: string }): Product[] {
  const where: string[] = [];
  const params: string[] = [];
  if (f.query) {
    where.push("(lower(title) LIKE ? OR lower(description) LIKE ?)");
    params.push(`%${f.query.toLowerCase()}%`, `%${f.query.toLowerCase()}%`);
  }
  if (f.status) {
    where.push("status = ?");
    params.push(f.status);
  }
  return s.db.prepare(`SELECT * FROM products ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY title LIMIT 50`).all(...params) as Product[];
}

export function discountExists(s: TenantStore, code: string): boolean {
  return !!s.db.prepare("SELECT 1 FROM discounts WHERE code = ?").get(code);
}

export function getProduct(s: TenantStore, id: string): Product | null {
  return (s.db.prepare("SELECT * FROM products WHERE id = ?").get(id) as Product | undefined) ?? null;
}

// Agent memory: short notes a job keeps between runs ("Ana prefers refunds as store credit").
// It lives in the tenant's own store, so one company's memory never surfaces in another's run.
export function recall(s: TenantStore, query?: string): { key: string; value: string; updated_at: string }[] {
  return (query
    ? s.db.prepare("SELECT key, value, updated_at FROM memory WHERE lower(key) LIKE ? OR lower(value) LIKE ? ORDER BY updated_at DESC LIMIT 20").all(`%${query.toLowerCase()}%`, `%${query.toLowerCase()}%`)
    : s.db.prepare("SELECT key, value, updated_at FROM memory ORDER BY updated_at DESC LIMIT 20").all()) as { key: string; value: string; updated_at: string }[];
}

export function remember(s: TenantStore, key: string, value: string, by: string) {
  s.db.prepare("INSERT INTO memory (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by").run(key, value, now(), by);
}
