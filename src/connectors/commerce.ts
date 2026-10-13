import { randomBytes } from "node:crypto";
import type { ActionTool } from "../approvals/proposals.js";
import type { Credentials } from "../secrets/credentials.js";
import { now, type TenantStore } from "../store/db.js";
import type { TenantContext } from "../tenancy/context.js";

// A sandbox stand-in for a store platform's admin API (Shopify, WooCommerce and the like).
// It is built per tenant context with that tenant's credentials only, and, like a real API,
// it rejects a key that does not belong to the store it is called for.
export type Connector = { apply(tool: ActionTool, args: Record<string, unknown>, proposalId: string): Record<string, unknown> };

export class ConnectorError extends Error {}

export function sandboxCommerce(ctx: TenantContext, creds: Credentials, store: TenantStore): Connector {
  if (!creds.commerce_api_key.startsWith(`sk_test_${ctx.tenant.id}_`)) throw new ConnectorError("commerce API rejected the key: it belongs to a different store");
  const db = store.db;
  return {
    apply(tool, args, proposalId) {
      switch (tool) {
        case "refund": {
          const order = db.prepare("SELECT id, total, refunded FROM orders WHERE id = ?").get(String(args.order_id)) as { id: string; total: number; refunded: number } | undefined;
          if (!order) throw new ConnectorError("order not found");
          const amount = Number(args.amount);
          if (order.refunded + amount > order.total + 1e-9) throw new ConnectorError("refund would exceed the order total");
          const id = `re_${randomBytes(4).toString("hex")}`;
          db.prepare("INSERT INTO refunds (id, order_id, amount, at, proposal_id) VALUES (?, ?, ?, ?, ?)").run(id, order.id, amount, now(), proposalId);
          db.prepare("UPDATE orders SET refunded = refunded + ?, status = CASE WHEN refunded + ? >= total THEN 'refunded' ELSE status END WHERE id = ?").run(amount, amount, order.id);
          return { refund_id: id, order_id: order.id, amount };
        }
        case "discount": {
          const expires = new Date(Date.now() + Number(args.days_valid) * 86_400_000).toISOString();
          db.prepare("INSERT INTO discounts (code, percent, expires_at, proposal_id) VALUES (?, ?, ?, ?)").run(String(args.code), Number(args.percent), expires, proposalId);
          return { code: args.code, percent: args.percent, expires_at: expires };
        }
        case "publish_product": {
          const res = db.prepare("UPDATE products SET description = ?, status = 'active' WHERE id = ?").run(String(args.description), String(args.product_id));
          if (res.changes === 0) throw new ConnectorError("product not found");
          db.prepare("INSERT INTO published (product_id, description, at, proposal_id) VALUES (?, ?, ?, ?)").run(String(args.product_id), String(args.description), now(), proposalId);
          return { product_id: args.product_id, status: "active" };
        }
        case "send_email": {
          // the recipient was fixed in the hashed arguments when the email was proposed
          const to = String(args.to_email);
          const c = db.prepare("SELECT 1 FROM customers WHERE id = ? AND email = ?").get(String(args.customer_id), to);
          if (!c) throw new ConnectorError("the customer's address changed since the email was approved");
          const id = `msg_${randomBytes(4).toString("hex")}`;
          db.prepare("INSERT INTO outbox (id, to_email, subject, body, at, proposal_id) VALUES (?, ?, ?, ?, ?, ?)").run(id, to, String(args.subject), String(args.body), now(), proposalId);
          return { message_id: id, to };
        }
      }
    },
  };
}
