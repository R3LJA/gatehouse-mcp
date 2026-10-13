import { readFileSync } from "node:fs";
import path from "node:path";
import { z } from "zod";

// The tenant manifest: who exists, what they may do, and who may approve for them.
// It is configuration, not data: it changes by pull request, never by an agent.
const Limits = z.object({
  refund_max: z.number().positive(), // largest single refund an agent may even propose
  refund_daily: z.number().positive(), // total refunds executed per UTC day
  discount_max_percent: z.number().int().min(1).max(100),
  proposals_per_hour: z.number().int().positive(),
});

const Tenant = z.object({
  id: z.string().regex(/^[a-z][a-z0-9-]{2,40}$/),
  name: z.string(),
  currency: z.enum(["USD", "EUR", "GBP"]),
  approvers: z.array(z.string().email()).min(1),
  limits: Limits,
});

export const Manifest = z.object({ tenants: z.array(Tenant).min(1) });

export type Tenant = z.infer<typeof Tenant>;
export type Manifest = z.infer<typeof Manifest>;

export function loadManifest(file = process.env.GATEHOUSE_MANIFEST ?? path.resolve("config/tenants.json")): Manifest {
  const parsed = Manifest.parse(JSON.parse(readFileSync(file, "utf8")));
  const ids = new Set<string>();
  for (const t of parsed.tenants) {
    if (ids.has(t.id)) throw new Error(`manifest: duplicate tenant id ${t.id}`);
    ids.add(t.id);
  }
  return parsed;
}

export const dataDir = () => path.resolve(process.env.GATEHOUSE_DATA_DIR ?? "data");
export const keysDir = () => path.resolve(process.env.GATEHOUSE_KEYS_DIR ?? "keys");
