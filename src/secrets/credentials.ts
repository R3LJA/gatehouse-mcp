import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { dataDir } from "../config.js";
import type { TenantContext } from "../tenancy/context.js";

// Each tenant's connector credentials live in their own file, sealed with AES-256-GCM.
// The tenant id is the associated data, so a sealed blob copied into another tenant's slot
// fails to open instead of quietly handing tenant B's API key to tenant A's run.
export type Credentials = { commerce_api_key: string };

function seal(key: Buffer, tenantId: string, creds: Credentials): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(`gatehouse:${tenantId}`));
  const body = Buffer.concat([cipher.update(JSON.stringify(creds), "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), body].map((b) => b.toString("base64")).join(".");
}

function unseal(key: Buffer, tenantId: string, sealed: string): Credentials {
  const [iv, tag, body] = sealed.split(".").map((p) => Buffer.from(p, "base64"));
  if (!iv || !tag || !body) throw new Error("credentials file is malformed");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(Buffer.from(`gatehouse:${tenantId}`));
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8"));
}

const fileFor = (tenantId: string, dir: string) => path.join(dir, tenantId, "credentials.enc");

export function writeCredentials(key: Buffer, tenantId: string, creds: Credentials, dir = dataDir()) {
  mkdirSync(path.join(dir, tenantId), { recursive: true });
  writeFileSync(fileFor(tenantId, dir), seal(key, tenantId, creds), { mode: 0o600 });
}

// Loaded per context: a run only ever holds its own tenant's credentials.
export function credentialsFor(ctx: TenantContext, key: Buffer, dir = dataDir()): Credentials {
  const file = fileFor(ctx.tenant.id, dir);
  if (!existsSync(file)) throw new Error(`no connector credentials for tenant ${ctx.tenant.id}`);
  try {
    return unseal(key, ctx.tenant.id, readFileSync(file, "utf8"));
  } catch {
    throw new Error(`connector credentials for tenant ${ctx.tenant.id} could not be opened`);
  }
}
