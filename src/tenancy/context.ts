import type { VerifiedClaims } from "../auth/tokens.js";
import type { Manifest, Tenant } from "../config.js";

// read: look things up. propose: draft actions that wait for a human. execute: carry out an
// action a human has already approved. A job gets only the scopes its work needs.
export const SCOPES = ["read", "propose", "execute"] as const;
export type Scope = (typeof SCOPES)[number];

declare const issued: unique symbol;

// The agent path's only way into tenant data. It is built from VerifiedClaims, which only a
// successful signature check produces, so no tool argument or string can conjure one.
// (Operator tooling, such as the CLI and the approvals endpoint, opens stores by tenant id instead;
// it is not reachable from an MCP tool.)
export type TenantContext = {
  readonly tenant: Tenant;
  readonly subject: string;
  readonly scopes: ReadonlySet<Scope>;
  readonly [issued]: true;
};

export class TenantError extends Error {}

export function contextFromClaims(claims: VerifiedClaims, manifest: Manifest): TenantContext {
  const tenant = manifest.tenants.find((t) => t.id === claims.tenant);
  if (!tenant) throw new TenantError(`unknown tenant in token: ${claims.tenant}`);
  return Object.freeze({ tenant, subject: claims.sub, scopes: new Set(claims.scopes) }) as unknown as TenantContext;
}

export const can = (ctx: TenantContext, scope: Scope) => ctx.scopes.has(scope);

// How the audit log names the caller: "agent:daily-ops", whether or not the token's subject has the prefix.
export const actorOf = (ctx: TenantContext) => (ctx.subject.startsWith("agent:") ? ctx.subject : `agent:${ctx.subject}`);
