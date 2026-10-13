import { randomUUID, type KeyObject } from "node:crypto";
import { SignJWT, jwtVerify, errors } from "jose";
import { SCOPES, type Scope } from "../tenancy/context.js";

// Gatehouse is the resource server. Tokens come from an issuer: your identity provider in
// production, or the bundled `gatehouse token` command locally. Set GATEHOUSE_ISSUER to its URL.
export const issuer = () => process.env.GATEHOUSE_ISSUER ?? "https://issuer.gatehouse.local";

export type AccessClaims = { tenant: string; sub: string; scopes: Scope[] };

declare const verified: unique symbol;
// Claims that came out of a signature check. Nothing else can produce this type, and a tenant
// context can only be built from it.
export type VerifiedClaims = AccessClaims & { readonly [verified]: true };

// Access tokens carry the tenant. Tool arguments never do: the model can name any id it
// likes, but which company's data it reaches is fixed by the credential the job runs with.
export async function issueAccessToken(issuerKey: KeyObject, opts: AccessClaims & { audience: string; ttlSeconds?: number }): Promise<string> {
  const scopes = [...new Set(opts.scopes)];
  for (const s of scopes) if (!SCOPES.includes(s)) throw new Error(`unknown scope ${s}`);
  return new SignJWT({ tenant: opts.tenant, scope: scopes.join(" ") })
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
    .setIssuer(issuer())
    .setSubject(opts.sub)
    .setAudience(opts.audience)
    .setIssuedAt()
    .setJti(randomUUID())
    .setExpirationTime(`${opts.ttlSeconds ?? 3600}s`)
    .sign(issuerKey);
}

export class TokenError extends Error {}

export async function verifyAccessToken(issuerPublicKey: KeyObject, token: string, audience: string): Promise<VerifiedClaims> {
  try {
    const { payload } = await jwtVerify(token, issuerPublicKey, { issuer: issuer(), audience, algorithms: ["EdDSA"], requiredClaims: ["exp", "iat", "sub"] });
    if (typeof payload.tenant !== "string" || typeof payload.sub !== "string" || typeof payload.scope !== "string") throw new TokenError("token is missing tenant, sub or scope");
    const scopes = payload.scope.split(" ").filter((s): s is Scope => (SCOPES as readonly string[]).includes(s));
    return { tenant: payload.tenant, sub: payload.sub, scopes } as VerifiedClaims;
  } catch (err) {
    if (err instanceof TokenError) throw err;
    if (err instanceof errors.JWTExpired) throw new TokenError("token expired");
    if (err instanceof errors.JWTClaimValidationFailed) throw new TokenError(`token claim rejected: ${err.claim}`);
    throw new TokenError("token signature or format is invalid");
  }
}
