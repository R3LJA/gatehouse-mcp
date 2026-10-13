import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { verifyAccessToken } from "./auth/tokens.js";
import { buildServer, type Deps } from "./server.js";
import { contextFromClaims } from "./tenancy/context.js";

export const STDIO_AUDIENCE = "gatehouse:stdio";

// A stdio process serves exactly one principal: the one in GATEHOUSE_TOKEN. The token is
// verified like any HTTP request, so a local process gets no shortcut around tenancy or scopes.
export async function serveStdio(deps: Deps, token: string | undefined) {
  if (!token) throw new Error("set GATEHOUSE_TOKEN to an access token issued for audience gatehouse:stdio");
  const ctx = contextFromClaims(await verifyAccessToken(deps.keys.issuer.publicKey, token, STDIO_AUDIENCE), deps.manifest);
  const server = buildServer(ctx, deps);
  await server.connect(new StdioServerTransport());
  console.error(`[gatehouse] stdio ready: ${ctx.tenant.name} as ${ctx.subject} (${[...ctx.scopes].join(", ")})`);
}
