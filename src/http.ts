import { randomUUID } from "node:crypto";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { GrantError, recordGrant, type Grant } from "./approvals/grants.js";
import { audit } from "./audit/log.js";
import { issuer, TokenError, verifyAccessToken } from "./auth/tokens.js";
import { buildServer, type Deps } from "./server.js";
import { operatorStore } from "./store/db.js";
import { contextFromClaims, SCOPES, TenantError, type TenantContext } from "./tenancy/context.js";

// The Streamable HTTP gateway, an OAuth 2.1 protected resource in the shape the MCP
// authorization spec asks for:
// - bearer tokens only;
// - 401 with a pointer to RFC 9728 metadata;
// - tokens checked for issuer, audience and expiry.
// Every session is pinned to the principal that opened it, so a session id from one tenant is
// useless with another tenant's token or with wider scopes.
type Session = { transport: StreamableHTTPServerTransport; ctx: TenantContext; lastSeen: number };

export type GatewayOptions = {
  baseUrl: string;
  // Host header values to accept; anything else gets 403 (DNS rebinding protection)
  allowedHosts?: string[];
  // browser Origins to accept; requests without an Origin header (CLIs, servers) are unaffected
  allowedOrigins?: string[];
  rateLimitPerMinute?: number;
  // where refusals are reported (401s, session mismatches, crashes); stderr by default
  log?: (message: string) => void;
};

const MAX_BODY = 1_000_000;

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > MAX_BODY) throw new HttpError(413, "body too large");
    chunks.push(c as Buffer);
  }
  if (!size) return undefined;
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "body is not valid JSON");
  }
}

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

export function createGateway(deps: Deps, opts: GatewayOptions): http.Server {
  const base = opts.baseUrl.replace(/\/$/, "");
  const resource = `${base}/mcp`;
  const metadataUrl = `${base}/.well-known/oauth-protected-resource`;
  const metadataPaths = new Set(["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]);
  const sessions = new Map<string, Session>();
  const hits = new Map<string, number[]>();
  const limit = opts.rateLimitPerMinute ?? 120;
  const log = opts.log ?? ((m: string) => console.error(`[gatehouse] ${m}`));

  const allow = (key: string) => {
    const t = Date.now();
    const recent = (hits.get(key) ?? []).filter((x) => t - x < 60_000);
    recent.push(t);
    hits.set(key, recent);
    return recent.length <= limit;
  };

  // RFC 6750: no error code when the request simply had no token; invalid_token when it was bad
  const unauthorized = (res: ServerResponse, description?: string) =>
    json(res, 401, { error: description ? "invalid_token" : "unauthorized", ...(description ? { error_description: description } : {}) }, {
      "www-authenticate": `Bearer resource_metadata="${metadataUrl}", scope="${SCOPES.join(" ")}"${description ? `, error="invalid_token", error_description="${description}"` : ""}`,
    });

  // idle sessions close after 30 minutes; rate-limit windows older than a minute are dropped
  const sweep = setInterval(() => {
    for (const [id, s] of sessions) if (Date.now() - s.lastSeen > 30 * 60_000) void s.transport.close().then(() => sessions.delete(id));
    for (const [key, times] of hits) if (times.every((x) => Date.now() - x > 60_000)) hits.delete(key);
  }, 60_000);
  sweep.unref();

  const server = http.createServer(async (req, res) => {
    try {
      if (opts.allowedHosts && !opts.allowedHosts.includes(req.headers.host ?? "")) return json(res, 403, { error: "forbidden", error_description: "host not allowed" });
      const origin = req.headers.origin;
      if (origin && opts.allowedOrigins && !opts.allowedOrigins.includes(origin)) return json(res, 403, { error: "forbidden", error_description: "origin not allowed" });

      const url = new URL(req.url ?? "/", base);

      if (req.method === "GET" && url.pathname === "/healthz") return json(res, 200, { ok: true });

      if (req.method === "GET" && metadataPaths.has(url.pathname))
        return json(res, 200, { resource, authorization_servers: [issuer()], scopes_supported: [...SCOPES], bearer_methods_supported: ["header"], resource_name: "Gatehouse MCP" });

      // The approval channel posts signed grants here. The signature is the authentication: it
      // must verify against the key of the approver the grant names. Every rejection gets the
      // same answer, so the endpoint does not reveal which tenants or proposals exist.
      if (req.method === "POST" && url.pathname === "/approvals") {
        if (!allow(`approvals:${req.socket.remoteAddress}`)) return json(res, 429, { error: "rate_limited" });
        const grant = ((await readJson(req)) as { grant?: Grant } | undefined)?.grant;
        const tenant = deps.manifest.tenants.find((t) => t.id === grant?.body?.tenant);
        try {
          if (!grant || !tenant) throw new GrantError("unknown tenant or missing grant");
          recordGrant(operatorStore(tenant.id, deps.dataDir), tenant, deps.keys.approvers, grant);
          return json(res, 201, { recorded: grant.body.proposal_id });
        } catch (err) {
          if (!(err instanceof GrantError)) throw err;
          if (tenant) audit(operatorStore(tenant.id, deps.dataDir), "system:approvals-endpoint", "grant.rejected", { proposal: String(grant?.body?.proposal_id ?? ""), reason: err.message });
          return json(res, 400, { error: "invalid_grant" });
        }
      }

      if (url.pathname !== "/mcp") return json(res, 404, { error: "not_found" });

      const auth = req.headers.authorization ?? "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
      if (!token) return unauthorized(res);
      let ctx: TenantContext;
      try {
        ctx = contextFromClaims(await verifyAccessToken(deps.keys.issuer.publicKey, token, resource), deps.manifest);
      } catch (err) {
        if (err instanceof TokenError || err instanceof TenantError) {
          log(`401 from ${req.socket.remoteAddress}: ${err.message}`);
          return unauthorized(res, err.message);
        }
        throw err;
      }
      if (!allow(`${ctx.tenant.id}:${ctx.subject}`)) return json(res, 429, { error: "rate_limited" }, { "retry-after": "30" });

      const sessionId = req.headers["mcp-session-id"];
      const body = req.method === "POST" ? await readJson(req) : undefined;

      if (typeof sessionId === "string") {
        const s = sessions.get(sessionId);
        if (!s) return json(res, 404, { jsonrpc: "2.0", error: { code: -32001, message: "session not found" }, id: null });
        const same = s.ctx.tenant.id === ctx.tenant.id && s.ctx.subject === ctx.subject && [...s.ctx.scopes].sort().join() === [...ctx.scopes].sort().join();
        if (!same) {
          log(`403 session ${sessionId} presented by ${ctx.tenant.id}/${ctx.subject}`);
          return json(res, 403, { error: "forbidden", error_description: "this session belongs to a different principal" });
        }
        s.lastSeen = Date.now();
        return s.transport.handleRequest(req, res, body);
      }

      if (req.method !== "POST" || !isInitializeRequest(body))
        return json(res, 400, { jsonrpc: "2.0", error: { code: -32600, message: "no session: send initialize first" }, id: null });

      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => void sessions.set(id, { transport, ctx, lastSeen: Date.now() }),
      });
      transport.onclose = () => {
        if (transport.sessionId) sessions.delete(transport.sessionId);
      };
      await buildServer(ctx, deps).connect(transport);
      return transport.handleRequest(req, res, body);
    } catch (err) {
      if (err instanceof HttpError) return json(res, err.status, { error: err.status === 413 ? "payload_too_large" : "bad_request", error_description: err.message });
      log(`request failed: ${err instanceof Error ? err.stack : String(err)}`);
      if (!res.headersSent) json(res, 500, { error: "internal_error" });
    }
  });
  server.on("close", () => {
    clearInterval(sweep);
    for (const s of sessions.values()) void s.transport.close();
    sessions.clear();
  });
  return server;
}
