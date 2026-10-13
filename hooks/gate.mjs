#!/usr/bin/env node
// Claude Code PreToolUse hook: the job-level gate, a second wall in front of the server's own.
//
// The server already refuses anything without a signed grant. This hook enforces what one *job*
// may do, whatever its token allows:
//   - only Gatehouse tools (plus any prefixes in GATEHOUSE_HOOK_ALLOW), nothing else;
//   - action_execute only in jobs started with GATEHOUSE_JOB_MAY_EXECUTE=1;
//   - at most GATEHOUSE_HOOK_MAX_CALLS tool calls and GATEHOUSE_HOOK_MAX_PROPOSALS proposals per session.
//
// It fails closed. Claude Code lets a call through when a hook exits with an ordinary error,
// so every failure here exits 2, which blocks, and settings.json wraps the command in
// `|| exit 2` so that a missing file or a missing node blocks too.
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const deny = (reason) => {
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: `gatehouse gate: ${reason}` } }));
  process.exit(0);
};

try {
  const input = JSON.parse(readFileSync(0, "utf8"));
  const tool = String(input.tool_name ?? "");
  const session = String(input.session_id ?? "unknown").replace(/[^a-zA-Z0-9_-]/g, "");
  const allow = ["mcp__gatehouse__", ...(process.env.GATEHOUSE_HOOK_ALLOW ?? "").split(",").map((s) => s.trim()).filter(Boolean)];
  // Claude Code's own schema loader for deferred MCP tools: it reads tool definitions, nothing else
  const harness = new Set(["ToolSearch"]);

  if (harness.has(tool)) process.exit(0);
  if (!allow.some((p) => tool.startsWith(p))) deny(`${tool} is outside this job's allowlist`);
  if (tool === "mcp__gatehouse__action_execute" && process.env.GATEHOUSE_JOB_MAY_EXECUTE !== "1")
    deny("this job proposes only; approved proposals run in a separate execute job");

  const limit = (name, fallback) => {
    const raw = process.env[name] ?? String(fallback);
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 0) throw new Error(`${name} must be a whole number, got "${raw}"`);
    return n;
  };
  const maxCalls = limit("GATEHOUSE_HOOK_MAX_CALLS", 40);
  const maxProposals = limit("GATEHOUSE_HOOK_MAX_PROPOSALS", 10);

  // one line per call, appended: appends of a few bytes do not interleave, so parallel calls
  // in the same session are all counted. An unreadable ledger blocks rather than resets.
  const dir = path.join(tmpdir(), "gatehouse-gate");
  mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${session}.log`);
  appendFileSync(file, `${tool}\n`);
  const calls = readFileSync(file, "utf8").split("\n").filter(Boolean);
  if (!calls.every((c) => /^[A-Za-z0-9_.-]+$/.test(c))) throw new Error("the call ledger is corrupt");
  const proposals = calls.filter((c) => c.endsWith("_propose")).length;
  if (calls.length > maxCalls) deny(`tool-call budget of ${maxCalls} for this run is used up`);
  if (proposals > maxProposals) deny(`proposal budget of ${maxProposals} for this run is used up`);
  process.exit(0); // no opinion: the normal permission rules and the server decide
} catch (err) {
  process.stderr.write(`gatehouse gate failed closed: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(2);
}
