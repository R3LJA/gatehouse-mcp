import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

const HOOK = path.resolve("hooks/gate.mjs");

// Runs the hook exactly as Claude Code would: JSON on stdin, decision on stdout or exit code 2.
function gate(tool: string, env: Record<string, string> = {}, session = randomUUID()) {
  const r = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({ session_id: session, hook_event_name: "PreToolUse", tool_name: tool, tool_input: {} }),
    env: { ...process.env, ...env },
    encoding: "utf8",
  });
  const out = r.stdout ? JSON.parse(r.stdout) : null;
  return { code: r.status, decision: out?.hookSpecificOutput?.permissionDecision ?? "none", reason: out?.hookSpecificOutput?.permissionDecisionReason ?? r.stderr };
}

describe("Claude Code PreToolUse gate", () => {
  it("lets Gatehouse read and propose tools through to the server", () => {
    expect(gate("mcp__gatehouse__orders_search").decision).toBe("none");
    expect(gate("mcp__gatehouse__refund_propose").decision).toBe("none");
  });

  it("lets Claude Code load deferred tool schemas", () => {
    expect(gate("ToolSearch").decision).toBe("none");
  });

  it("denies tools outside the job's allowlist", () => {
    for (const tool of ["Bash", "WebFetch", "mcp__other__send_money"]) expect(gate(tool).decision, tool).toBe("deny");
  });

  it("denies execution in a propose-only job, even if the token could execute", () => {
    expect(gate("mcp__gatehouse__action_execute").reason).toMatch(/proposes only/);
    expect(gate("mcp__gatehouse__action_execute", { GATEHOUSE_JOB_MAY_EXECUTE: "1" }).decision).toBe("none");
  });

  it("enforces a per-run proposal budget", () => {
    const session = randomUUID();
    const env = { GATEHOUSE_HOOK_MAX_PROPOSALS: "2" };
    expect(gate("mcp__gatehouse__refund_propose", env, session).decision).toBe("none");
    expect(gate("mcp__gatehouse__email_propose", env, session).decision).toBe("none");
    expect(gate("mcp__gatehouse__discount_propose", env, session).reason).toMatch(/proposal budget/);
  });

  it("fails closed on garbage input", () => {
    const r = spawnSync(process.execPath, [HOOK], { input: "not json", encoding: "utf8" });
    expect(r.status).toBe(2);
  });

  it("fails closed on a budget that is not a number", () => {
    expect(gate("mcp__gatehouse__orders_search", { GATEHOUSE_HOOK_MAX_PROPOSALS: "two" }).code).toBe(2);
  });

  it("fails closed when the call ledger is corrupt instead of starting again from zero", () => {
    const session = randomUUID();
    gate("mcp__gatehouse__orders_search", {}, session);
    const dir = path.join(tmpdir(), "gatehouse-gate");
    mkdirSync(dir, { recursive: true });
    appendFileSync(path.join(dir, `${session}.log`), "\u0000garbage{}\n");
    expect(gate("mcp__gatehouse__orders_search", {}, session).code).toBe(2);
  });

  it("the registered command blocks even when the hook file cannot be found", () => {
    const settings = JSON.parse(readFileSync(path.resolve("hooks/settings.json"), "utf8"));
    const command: string = settings.hooks.PreToolUse[0].hooks[0].command;
    const input = JSON.stringify({ session_id: randomUUID(), tool_name: "mcp__gatehouse__orders_search", tool_input: {} });
    const missing = spawnSync("sh", ["-c", command], { input, env: { ...process.env, CLAUDE_PROJECT_DIR: "/nonexistent" }, encoding: "utf8" });
    expect(missing.status).toBe(2);
    const present = spawnSync("sh", ["-c", command], { input, env: { ...process.env, CLAUDE_PROJECT_DIR: path.resolve(".") }, encoding: "utf8" });
    expect(present.status).toBe(0);
  });
});
