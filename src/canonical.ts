import { createHash } from "node:crypto";

// Deterministic JSON: keys sorted at every level, no whitespace. Two parties that hash the
// same logical value get the same bytes, so a signature over it means exactly one thing.
export function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new Error("canonical: non-finite number");
    if (value === undefined) throw new Error("canonical: undefined has no JSON form");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
}

export function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}
