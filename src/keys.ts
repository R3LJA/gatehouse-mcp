import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, type KeyObject } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { keysDir } from "./config.js";

// Keys and their owners:
// - issuer: signs access tokens. In production this is your identity provider.
// - one key per approver: signs that person's approval grants and audit anchors. The private
//   half lives with the approval channel (here ~/.gatehouse/approvers; in production a KMS behind
//   the Slack handler). The server holds only the public halves, so a grant proves which listed
//   person approved, and nothing on the agent's side can produce one.
// - secrets: AES-256 key that seals each tenant's connector credentials at rest.
export type Approvers = ReadonlyMap<string, KeyObject>;
export type ServerKeys = { issuer: { publicKey: KeyObject }; approvers: Approvers; secrets: Buffer };

export const approverDir = () => path.resolve(process.env.GATEHOUSE_APPROVER_DIR ?? path.join(homedir(), ".gatehouse", "approvers"));
const safe = (email: string) => email.replace(/[^a-zA-Z0-9@._-]/g, "_");
const pem = (key: KeyObject, type: "pkcs8" | "spki") => key.export({ type, format: "pem" }) as string;

// In-memory keys for tests and the red-team script.
export function generateKeys(approverEmails: string[]) {
  const approvers = new Map(approverEmails.map((e) => [e, generateKeyPairSync("ed25519")] as const));
  return { issuer: generateKeyPairSync("ed25519"), approvers, secrets: randomBytes(32) };
}

export function serverKeysFrom(k: ReturnType<typeof generateKeys>): ServerKeys {
  return { issuer: { publicKey: k.issuer.publicKey }, approvers: new Map([...k.approvers].map(([e, p]) => [e, p.publicKey])), secrets: k.secrets };
}

export function writeKeys(approverEmails: string[], dir = keysDir(), approvers = approverDir()) {
  if (existsSync(path.join(dir, "issuer.key"))) throw new Error(`keys already exist in ${dir}; refusing to overwrite`);
  mkdirSync(path.join(dir, "approvers"), { recursive: true, mode: 0o700 });
  const k = generateKeys([]);
  writeFileSync(path.join(dir, "issuer.key"), pem(k.issuer.privateKey, "pkcs8"), { mode: 0o600 });
  writeFileSync(path.join(dir, "issuer.pub"), pem(k.issuer.publicKey, "spki"));
  writeFileSync(path.join(dir, "secrets.key"), k.secrets.toString("base64"), { mode: 0o600 });
  for (const email of approverEmails) addApprover(email, dir, approvers);
}

// The private key goes to the approval side; the server's key directory gets the public key only.
export function addApprover(email: string, dir = keysDir(), approvers = approverDir()) {
  const pair = generateKeyPairSync("ed25519");
  mkdirSync(approvers, { recursive: true, mode: 0o700 });
  mkdirSync(path.join(dir, "approvers"), { recursive: true, mode: 0o700 });
  writeFileSync(path.join(approvers, `${safe(email)}.key`), pem(pair.privateKey, "pkcs8"), { mode: 0o600 });
  writeFileSync(path.join(dir, "approvers", `${safe(email)}.pub`), pem(pair.publicKey, "spki"));
}

const read = (dir: string, file: string) => readFileSync(path.join(dir, file), "utf8");

// What the MCP server loads: public keys only, plus the secrets key it needs to open credentials.
export function loadServerKeys(dir = keysDir()): ServerKeys {
  const approvers = new Map<string, KeyObject>();
  for (const f of readdirSync(path.join(dir, "approvers")).filter((f) => f.endsWith(".pub")))
    approvers.set(f.slice(0, -4), createPublicKey(read(path.join(dir, "approvers"), f)));
  return { issuer: { publicKey: createPublicKey(read(dir, "issuer.pub")) }, approvers, secrets: Buffer.from(read(dir, "secrets.key").trim(), "base64") };
}

// The approval channel loads one person's key. The server process never calls this.
export function loadApproverKey(email: string, dir = approverDir()): KeyObject {
  const file = path.join(dir, `${safe(email)}.key`);
  if (!existsSync(file)) throw new Error(`no approver key for ${email} in ${dir}`);
  return createPrivateKey(readFileSync(file, "utf8"));
}

// The local stand-in for an identity provider.
export function loadIssuerKey(dir = keysDir()): KeyObject {
  return createPrivateKey(read(dir, "issuer.key"));
}
