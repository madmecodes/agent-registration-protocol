#!/usr/bin/env node
// Agentic Registration Protocol -- reference client (Node.js, stdlib only).
//
// Flow: enroll a host -> generate an Ed25519 keypair -> register the agent ->
// sign a 60s JWT -> call a protected endpoint.
//
// Usage:
//   BASE_URL=https://api.example.com node examples/client.mjs
//
// In a real client you would generate the keypair ONCE, persist the private key
// at mode 0600, and reuse it on every run (re-deriving the fingerprint).

import crypto from "node:crypto";

const BASE = process.env.BASE_URL || "https://api.example.com";
const b64url = (b) => Buffer.from(b).toString("base64url");

async function jpost(path, body, headers = {}) {
  const r = await fetch(BASE + path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { status: r.status, json: await r.json().catch(() => ({})) };
}

// 1) Enroll a host (once per tenant). Keep enrollmentToken safe.
const host = await jpost("/hosts/register", { name: "my-tenant" });
const enrollmentToken = host.json.enrollmentToken;
if (!enrollmentToken) throw new Error(`host register failed: ${JSON.stringify(host)}`);

// 2) Generate an Ed25519 keypair; derive raw pubkey + fingerprint.
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const jwk = publicKey.export({ format: "jwk" });
const rawPub = Buffer.from(jwk.x, "base64url"); // 32 bytes
const publicKeyB64 = rawPub.toString("base64"); // what /agents/register expects
const fingerprint = crypto.createHash("sha256").update(rawPub).digest("hex"); // JWT sub

// Persist privateKey to a 0600 file in production, e.g.:
//   fs.writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });

// 3) Register the agent.
const reg = await jpost("/agents/register", {
  hostToken: enrollmentToken,
  publicKey: publicKeyB64,
  name: "my-agent",
});
if (reg.status !== 200 && reg.status !== 201) throw new Error(`agent register failed: ${JSON.stringify(reg)}`);
console.log("registered agentId:", reg.json.agentId, "fingerprint:", fingerprint.slice(0, 16) + "...");

// 4) Sign a 60s JWT and call a protected endpoint.
function signAgentJWT() {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "EdDSA", typ: "agent+jwt" }));
  const payload = b64url(JSON.stringify({ sub: fingerprint, iat: now, exp: now + 60, jti: crypto.randomUUID() }));
  const sig = b64url(crypto.sign(null, Buffer.from(`${header}.${payload}`), privateKey));
  return `${header}.${payload}.${sig}`;
}

const res = await fetch(BASE + "/protected/thing", {
  headers: { authorization: `Bearer ${signAgentJWT()}` },
});
console.log("protected call status:", res.status);
