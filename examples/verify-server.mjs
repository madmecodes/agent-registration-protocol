// Agentic Registration Protocol -- reference server verification (Node.js + jose).
//
//   npm i jose
//
// Express middleware that authenticates an agent JWT: peek at `sub` to find the
// agent's stored public key, then verify the Ed25519 signature, typ, and expiry.

import { importSPKI, jwtVerify } from "jose";

// --- Your store. Replace with a real DB lookup. ---
// Maps fingerprint (sha256-hex of the raw 32-byte pubkey) -> base64(raw pubkey).
const PUBLIC_KEYS = new Map();
export async function lookupPublicKeyB64(fingerprint) {
  return PUBLIC_KEYS.get(fingerprint) || null;
}

// Raw 32-byte Ed25519 keys must be wrapped in an ASN.1 SPKI header before jose
// can import them. This prefix is constant for Ed25519.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function rawEd25519ToSPKI(rawB64) {
  const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(rawB64, "base64")]);
  return `-----BEGIN PUBLIC KEY-----\n${der.toString("base64")}\n-----END PUBLIC KEY-----\n`;
}

export function agentAuth() {
  return async function (req, res, next) {
    try {
      const auth = req.headers.authorization || "";
      if (!auth.startsWith("Bearer ")) return res.status(401).json({ error: "missing bearer token" });
      const token = auth.slice(7);

      // Peek at sub (UNVERIFIED) only to find the right key.
      const payloadB64 = token.split(".")[1];
      if (!payloadB64) return res.status(401).json({ error: "malformed token" });
      const { sub } = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
      if (!sub) return res.status(401).json({ error: "no sub" });

      const pubB64 = await lookupPublicKeyB64(sub);
      if (!pubB64) return res.status(401).json({ error: "unknown agent fingerprint" });

      // Now actually verify: signature against the looked-up key, plus typ + age.
      const key = await importSPKI(rawEd25519ToSPKI(pubB64), "EdDSA");
      const { payload } = await jwtVerify(token, key, { typ: "agent+jwt", maxTokenAge: "60s" });

      // Optional strict replay protection:
      //   if (await seenJti(payload.jti)) return res.status(401).json({ error: "replay" });
      //   await rememberJti(payload.jti, 60);

      req.agent = { fingerprint: payload.sub };
      next();
    } catch (err) {
      return res.status(401).json({ error: "invalid token" });
    }
  };
}

// Example wiring:
//   import express from "express";
//   const app = express();
//   app.get("/protected/thing", agentAuth(), (req, res) => res.json({ ok: true, agent: req.agent }));
