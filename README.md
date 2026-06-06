# Agentic Registration Protocol

A small, dependency-light protocol for **AI agents to self-register and authenticate
to a backend with zero shared secrets and zero human in the loop**.

It uses **Ed25519 keypairs + short-lived JWTs**. An agent generates a keypair locally,
registers its public key once, and then signs a fresh 60-second JWT for every request.
The server never stores a password or a long-lived API key for the agent — only its
public key.

This repo is the protocol spec + copy-pasteable client/server examples. It is
framework- and product-agnostic; drop it into any service that needs agents (or any
machine client) to onboard themselves programmatically.

---

## Why this design

- **No shared secrets in flight.** The agent's private key never leaves its machine.
  The server only ever sees a public key, so a leaked request can't impersonate the agent.
- **Short-lived auth.** Each request carries a JWT that expires in ~60s with a random
  nonce (`jti`), so captured tokens are useless almost immediately and replay is hard.
- **No human step.** An agent can go from "never seen before" to "authenticated" in two
  HTTP calls, entirely programmatically.
- **Cheap to verify.** Ed25519 verification is fast and the primitives are in every
  language's stdlib (or one tiny library).
- **Multi-tenant ready.** A "host" (org / machine / tenant) holds an enrollment token;
  many agents can enroll under it, and you can cap/revoke per host.

---

## Concepts

| Term | Meaning |
|------|---------|
| **Host** | A tenant/owner (an org, a machine, a customer). Holds an enrollment token. |
| **Enrollment token** | A one-time-ish secret a host uses to enroll agents. Stored **hashed** server-side. |
| **Agent** | A client that registers an Ed25519 public key under a host. |
| **Fingerprint** | `SHA-256(raw 32-byte public key)`, hex. The agent's stable identity / JWT `sub`. |
| **Agent JWT** | A 60s Ed25519-signed token the agent sends on every authenticated request. |

---

## The flow

```
  AGENT / CLIENT                         SERVER
  ─────────────                          ──────
  (once, per tenant)
  POST /hosts/register {name}  ───────►  create host, return enrollmentToken
                               ◄───────  { enrollmentToken }   (store its SHA-256 hash)

  (once, per agent)
  generate Ed25519 keypair locally
  POST /agents/register {                ───────►  verify hostToken (hash match),
    hostToken, publicKey,                          decode 32-byte pubkey,
    name }                                         fingerprint = SHA256(pubkey),
                                                   store agent + public key
                               ◄───────  { agentId }

  (every authenticated request)
  sign JWT {sub: fingerprint,  ───────►  decode sub -> look up stored public key
            iat, exp, jti}               by fingerprint -> verify Ed25519 signature
  Authorization: Bearer <jwt>            -> check exp/iat (-> optional jti replay check)
                               ◄───────  200 / your protected resource
```

Two calls to onboard, then a freshly-signed JWT per request.

---

## Endpoint reference

These names are a suggestion — adapt the paths to your service.

### `POST /hosts/register`
Create a tenant and get an enrollment token.

Request:
```json
{ "name": "my-tenant", "contactEmail": "optional@example.com" }
```
Response:
```json
{ "hostId": "uuid", "enrollmentToken": "<64 hex chars>", "enrollmentTokenExpiresAt": "ISO-8601" }
```
Server stores **only `SHA-256(enrollmentToken)`**, never the raw token.

### `POST /agents/register`
Register an agent's public key under a host.

Request:
```json
{
  "hostToken": "<enrollmentToken>",
  "publicKey": "<base64 of the raw 32-byte Ed25519 public key>",
  "name": "my-agent"
}
```
Response:
```json
{ "agentId": "uuid" }
```
Server validation:
1. `SHA-256(hostToken)` must match a stored host hash (and not be expired/inactive).
2. `base64decode(publicKey)` must be exactly **32 bytes**.
3. `fingerprint = SHA-256(those 32 bytes)` (hex) — reject if already registered.
4. Persist the agent + its public key, keyed by fingerprint.

### Authenticated requests
Every protected endpoint expects:
```
Authorization: Bearer <agent-jwt>
```

---

## The agent JWT

A standard JWT signed with **EdDSA (Ed25519)**.

**Header**
```json
{ "alg": "EdDSA", "typ": "agent+jwt" }
```
**Payload**
```json
{
  "sub": "<fingerprint = sha256-hex of the raw public key>",
  "iat": 1700000000,
  "exp": 1700000060,
  "jti": "<random uuid>"
}
```
- `sub` is how the server finds which public key to verify against.
- `exp - iat` should be small (60s is a good default).
- `jti` is a random nonce; store recently-seen `jti`s if you want strict replay protection.

Signing input is the usual `base64url(header) + "." + base64url(payload)`, and the
token is `signingInput + "." + base64url(ed25519_signature)`.

---

## Client example (Node.js, stdlib only)

`examples/client.mjs` — generate a key, register, sign a JWT, call a protected route.

```js
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

// 1) Enroll a host (do this once per tenant; keep the token safe)
const host = await jpost("/hosts/register", { name: "my-tenant" });
const enrollmentToken = host.json.enrollmentToken;

// 2) Generate an Ed25519 keypair and derive the raw pubkey + fingerprint
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const jwk = publicKey.export({ format: "jwk" });          // { kty:"OKP", crv:"Ed25519", x:"<b64url>" }
const rawPub = Buffer.from(jwk.x, "base64url");           // 32 bytes
const publicKeyB64 = rawPub.toString("base64");           // what /agents/register expects
const fingerprint = crypto.createHash("sha256").update(rawPub).digest("hex"); // JWT sub

// Persist the private key locally (mode 0600). Re-use it on every run.
crypto.createPrivateKey(privateKey); // keep `privateKey` object or export to a 0600 file

// 3) Register the agent
const reg = await jpost("/agents/register", {
  hostToken: enrollmentToken,
  publicKey: publicKeyB64,
  name: "my-agent",
});
const agentId = reg.json.agentId;

// 4) Sign a 60s JWT and call a protected endpoint
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
console.log(res.status);
```

---

## Server verification example (Node.js + jose)

`examples/verify-server.mjs` — Express middleware that authenticates the agent JWT.

```js
import { importSPKI, jwtVerify } from "jose";
import crypto from "node:crypto";

// Your store: fingerprint -> base64(raw 32-byte ed25519 public key)
async function lookupPublicKeyB64(fingerprint) { /* db query */ }

// Raw 32-byte Ed25519 keys must be wrapped in an ASN.1 SPKI header before jose
// can import them. This prefix is constant for Ed25519.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function rawEd25519ToSPKI(rawB64) {
  const raw = Buffer.from(rawB64, "base64");
  const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  return `-----BEGIN PUBLIC KEY-----\n${der.toString("base64")}\n-----END PUBLIC KEY-----\n`;
}

export async function agentAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    if (!auth.startsWith("Bearer ")) return res.status(401).json({ error: "missing bearer" });
    const token = auth.slice(7);

    // Peek at sub (unverified) to find which public key to check against.
    const payloadB64 = token.split(".")[1];
    const { sub } = JSON.parse(Buffer.from(payloadB64, "base64url").toString());

    const pubB64 = await lookupPublicKeyB64(sub);
    if (!pubB64) return res.status(401).json({ error: "unknown agent" });

    // Verify signature, typ, and expiry against the looked-up key.
    const key = await importSPKI(rawEd25519ToSPKI(pubB64), "EdDSA");
    const { payload } = await jwtVerify(token, key, { typ: "agent+jwt", maxTokenAge: "60s" });

    // (optional) reject replays: if (await seenJti(payload.jti)) return 401; else rememberJti(payload.jti)

    req.agent = { fingerprint: payload.sub };
    next();
  } catch {
    return res.status(401).json({ error: "invalid token" });
  }
}
```

> **The SPKI gotcha:** a raw 32-byte Ed25519 public key cannot be imported by most JWT
> libraries directly. Prepend the fixed ASN.1 prefix `302a300506032b6570032100` to get a
> valid SPKI DER, then PEM-wrap it. This trips everyone up once.

---

## Client example (Python, stdlib + PyNaCl)

```python
import base64, hashlib, json, time, uuid, requests
from nacl.signing import SigningKey

BASE = "https://api.example.com"
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

# host enroll (once)
enroll = requests.post(f"{BASE}/hosts/register", json={"name": "my-tenant"}).json()["enrollmentToken"]

# keypair + identity
sk = SigningKey.generate()
raw_pub = bytes(sk.verify_key)                                  # 32 bytes
fingerprint = hashlib.sha256(raw_pub).hexdigest()
agent = requests.post(f"{BASE}/agents/register", json={
    "hostToken": enroll,
    "publicKey": base64.b64encode(raw_pub).decode(),
    "name": "my-agent",
}).json()

# sign a 60s JWT
def sign_jwt():
    now = int(time.time())
    header = b64u(json.dumps({"alg": "EdDSA", "typ": "agent+jwt"}).encode())
    payload = b64u(json.dumps({"sub": fingerprint, "iat": now, "exp": now + 60, "jti": str(uuid.uuid4())}).encode())
    sig = b64u(sk.sign(f"{header}.{payload}".encode()).signature)
    return f"{header}.{payload}.{sig}"

requests.get(f"{BASE}/protected/thing", headers={"Authorization": f"Bearer {sign_jwt()}"})
```

---

## Security model & best practices

- **Store the private key at `0600`** (and its directory `0700`). It is the agent's identity.
- **Never store the enrollment token or any token in plaintext** server-side — store
  `SHA-256(token)` and compare hashes.
- **Keep JWT lifetimes short** (60s). Long-lived agent JWTs defeat the point.
- **Add replay protection** by remembering recent `jti`s (e.g. in Redis with a TTL = token
  lifetime) if your threat model needs it.
- **Cap and revoke per host** — limit agents per host; mark a host inactive to cut off all
  its agents at once; rotate the enrollment token to stop new enrollments.
- **Support key rotation** — let an agent register a new public key and retire the old
  fingerprint, so a compromised key can be replaced without losing identity continuity.
- **Always verify the signature against the looked-up key** — never trust the `sub` (or any
  claim) before signature verification; the unverified peek is only to find the right key.
- **Use HTTPS** and only follow same-origin redirects (don't let a redirect carry the
  `Authorization` header to another host).

---

## License

MIT
