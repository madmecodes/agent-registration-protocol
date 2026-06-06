#!/usr/bin/env python3
"""Agentic Registration Protocol -- reference client (Python).

    pip install pynacl requests

Flow: enroll a host -> generate an Ed25519 keypair -> register the agent ->
sign a 60s JWT -> call a protected endpoint.

In a real client, generate the keypair ONCE, persist the 32-byte seed at mode
0600, and reuse it on every run.
"""
import base64
import hashlib
import json
import os
import time
import uuid

import requests
from nacl.signing import SigningKey

BASE = os.environ.get("BASE_URL", "https://api.example.com")


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# 1) Enroll a host (once per tenant).
enroll = requests.post(f"{BASE}/hosts/register", json={"name": "my-tenant"}).json()
enrollment_token = enroll["enrollmentToken"]

# 2) Keypair + identity.
sk = SigningKey.generate()                 # persist sk.encode() (32-byte seed) at 0600
raw_pub = bytes(sk.verify_key)             # 32 bytes
fingerprint = hashlib.sha256(raw_pub).hexdigest()

# 3) Register the agent.
agent = requests.post(
    f"{BASE}/agents/register",
    json={
        "hostToken": enrollment_token,
        "publicKey": base64.b64encode(raw_pub).decode(),
        "name": "my-agent",
    },
).json()
print("registered agentId:", agent.get("agentId"), "fingerprint:", fingerprint[:16] + "...")


# 4) Sign a 60s JWT and call a protected endpoint.
def sign_jwt() -> str:
    now = int(time.time())
    header = b64u(json.dumps({"alg": "EdDSA", "typ": "agent+jwt"}).encode())
    payload = b64u(
        json.dumps({"sub": fingerprint, "iat": now, "exp": now + 60, "jti": str(uuid.uuid4())}).encode()
    )
    sig = b64u(sk.sign(f"{header}.{payload}".encode()).signature)
    return f"{header}.{payload}.{sig}"


resp = requests.get(f"{BASE}/protected/thing", headers={"Authorization": f"Bearer {sign_jwt()}"})
print("protected call status:", resp.status_code)
