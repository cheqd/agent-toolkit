# SPDX-License-Identifier: Apache-2.0
"""Real cross-language wire conformance for the A2A SendMessage request proof - the Python half
of the TS-client-wire-JSON <-> Python-proto-parse (and reverse) round trip docs/design-
decisions.md D15's "Revisit-if" left open: whether gate.py/client.py's dict-based design, once
wired to the real a2a-sdk via proto_bridge.py, survives a real TypeScript-client-to-Python-
server (or reverse) wire round trip, not just a Python-proto-to-Python-gate one (already
covered by tests/test_proto_bridge.py).

Two modes, each a half of one of the two cross-language directions. The counterpart TS script is
conformance/cross-language-a2a-wire.mjs at the repository root - same two modes, same shapes.

  mint   - acts as a real Python client (client.py's own ProofInterceptor.before, unmodified):
           mints a request proof, then round-trips it through a real a2a-sdk SendMessageRequest
           proto (ParseDict/MessageToDict, the same conversion proto_bridge.py uses) - the exact
           wire JSON a real Python client sends. Prints {wire, clientDid, clientKid,
           clientPublicJwk, serverDid} to stdout.
  verify - acts as a real Python server (gate.py's own verify_caller, unmodified): reads that
           JSON from stdin (either this script's own mint output, or the TS script's), round-
           trips it through ParseDict/MessageToDict again, then calls verify_caller. Exits 0 and
           prints the verified DID on success; exits 1 otherwise.

Run with `poetry run python conformance_cross_language.py <mint|verify>` from this directory.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from google.protobuf.json_format import MessageToDict, ParseDict

from a2a.types import SendMessageRequest
from cheqd_agent_identity_a2a.client import ProofInterceptor, ProofInterceptorOptions
from cheqd_agent_identity_a2a.gate import verify_caller
from cheqd_agent_identity_a2a.proof.signer import ed25519_signer_from_jwk
from cheqd_agent_identity_a2a.proof.verify import VerifyProofDeps

CLIENT_DID = "did:web:client.example"
CLIENT_KID = f"{CLIENT_DID}#key-1"
SERVER_DID = "did:web:server.example"
EXT_URI = "https://cheqd.io/a2a/ext/trust/v1"


def _wire_roundtrip(wire: dict) -> dict:
    """Parse incoming wire JSON into a real `SendMessageRequest` proto, then back into a dict -
    exactly what a real `a2a-sdk` JSON-RPC/REST dispatcher does before `on_message_send` ever
    sees it (`jsonrpc_dispatcher.py`'s own `ParseDict`/`MessageToDict`, read directly).
    """
    request_proto = ParseDict(wire, SendMessageRequest(), ignore_unknown_fields=True)
    return MessageToDict(request_proto)


async def mint() -> None:
    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    pub_bytes = private_key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode("ascii")
    d = base64.urlsafe_b64encode(seed).rstrip(b"=").decode("ascii")
    private_jwk = {"kty": "OKP", "crv": "Ed25519", "x": x, "d": d}
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}

    signer = ed25519_signer_from_jwk(did=CLIENT_DID, kid=CLIENT_KID, private_jwk=private_jwk)
    interceptor = ProofInterceptor(
        ProofInterceptorOptions(
            signer=signer,
            server_did=SERVER_DID,
            client_did=CLIENT_DID,
            # Only before() is exercised here; see the TS script's mint() for the same note.
            server_public_jwk={"kty": "OKP", "crv": "Ed25519", "x": "unused", "kid": f"{SERVER_DID}#key-1"},
            extension_uri=EXT_URI,
        )
    )
    params, _headers = await interceptor.before(
        "SendMessage", {"message": {"parts": [{"text": "hello from a real Python client"}]}}
    )
    wire = _wire_roundtrip(params)
    json.dump(
        {
            "wire": wire,
            "clientDid": CLIENT_DID,
            "clientKid": CLIENT_KID,
            "clientPublicJwk": public_jwk,
            "serverDid": SERVER_DID,
        },
        sys.stdout,
    )


async def verify() -> None:
    payload = json.load(sys.stdin)
    wire = _wire_roundtrip(payload["wire"])

    async def resolve_key(kid: str):
        if kid != payload["clientKid"]:
            raise AssertionError(f"unexpected kid {kid}")
        return payload["clientPublicJwk"]

    async def resolve_did_keys(did: str):
        return [payload["clientPublicJwk"]] if did == payload["clientDid"] else []

    seen_nonces: set[tuple[str, str]] = set()

    async def consume(nonce: str, did: str, _min_ttl: float) -> bool:
        key = (did, nonce)
        if key in seen_nonces:
            return False
        seen_nonces.add(key)
        return True

    deps = VerifyProofDeps(
        resolve_key=resolve_key,
        resolve_did_keys=resolve_did_keys,
        expected_audience=payload["serverDid"],
        consume_nonce_if_fresh=consume,
    )
    user = await verify_caller("SendMessage", wire, deps)
    if not user.is_authenticated or user.verified is None:
        print(json.dumps({"ok": False, "rejection": user.rejection}), file=sys.stderr)
        sys.exit(1)
    print(json.dumps({"ok": True, "did": user.verified.did}))


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "mint":
        asyncio.run(mint())
    elif mode == "verify":
        asyncio.run(verify())
    else:
        print("usage: python conformance_cross_language.py <mint|verify>", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
