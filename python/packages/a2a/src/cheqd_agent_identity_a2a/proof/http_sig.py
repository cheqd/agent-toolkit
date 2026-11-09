"""KYA-OS Entity Card proof — the RFC 9421 HTTP Message Signature sibling (DUAL carrier).

Ported from `@kya-os/mcp/card`'s `card/proof/http-sig.ts`, read directly from
`node_modules/@kya-os/mcp/dist`. The stateless proof carries TWO signatures by ONE DID key over
ONE semantic set: the detached JWS in `_meta` (canonical, for JSON-RPC/stdio) and this RFC 9421
sibling for HTTP verifiers that already ship (SEP-1960, Cloudflare Web Bot Auth). A JWS
signature also covers its protected header, so its bytes can NEVER satisfy a stock 9421
verifier reconstructing a bare signature base - the two carriers therefore require two
signatures. `http_sig` (minted by the signer's `sign_raw` seam) is a RAW signature over exactly
the base `http_signature_base` exposes, so a stock 9421 verifier reconstructs that base and
verifies `http_sig` against the resolved DID key with zero new code. If a signer omits
`sign_raw`, the proof has no `httpSig` and the sibling simply degrades away (the JWS carrier
still verifies).

Not wired into this package's `gate.py`/`client.py` - the A2A transports in use here are
JSON-RPC/REST/gRPC via the `a2a-sdk`, not real HTTP headers a generic RFC 9421 verifier reads -
so nothing in this package calls `verify_http_signature` on the gate's own behalf. This module
exists for integrators who DO put proofs on the wire as real HTTP headers (matching the
TypeScript original's scope exactly), and for cross-language conformance against
`@kya-os/mcp`'s own `http-sig.ts`.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
from typing import Any

from cheqd_agent_identity_a2a.proof.canonical import ed25519_verify_raw, es256_verify_raw
from cheqd_agent_identity_a2a.proof.types import CardProofMeta

HTTP_SIG_LABEL = "kyaos"
"""The signature label under which the KYA-OS covered components are grouped."""


def _covered_components(meta: CardProofMeta) -> str:
    comps = ['"content-digest"', '"kya-audience"', '"kya-nonce"']
    if meta.cnf is not None:
        comps.append('"kya-cnf"')
    return f"({' '.join(comps)})"


def _sig_params(meta: CardProofMeta) -> str:
    label = "ecdsa-p256-sha256" if meta.alg == "ES256" else "ed25519"
    return f'created={meta.created};expires={meta.expires};keyid="{meta.kid}";alg="{label}"'


def http_signature_base(meta: CardProofMeta) -> str:
    """The RFC 9421 signature base - the EXACT string a stock 9421 verifier reconstructs and
    the exact bytes `http_sig` signs. Deterministic and self-contained from the proof, so
    both the minter and a third-party verifier derive an identical base.
    """
    lines = [
        f'"content-digest": {meta.request_hash}',
        f'"kya-audience": {meta.audience}',
        f'"kya-nonce": {meta.nonce}',
    ]
    if meta.cnf is not None:
        lines.append(f'"kya-cnf": {meta.cnf.jkt}')
    lines.append(f'"@signature-params": {_covered_components(meta)};{_sig_params(meta)}')
    return "\n".join(lines)


def http_signature_base_bytes(meta: CardProofMeta) -> bytes:
    """The UTF-8 bytes of `http_signature_base` - the payload the `sign_raw` seam signs at
    mint.
    """
    return http_signature_base(meta).encode("utf-8")


def _b64url_to_b64(b64url: str) -> str:
    padded = b64url + "=" * (-len(b64url) % 4)
    return base64.b64encode(base64.urlsafe_b64decode(padded)).decode("ascii")


def to_http_message_signature(meta: CardProofMeta) -> dict[str, str]:
    """Project a minted `org.kya-os/proof.v1` into its RFC 9421 header set. Emits every
    covered component as a real HTTP field - `Content-Digest`/`Kya-Audience`/`Kya-Nonce` (and
    `Kya-Cnf` when a `cnf` is present), each byte-identical to its `http_signature_base`
    line - plus `Signature-Input` (the covered-component list + params) and `Signature` (the
    RAW `http_sig` as a base64 byte sequence). Raises when the proof has no `http_sig` (minted
    without a `sign_raw`-capable signer): there is no cross-verifiable sibling to project, and
    emitting the JWS bytes here would be silently unverifiable.
    """
    if not meta.http_sig:
        raise ValueError("card/proof: proof carries no httpSig; mint with a sign_raw-capable signer")
    headers = {
        "Content-Digest": meta.request_hash,
        "Kya-Audience": meta.audience,
        "Kya-Nonce": meta.nonce,
        "Signature-Input": f"{HTTP_SIG_LABEL}={_covered_components(meta)};{_sig_params(meta)}",
        "Signature": f"{HTTP_SIG_LABEL}=:{_b64url_to_b64(meta.http_sig)}:",
    }
    if meta.cnf is not None:
        headers["Kya-Cnf"] = meta.cnf.jkt
    return headers


def verify_http_signature(meta: CardProofMeta, key: dict[str, Any]) -> bool:
    """Verify the sibling exactly as a stock RFC 9421 verifier would: reconstruct
    `http_signature_base` and check the RAW `http_sig` against `key` (the resolved DID
    verification key). Fail-closed - returns `False` when the proof carries no `http_sig` or
    the signature does not verify.

    CONTRACT: dispatches on the KEY type (P-256 -> `ecdsa-p256-sha256`, Ed25519 -> `ed25519`),
    NOT on `meta.alg`. It ASSUMES the caller has already bound `meta.alg` to the key type (the
    `alg_key_mismatch` check in `verify.py`'s `_key_matches_alg`); call this standalone only
    after that binding holds.
    """
    if not meta.http_sig:
        return False
    padded = meta.http_sig + "=" * (-len(meta.http_sig) % 4)
    signature = base64.urlsafe_b64decode(padded)
    base = http_signature_base_bytes(meta)
    if key.get("kty") == "EC":
        return es256_verify_raw(key, signature, base)
    return ed25519_verify_raw(key, signature, base)
