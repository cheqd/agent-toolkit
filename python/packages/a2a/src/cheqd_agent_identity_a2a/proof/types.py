"""KYA-OS Entity Card — stateless per-request holder-of-key proof: shapes + constants.

`org.kya-os/proof.v1` is the stateless, sender-constrained proof profile this A2A binding
verifies. This is a from-spec Python re-implementation of `@kya-os/mcp/card`'s
`card/proof/types.ts` (MIT-licensed; read directly from `node_modules/@kya-os/mcp/dist`, not
reconstructed from documentation) - see docs/design-decisions.md D12 for why this exists
(no Python package implements this profile) and D13 for what was and wasn't ported.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, Optional, Union

PROOF_PROFILE_V1 = "org.kya-os/proof.v1"
LEGACY_PROOF_PROFILE_ID = "org.kya-os/proof@1"

KYA_OS_CARD_PROOF_META_KEY = "org.kya-os/request-proof"
LEGACY_CARD_PROOF_META_KEY = LEGACY_PROOF_PROFILE_ID

DEFAULT_TTL_SEC = 60
"""Default proof lifetime in seconds (SPEC §8: short-lived, <= 60s)."""

MAX_TTL_SEC = 60
"""Maximum accepted proof lifetime in seconds - a longer window fails closed."""

DEFAULT_SKEW_SEC = 5
"""Default accepted clock skew in seconds (+-) for the created/expires window."""

NONCE_RETENTION_SEC = MAX_TTL_SEC + 2 * DEFAULT_SKEW_SEC + 1
"""Minimum time a consumed nonce MUST be retained by the replay cache: the full verifier
acceptance window, plus one second of rounding headroom - see the TypeScript original's
doc comment for the full derivation."""

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_DID_RE = re.compile(r"^did:(key|web):.+$")
_KID_RE = re.compile(r"^did:(key|web):.+#.+$")


@dataclass(frozen=True)
class CardProofCnf:
    jkt: str


@dataclass(frozen=True)
class CardProofMeta:
    """The `org.kya-os/proof.v1` payload. Every field except the signature (`jws`) is a
    COVERED claim: the detached EdDSA/ES256 `jws` signs the RFC 8785 (JCS) canonicalization
    of the claims, so tampering any of them fails the signature.
    """

    prf: Literal["org.kya-os/proof.v1", "org.kya-os/proof@1"]
    alg: Literal["EdDSA", "ES256"]
    did: str
    kid: str
    audience: str
    nonce: str
    created: int
    expires: int
    request_hash: str
    jws: str
    cnf: Optional[CardProofCnf] = None
    http_sig: Optional[str] = None
    """The RFC 9421 HTTP Message Signature sibling's raw signature - present on any proof
    minted by a signer with a `signRaw` seam (e.g. `@kya-os/mcp`'s `ed25519SignerFromJwk`),
    whether or not this verifier ever checks it (see docs/design-decisions.md D13: http-sig.ts
    is not ported, since this package's gate never carries proofs over real HTTP headers). A
    strict verifier MUST still accept its presence - rejecting a well-formed proof merely
    because it carries this optional field would break interop with any real signer."""


@dataclass(frozen=True)
class ParsedCardProofOk:
    meta: CardProofMeta
    ok: bool = True


@dataclass(frozen=True)
class ParsedCardProofFailed:
    ok: bool = False


ParsedCardProofResult = Union[ParsedCardProofOk, ParsedCardProofFailed]


def _is_non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def parse_card_proof_meta(value: Any) -> ParsedCardProofResult:
    """Strict validation of a `CardProofMeta`-shaped dict: no unknown fields, matching
    `CardProofMetaSchema.strict()` in the TypeScript original - the covered-claims set IS
    the signed contract.
    """
    if not isinstance(value, dict):
        return ParsedCardProofFailed()

    known_keys = {
        "prf",
        "alg",
        "did",
        "kid",
        "audience",
        "nonce",
        "created",
        "expires",
        "requestHash",
        "cnf",
        "jws",
        "httpSig",
    }
    if not set(value.keys()) <= known_keys:
        return ParsedCardProofFailed()

    if value.get("prf") not in (PROOF_PROFILE_V1, LEGACY_PROOF_PROFILE_ID):
        return ParsedCardProofFailed()
    if value.get("alg") not in ("EdDSA", "ES256"):
        return ParsedCardProofFailed()
    did = value.get("did")
    if not isinstance(did, str) or not _DID_RE.match(did):
        return ParsedCardProofFailed()
    kid = value.get("kid")
    if not isinstance(kid, str) or not _KID_RE.match(kid):
        return ParsedCardProofFailed()
    audience = value.get("audience")
    if not isinstance(audience, str) or not _DID_RE.match(audience):
        return ParsedCardProofFailed()
    nonce = value.get("nonce")
    if not isinstance(nonce, str) or len(nonce) == 0 or not _BASE64URL_RE.match(nonce):
        return ParsedCardProofFailed()
    if not _is_non_negative_int(value.get("created")):
        return ParsedCardProofFailed()
    if not _is_non_negative_int(value.get("expires")):
        return ParsedCardProofFailed()
    request_hash = value.get("requestHash")
    if not isinstance(request_hash, str) or len(request_hash) == 0:
        return ParsedCardProofFailed()
    jws = value.get("jws")
    if not isinstance(jws, str) or len(jws) == 0:
        return ParsedCardProofFailed()
    http_sig = value.get("httpSig")
    if http_sig is not None and (not isinstance(http_sig, str) or len(http_sig) == 0):
        return ParsedCardProofFailed()

    cnf: Optional[CardProofCnf] = None
    if "cnf" in value:
        raw_cnf = value["cnf"]
        if not isinstance(raw_cnf, dict) or set(raw_cnf.keys()) != {"jkt"}:
            return ParsedCardProofFailed()
        jkt = raw_cnf.get("jkt")
        if not isinstance(jkt, str) or len(jkt) == 0 or not _BASE64URL_RE.match(jkt):
            return ParsedCardProofFailed()
        cnf = CardProofCnf(jkt=jkt)

    return ParsedCardProofOk(
        meta=CardProofMeta(
            prf=value["prf"],
            alg=value["alg"],
            did=did,
            kid=kid,
            audience=audience,
            nonce=nonce,
            created=value["created"],
            expires=value["expires"],
            request_hash=request_hash,
            jws=jws,
            http_sig=http_sig,
            cnf=cnf,
        )
    )
