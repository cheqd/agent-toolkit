"""Status-list primitives — the ONE home for the mechanics every W3C status-list reader in
this package shares (StatusList2021 / Bitstring Status List v1.0): canonical index parsing,
bounded GZIP inflation, and the MSB-first bit read.

Ported from `@kya-os/mcp/utils/statuslist-bits.ts` and `statuslist-purpose.ts`, read directly
from `node_modules/@kya-os/mcp/dist`, for `revocation.py`'s `create_revocation_checker` - see
docs/design-decisions.md D10 (this module, along with `revocation.py`/`status_list_proof.py`/
`eddsa_jcs_status.py`, is the Python re-specification of the provider seams D10 originally
left unported, now built because a consumer needs the proof-based status-list path
specifically).

Deliberate deviation from the TypeScript original: `decode_status_list_payload`'s
`decompress` seam is a plain SYNCHRONOUS `bytes -> bytes` callable, not an async one. The
TypeScript seam is async because it dynamically `import()`s `node:zlib` so a Workers/browser
bundle can inject `CompressionStream`/`DecompressionStream` instead and keep `node:zlib` out
of its graph - a concern with no Python equivalent (Python's `gzip` module has no bundler to
avoid), so the extra `await` plumbing would be ceremony with nothing to defer.

FAIL-CLOSED throughout: a non-canonical index, an oversized inflation, a payload that is not
GZIP, or an unreadable bit raises rather than reading as "not revoked".

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import gzip
import re
from typing import Callable

MAX_STATUS_LIST_BYTES = 16 * 1024 * 1024
"""Hard ceiling on an INFLATED status bitstring (16 MiB ≈ 134M entries - far beyond any
herd-privacy list). A fixed cap costs nothing legitimate while stopping a decompression
bomb; exceeding it raises (fail-closed)."""

MULTIBASE_BASE64URL = "u"
"""The W3C Bitstring Status List `encodedList` multibase prefix (base64url, no padding)."""

Decompress = Callable[[bytes], bytes]

_CANONICAL_DECIMAL_RE = re.compile(r"^[0-9]+$")
_PYTHON_SAFE_INTEGER = 2**53 - 1


def parse_status_list_index(raw: str) -> int:
    """Parse a decimal `statusListIndex` (a non-negative integer expressed as a string),
    fail-closed. Canonical decimal ONLY: a looser parse would silently accept whitespace,
    hex, a leading `+`, or exponent notation - reading a DIFFERENT (often clear) bit than the
    credential names, so a revoked credential could read as live.
    """
    if not _CANONICAL_DECIMAL_RE.match(raw):
        raise ValueError(f'Invalid statusListIndex "{raw}" - must be a canonical non-negative decimal')
    index = int(raw)
    if index > _PYTHON_SAFE_INTEGER:
        raise ValueError(f'statusListIndex "{raw}" exceeds the safe integer range')
    return index


def _is_gzip(data: bytes) -> bool:
    return len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B


def _default_decompress(data: bytes) -> bytes:
    return gzip.decompress(data)


def decode_status_list_payload(encoded_list: str, decompress: Decompress = _default_decompress) -> bytes:
    """Decode a status-list `encodedList` to the raw bitstring: strip the optional multibase
    `u` prefix, base64url-decode, run the injected decompressor, and re-check
    `MAX_STATUS_LIST_BYTES` POST-inflation as a backstop (a production decompressor SHOULD
    also bound output during inflation; `gzip.decompress` does not, so this check is
    load-bearing here, not merely defensive).

    Raises when the payload is not GZIP, and when the decompressor hands back its GZIP input
    unchanged (a pass-through): read as a bitstring, the GZIP header would clear bits the
    issuer set, so a revoked credential would read as live.
    """
    payload = encoded_list[1:] if encoded_list[:1] == MULTIBASE_BASE64URL else encoded_list
    padded = payload + "=" * (-len(payload) % 4)
    compressed = base64.urlsafe_b64decode(padded)
    if not _is_gzip(compressed):
        raise ValueError("Status list encodedList is not GZIP")
    inflated = decompress(compressed)
    if inflated == compressed:
        raise ValueError("Status list decompressor returned its GZIP input unchanged: it must inflate GZIP")
    if len(inflated) > MAX_STATUS_LIST_BYTES:
        raise ValueError(f"Status list too large: {len(inflated)} bytes exceeds {MAX_STATUS_LIST_BYTES}")
    return inflated


def read_status_bit(bits: bytes, index: int) -> bool:
    """Read the status bit at `index` - MSB-first within each byte (W3C Bitstring encoding).
    NaN/negative/fractional/out-of-buffer indexes raise.
    """
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ValueError(f"Bit index {index} out of range for the status list")
    byte_index = index // 8
    if byte_index >= len(bits):
        raise ValueError(f"Bit index {index} out of range for the status list")
    byte = bits[byte_index]
    return (byte & (0x80 >> (index % 8))) != 0


def assert_status_purpose(list_purpose: object, wanted: str) -> None:
    """Fail CLOSED unless the resolved status list's `statusPurpose` is present AND equals
    `wanted`. A list of a DIFFERENT kind (e.g. a `suspension` list read as `revocation`) must
    not be accepted - its clear bit would otherwise report "not revoked" from the wrong list,
    a fail-open bypass.
    """
    if not isinstance(list_purpose, str):
        raise ValueError(f'status list has no statusPurpose (expected "{wanted}") - fail-closed')
    if list_purpose != wanted:
        raise ValueError(f'status list statusPurpose mismatch: "{list_purpose}" != "{wanted}"')
