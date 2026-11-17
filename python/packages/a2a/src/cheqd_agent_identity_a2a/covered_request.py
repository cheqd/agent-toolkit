"""The A2A canonical request shape - the one genuinely new piece of this binding.
`covered_request` (below) itself strips exactly one thing: `PROOF_META_KEY` from
`params.message.metadata` (dropping `message.metadata` entirely if that empties it) - and that
key alone, nothing else in `message.metadata`.

`request_hash`, however, is NOT hashed directly from this function's output: `compute_request_hash`
(`proof/canonical.py`, ported from `@kya-os/mcp`'s `card/proof/canonical.ts`) takes the covered
form produced here and applies ONE MORE stripping step before canonicalizing - it also removes
the top-level `params._meta` member, the MCP transport-metadata carrier (it carries the proof
itself, so it can never be part of the signed material). That means `params._meta` is UNSIGNED,
UNVERIFIED data end to end: nothing here or in `compute_request_hash` authenticates it, so
whatever a sender puts there travels unchecked by this binding. It is harmless today only
because the SDK's `fromJSON`/`ParseDict` already drop `_meta` before this code ever sees it -
do not rely on that incidentally, and do not treat `params._meta` as verified input if that
ever changes.

Found by review: an earlier version also stripped a second, `"org.kya-os/proof@1"`, key from
the covered form, as a "legacy mirror" of `PROOF_META_KEY`. Nothing in this codebase - not this
package's `gate.py`, not the TS port's `user-builder.ts`/`grpc-user-builder.ts` - ever reads
that key as a verification input; it was never anything but write-only dead weight. Excluding
ANY `message.metadata` key from the covered/signed form is only safe when that key is also
verified by some other means - otherwise excluding it from coverage is exactly how you let an
attacker smuggle unsigned data into `message.metadata` (and, since the gate never substitutes
the covered form back into the request that actually gets processed, into task history too)
past a proof that is otherwise genuinely valid: the proof's own signature never covered that
field, so putting anything there, or changing it after the fact, does not invalidate it. Do not
add another excluded key here unless something actually reads and verifies it.

DRAFT - early exploration, not reviewed or stable. See the repository README.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

PROOF_META_KEY = "org.kya-os/request-proof"
RESPONSE_PROOF_META_KEY = "org.kya-os/response-proof"


@dataclass(frozen=True)
class CoveredRequest:
    method: str
    params: Any


def covered_request(method: str, wire_params: Any) -> CoveredRequest:
    """Build the covered form of an A2A `SendMessage` / `SendStreamingMessage` request: the
    wire `params` with `message.metadata[PROOF_META_KEY]` removed, and `message.metadata`
    removed entirely if that empties it. `method` MUST be the wire method name (`SendMessage`,
    `SendStreamingMessage`) - never the v0.3 `message/send` spelling.
    """
    params = copy.deepcopy(wire_params)
    message = params.get("message") if isinstance(params, dict) else None
    metadata = message.get("metadata") if isinstance(message, dict) else None
    if isinstance(metadata, dict):
        metadata.pop(PROOF_META_KEY, None)
        if len(metadata) == 0 and "metadata" in message:
            del message["metadata"]
    return CoveredRequest(method=method, params=params)


def covered_result(result: dict[str, Any]) -> dict[str, Any]:
    """The covered form of a final result, with the response proof key removed from its
    metadata.
    """
    covered = copy.deepcopy(result)
    metadata = covered.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop(RESPONSE_PROOF_META_KEY, None)
        if len(metadata) == 0:
            covered.pop("metadata", None)
    return covered
