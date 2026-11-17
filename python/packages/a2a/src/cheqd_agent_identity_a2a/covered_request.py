"""The A2A canonical request shape - the one genuinely new piece of this binding.
`request_hash` MUST be computed over `{method, params}` with the proof metadata key removed
from `params.message.metadata`, and that key alone - nothing else stripped.

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
