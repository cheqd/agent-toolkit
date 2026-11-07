"""The real `a2a-sdk` protobuf <-> dict bridge, deliberately kept OUT of `gate.py`/`client.py`
(see docs/design-decisions.md D15) so this module's own correctness - and its own test
failures - never get confused with the gate's. `gate.py`/`client.py` operate on plain
JSON-safe dicts; the real `a2a-sdk` dispatchers call `RequestHandler.on_message_send` with a
protobuf-typed `SendMessageRequest` and require a `Task | Message` protobuf back
(`request_handler.py`'s own signature, read directly - not assumed). This module is the
integrator's bridge between the two, built and tested against the REAL `a2a-sdk` package
installed in this repo's environment (`a2a.types.SendMessageRequest`/`Task`/`Message`), not a
hand-rolled stand-in for it.

**The one real finding this surfaced** (see `wrap_on_message_send`'s docstring and
`tests/test_proto_bridge.py`): `SendMessageRequest.message.metadata` is a
`google.protobuf.Struct`, whose `Value.number_value` is always a `double`. Every number
inside a proof that has round-tripped through a real `SendMessageRequest` - `created`,
`expires` - arrives at `gate.py` as a Python `float` (`1700000000.0`), never an `int`
(`1700000000`), even though the original wire JSON had no decimal point. Two things were
verified, not assumed, about what this means:

1. `rfc8785.dumps({"created": 1700000000.0})` and `rfc8785.dumps({"created": 1700000000})`
   produce byte-identical output - RFC 8785's number formatting already collapses an
   integral `float` to the same canonical form as the equivalent `int`, matching JavaScript's
   own number semantics (JS has no `int` type at all). The REQUEST-HASH fidelity D15 flagged
   as the security-sensitive open question is therefore NOT at risk from this - proven here,
   not assumed.
2. `CardProofMeta`'s (and `ResponseProofMeta`'s) strict parser WAS at risk: its
   `isinstance(value, int)` check would reject a well-formed proof's `created`/`expires`/`ts`
   outright once it arrived as a `float` from a real proto round trip. Fixed in
   `proof/types.py`'s `_coerce_non_negative_int` and `proof/response.py`'s `_wire_to_meta` to
   accept a whole-number `float` as equivalent to an `int` - matching what the TypeScript
   schema (`z.number().int()`) already accepted all along, since JS numbers are always
   doubles.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Union

from a2a.types import Message, SendMessageRequest, Task
from google.protobuf.json_format import MessageToDict, ParseDict

if TYPE_CHECKING:
    from a2a.server.context import ServerCallContext

    from cheqd_agent_identity_a2a.gate import AgentIdentityGate


def send_message_request_to_params(request: SendMessageRequest) -> dict[str, Any]:
    """Convert a real `SendMessageRequest` protobuf message into the plain dict
    `gate.py`'s `AgentIdentityGate.handle_send_message`/`verify_caller` and `covered_request`
    expect as `params` (`{"message": {...}, "configuration": {...}}`). Uses `MessageToDict`
    with its default camelCase field naming, matching the shape the real `a2a-sdk` JSON-RPC
    and REST dispatchers already produce on the wire (`jsonrpc_dispatcher.py`'s own
    `ParseDict`/`MessageToDict` calls, read directly - this module mirrors that convention,
    not a new one).
    """
    return MessageToDict(request)


def result_dict_to_proto(result: dict[str, Any]) -> Union[Task, Message]:
    """Convert `gate.py`'s dict result (with the response-proof already attached to
    `metadata`) back into the real `Task` or `Message` protobuf the real `a2a-sdk`'s
    `on_message_send` contract requires returning (`request_handler.py`: `-> Task | Message`).
    Dispatches on the same `"status" in result` test `gate.py`'s own `handle_send_message`
    uses to distinguish the two (a `Message` result has no `status` field; a `Task` always
    does) - the two call sites MUST agree on this test, so this reuses it rather than
    re-deriving it.
    """
    target = Task() if "status" in result else Message()
    return ParseDict(result, target, ignore_unknown_fields=True)


async def wrap_on_message_send(
    *,
    gate: "AgentIdentityGate",
    request: SendMessageRequest,
    context: "ServerCallContext",
    real_on_message_send: Callable[
        [SendMessageRequest, "ServerCallContext"], Awaitable[Union[Task, Message]]
    ],
) -> Union[Task, Message]:
    """The actual drop-in replacement for a real `a2a-sdk` `RequestHandler.on_message_send`:
    converts the incoming `SendMessageRequest` to the dict `gate.py` verifies against, runs
    the gate around the REAL handler (`real_on_message_send` - e.g. a
    `DefaultRequestHandler`'s own method, bound), and converts the gate's dict result back
    into the `Task | Message` protobuf the SDK's dispatchers require returning. `real_on_message_send`
    still receives the original, untouched protobuf `request` - this module never
    reconstructs a `SendMessageRequest` from the dict, since the SDK's own handler expects
    the real thing, not a round-tripped approximation of it.
    """
    params_dict = send_message_request_to_params(request)

    async def call_through() -> dict[str, Any]:
        result = await real_on_message_send(request, context)
        return MessageToDict(result)

    result_dict = await gate.handle_send_message("SendMessage", params_dict, call_through)
    return result_dict_to_proto(result_dict)
