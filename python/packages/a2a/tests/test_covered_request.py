# SPDX-License-Identifier: Apache-2.0
# No TypeScript test file exists for covered-request.ts (it's exercised indirectly through the
# gate tests that are not ported here - see docs/design-decisions.md D12). These tests check
# its own documented contract directly: strip PROOF_META_KEY/LEGACY_PROOF_META_KEY and nothing
# else, drop message.metadata entirely only if that empties it.
from cheqd_agent_identity_a2a.covered_request import (
    LEGACY_PROOF_META_KEY,
    PROOF_META_KEY,
    RESPONSE_PROOF_META_KEY,
    covered_request,
    covered_result,
)


def test_strips_the_proof_key_from_message_metadata():
    wire_params = {"message": {"metadata": {PROOF_META_KEY: "sig", "other": "keep-me"}}}
    covered = covered_request("SendMessage", wire_params)
    assert covered.method == "SendMessage"
    assert covered.params["message"]["metadata"] == {"other": "keep-me"}


def test_strips_the_legacy_proof_key_too():
    wire_params = {"message": {"metadata": {LEGACY_PROOF_META_KEY: "sig"}}}
    covered = covered_request("SendMessage", wire_params)
    assert "metadata" not in covered.params["message"]


def test_drops_metadata_entirely_once_emptied_by_stripping_the_proof_key():
    wire_params = {"message": {"metadata": {PROOF_META_KEY: "sig"}}}
    covered = covered_request("SendMessage", wire_params)
    assert "metadata" not in covered.params["message"]


def test_does_not_mutate_the_original_wire_params():
    wire_params = {"message": {"metadata": {PROOF_META_KEY: "sig", "other": "keep-me"}}}
    covered_request("SendMessage", wire_params)
    assert wire_params["message"]["metadata"][PROOF_META_KEY] == "sig"


def test_covered_result_strips_the_response_proof_key():
    result = {"status": "ok", "metadata": {RESPONSE_PROOF_META_KEY: "sig", "other": "keep-me"}}
    covered = covered_result(result)
    assert covered["metadata"] == {"other": "keep-me"}


def test_covered_result_drops_metadata_entirely_once_emptied():
    result = {"status": "ok", "metadata": {RESPONSE_PROOF_META_KEY: "sig"}}
    covered = covered_result(result)
    assert "metadata" not in covered
