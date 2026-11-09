# SPDX-License-Identifier: Apache-2.0
from cheqd_agent_identity.linkage.reciprocal_linkage import LinkageDidDocument, verify_reciprocal_linkage

CHEQD = LinkageDidDocument(id="did:cheqd:testnet:abc", also_known_as=["did:web:agent.example"])
WEB = LinkageDidDocument(id="did:web:agent.example", also_known_as=["did:cheqd:testnet:abc"])


def test_reciprocal_linkage_in_both_directions_is_accepted():
    result = verify_reciprocal_linkage(CHEQD, WEB)
    assert result.ok is True


def test_order_does_not_matter():
    result = verify_reciprocal_linkage(WEB, CHEQD)
    assert result.ok is True


def test_a_one_directional_claim_a_names_b_b_does_not_name_a_is_rejected():
    unreciprocated_web = LinkageDidDocument(id="did:web:agent.example", also_known_as=[])
    result = verify_reciprocal_linkage(CHEQD, unreciprocated_web)
    assert result.ok is False
    assert "b_does_not_name_a" in result.reasons


def test_a_one_directional_claim_the_other_way_is_rejected():
    unreciprocated_cheqd = LinkageDidDocument(id="did:cheqd:testnet:abc", also_known_as=[])
    result = verify_reciprocal_linkage(unreciprocated_cheqd, WEB)
    assert result.ok is False
    assert "a_does_not_name_b" in result.reasons


def test_a_missing_also_known_as_on_either_side_is_rejected_not_treated_as_vacuously_true():
    no_field = LinkageDidDocument(id="did:web:agent.example")
    result = verify_reciprocal_linkage(CHEQD, no_field)
    assert result.ok is False
    assert "b_does_not_name_a" in result.reasons


def test_neither_side_naming_the_other_is_rejected_with_both_reasons():
    result = verify_reciprocal_linkage(
        LinkageDidDocument(id="did:a", also_known_as=[]), LinkageDidDocument(id="did:b", also_known_as=[])
    )
    assert result.reasons == ("a_does_not_name_b", "b_does_not_name_a")


def test_a_document_naming_itself_as_both_sides_is_rejected():
    self_doc = LinkageDidDocument(id="did:a", also_known_as=["did:a"])
    result = verify_reciprocal_linkage(self_doc, self_doc)
    assert result.ok is False
    assert "same_did" in result.reasons
