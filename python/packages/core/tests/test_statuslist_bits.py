# SPDX-License-Identifier: Apache-2.0
# Tests the Bitstring Status List v1.0 primitives (statuslist_bits.py), ported from
# @kya-os/mcp/utils/statuslist-bits.ts - read directly, not reconstructed from prose.
import base64
import gzip

import pytest

from cheqd_agent_identity.status.statuslist_bits import (
    MAX_STATUS_LIST_BYTES,
    assert_status_purpose,
    decode_status_list_payload,
    parse_status_list_index,
    read_status_bit,
)


def _encode(bits: bytes) -> str:
    compressed = gzip.compress(bits)
    return "u" + base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")


def test_parse_status_list_index_accepts_canonical_decimal():
    assert parse_status_list_index("42") == 42
    assert parse_status_list_index("0") == 0


@pytest.mark.parametrize("raw", ["0x2A", " 42", "+42", "1e1", "-1", "4.2", ""])
def test_parse_status_list_index_rejects_non_canonical_forms(raw):
    with pytest.raises(ValueError):
        parse_status_list_index(raw)


def test_read_status_bit_is_msb_first():
    bits = bytes([0b10000000, 0b00000001])
    assert read_status_bit(bits, 0) is True
    assert read_status_bit(bits, 1) is False
    assert read_status_bit(bits, 15) is True
    assert read_status_bit(bits, 14) is False


def test_read_status_bit_out_of_range_raises():
    with pytest.raises(ValueError):
        read_status_bit(bytes([0]), 8)


def test_read_status_bit_negative_index_raises():
    with pytest.raises(ValueError):
        read_status_bit(bytes([0]), -1)


def test_decode_status_list_payload_round_trips_a_real_gzip_bitstring():
    bits = bytes([0b10100000, 0b00000000])
    encoded = _encode(bits)
    assert decode_status_list_payload(encoded) == bits


def test_decode_status_list_payload_accepts_without_multibase_prefix():
    bits = bytes([0b00000001])
    encoded = _encode(bits)[1:]  # strip the leading "u"
    assert decode_status_list_payload(encoded) == bits


def test_decode_status_list_payload_rejects_non_gzip():
    not_gzip = "u" + base64.urlsafe_b64encode(b"not gzip data").rstrip(b"=").decode("ascii")
    with pytest.raises(ValueError, match="not GZIP"):
        decode_status_list_payload(not_gzip)


def test_decode_status_list_payload_rejects_a_pass_through_decompressor():
    bits = bytes([0, 0])
    encoded = _encode(bits)

    def pass_through(data: bytes) -> bytes:
        return data

    with pytest.raises(ValueError, match="unchanged"):
        decode_status_list_payload(encoded, pass_through)


def test_decode_status_list_payload_rejects_oversized_inflation():
    bits = bytes([0, 0])
    encoded = _encode(bits)

    def oversized(_data: bytes) -> bytes:
        return bytes(MAX_STATUS_LIST_BYTES + 1)

    with pytest.raises(ValueError, match="too large"):
        decode_status_list_payload(encoded, oversized)


def test_assert_status_purpose_accepts_a_match():
    assert_status_purpose("revocation", "revocation")


@pytest.mark.parametrize("purpose", [None, 42, "suspension"])
def test_assert_status_purpose_rejects_missing_or_mismatched(purpose):
    with pytest.raises(ValueError):
        assert_status_purpose(purpose, "revocation")
