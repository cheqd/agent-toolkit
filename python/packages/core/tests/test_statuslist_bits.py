# SPDX-License-Identifier: Apache-2.0
# Tests the Bitstring Status List v1.0 primitives (statuslist_bits.py), ported from
# @kya-os/mcp/utils/statuslist-bits.ts - read directly, not reconstructed from prose.
import base64
import gzip
import platform
import resource

import pytest

from cheqd_agent_identity.status.statuslist_bits import (
    MAX_STATUS_LIST_BYTES,
    _default_decompress,
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


def _max_rss_bytes() -> int:
    """Peak resident set size observed so far, normalised to bytes (`ru_maxrss` is KiB on
    Linux, bytes on macOS - the platform this ran against while writing the regression)."""
    maxrss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return maxrss if platform.system() == "Darwin" else maxrss * 1024


def _highly_compressible_bomb(inflated_size: int) -> bytes:
    """A GZIP payload that is tiny on the wire but inflates to `inflated_size` zero bytes - the
    same shape the security review measured (a 1.39 MB `encodedList` inflating to 1.11 GB)."""
    return gzip.compress(bytes(inflated_size), compresslevel=9)


def test_default_decompress_rejects_an_oversized_payload_without_fully_inflating_it():
    """Regression for the decompression-bomb finding: `gzip.decompress` has no output limit,
    so it fully inflates (allocating the whole output buffer) BEFORE anything downstream can
    apply the `MAX_STATUS_LIST_BYTES` check - the check still fails closed, but only after the
    memory is already spent. `_default_decompress` must bound the output size WHILE inflating
    (`zlib.decompressobj(...).decompress(data, MAX_STATUS_LIST_BYTES + 1)`) so a bomb is
    rejected mid-stream instead.

    Measured the same way the review measured the bug: peak RSS before vs. after the call. A
    decompressor bounded during inflation never allocates anywhere near the bomb's full
    inflated size, so the increase stays small; one that is not bounded (`gzip.decompress`)
    allocates the whole ~128 MiB output buffer first, which this asserts against.
    """
    inflated_size = 128 * 1024 * 1024  # 128 MiB - far past the 16 MiB cap
    bomb = _highly_compressible_bomb(inflated_size)
    assert len(bomb) < 512 * 1024  # tiny on the wire, like the review's 1.39 MB example

    before = _max_rss_bytes()
    with pytest.raises(ValueError, match="too large"):
        _default_decompress(bomb)
    after = _max_rss_bytes()
    grew_by_mib = (after - before) / (1024 * 1024)

    # A generous margin above the ~16 MiB cap (decompressor state, the output buffer up to
    # MAX_STATUS_LIST_BYTES + 1, zlib's own window) - nowhere near the 128 MiB this bomb would
    # fully inflate to if it were not bounded during inflation.
    assert grew_by_mib < 100, (
        f"peak RSS grew by {grew_by_mib:.1f} MiB decompressing a bomb that should have been "
        "rejected mid-inflation, not after fully inflating"
    )


def test_default_decompress_still_inflates_a_legitimate_payload():
    bits = bytes([0b10100000, 0b00000000, 0xFF, 0x00])
    compressed = gzip.compress(bits)
    assert _default_decompress(compressed) == bits


def test_decode_status_list_payload_rejects_a_decompression_bomb_via_the_default_decompressor():
    """End-to-end: the same bomb, through the public `decode_status_list_payload` entry point
    `revocation.py` actually calls, using the real default decompressor (not an injected
    stand-in), so the bound is exercised exactly as production traffic would hit it."""
    inflated_size = 64 * 1024 * 1024  # 64 MiB - past the 16 MiB cap
    bomb = gzip.compress(bytes(inflated_size), compresslevel=9)
    encoded = "u" + base64.urlsafe_b64encode(bomb).rstrip(b"=").decode("ascii")
    with pytest.raises(ValueError, match="too large"):
        decode_status_list_payload(encoded)
