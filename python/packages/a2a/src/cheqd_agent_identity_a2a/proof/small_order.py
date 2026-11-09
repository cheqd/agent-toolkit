"""The small-order Ed25519 public-key check every verification path in `@kya-os/mcp` applies,
ported from `utils/ed25519-public-key.ts`. Under a small-order key (order 1, 2, 4 or 8), the
signature R = identity, S = 0 satisfies the verification equation for EVERY message - anyone
could sign as it. `cryptography`'s Ed25519 verification does not reject these on its own, so
this check is load-bearing, not redundant.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

ED25519_KEY_SIZE = 32

_SMALL_ORDER_ENCODINGS = (
    bytes(32),  # 0 (order 4)
    bytes([1] + [0] * 31),  # 1 (order 1): the identity
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),  # order 8
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),  # order 8
    bytes([0xEC] + [0xFF] * 30 + [0x7F]),  # p - 1 (order 2)
    bytes([0xED] + [0xFF] * 30 + [0x7F]),  # p, a non-canonical 0 (order 4)
    bytes([0xEE] + [0xFF] * 30 + [0x7F]),  # p + 1, a non-canonical 1 (order 1)
)


def is_small_order_ed25519_key(key: bytes) -> bool:
    """True if `key` (32 bytes) encodes a point of small order, under either sign bit."""
    for blocked in _SMALL_ORDER_ENCODINGS:
        if all((key[i] & 0x7F if i == 31 else key[i]) == blocked[i] for i in range(32)):
            return True
    return False
