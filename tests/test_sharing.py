"""Unit tests for GF(256) Shamir split/reconstruct and share encoding."""

import os
import random

import pytest

from app import gf256, sharing


@pytest.mark.parametrize("seed", range(20))
def test_split_and_recover(seed):
    random.seed(seed)
    secret = os.urandom(random.randint(1, 64))
    t = random.randint(2, 4)
    n = random.randint(t, 8)
    shares = sharing.split_secret(secret, t, n)
    assert len(shares) == n

    # Exactly the threshold, chosen randomly, must recover.
    chosen = random.sample(shares, t)
    assert sharing.reconstruct_secret(chosen) == secret

    # More than the threshold must also recover.
    if n > t:
        chosen = random.sample(shares, t + 1)
        assert sharing.reconstruct_secret(chosen) == secret


def test_all_threshold_subsets_of_small_case():
    secret = b"abcdef"
    shares = sharing.split_secret(secret, 3, 5)
    from itertools import combinations

    for combo in combinations(shares, 3):
        assert sharing.reconstruct_secret(list(combo)) == secret


def test_below_threshold_gives_wrong_or_no_secret():
    # t-1 shares must not yield the constant terms deterministically.
    secret = b"\x00" * 8
    shares = sharing.split_secret(secret, 3, 5)
    recovered = sharing.reconstruct_secret(shares[:2])
    # With probability overwhelming the random degree-2 poly reduces to
    # something other than the all-zero secret.
    assert recovered != secret


def test_share_indexes_start_at_one():
    shares = sharing.split_secret(b"x", 2, 3)
    assert [x for x, _ in shares] == [1, 2, 3]


def test_share_length_equals_secret_length():
    secret = os.urandom(17)
    shares = sharing.split_secret(secret, 2, 4)
    assert all(len(y) == 17 for _, y in shares)


def test_encode_decode_roundtrip():
    shares = sharing.split_secret(b"hello", 2, 3)
    sid = "abc123"
    tokens = [sharing.encode_share(sid, x, y) for x, y in shares]
    for token, (x, y) in zip(tokens, shares):
        psid, px, py = sharing.decode_share(token)
        assert (psid, px, py) == (sid, x, y)


@pytest.mark.parametrize(
    "bad",
    ["", "not-base64!!!", "AA", "###", "eyJhIjoxfQ"],  # last decodes to JSON non-list
)
def test_decode_rejects_garbage(bad):
    with pytest.raises(ValueError):
        sharing.decode_share(bad)


def test_tampered_share_fails_digest():
    """Flipping any share byte changes its digest -> integrity check rejects."""
    from app.database import share_digest

    shares = sharing.split_secret(b"topsecret", 3, 5)
    sid = "sess1"
    x, y = shares[0]
    good = share_digest(sid, x, y)
    tampered = bytearray(y)
    tampered[0] ^= 0x01
    assert share_digest(sid, x, bytes(tampered)) != good
    assert share_digest("other", x, y) != good


def test_gf256_basic_identities():
    for a in range(256):
        assert gf256.mul(a, 0) == 0
        assert gf256.mul(a, 1) == a
        if a:
            assert gf256.mul(a, gf256.inverse(a)) == 1
    assert gf256.mul(0x53, 0xCA) == 0x01  # known AES-field value
