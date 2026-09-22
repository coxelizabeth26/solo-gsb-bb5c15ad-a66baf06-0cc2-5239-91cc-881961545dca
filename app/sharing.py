"""Shamir threshold secret sharing over GF(256) and share serialisation."""

from __future__ import annotations

import base64
import json
import secrets

from . import gf256

MAX_SHARES = 255
MIN_THRESHOLD = 2


def split_secret(secret: bytes, threshold: int, total: int) -> list[tuple[int, bytes]]:
    """Split ``secret`` into ``total`` shares, any ``threshold`` of which recover it.

    Returns ``(x, y_bytes)`` pairs with x in 1..total. Each secret byte gets an
    independent random degree-(threshold-1) polynomial, so the split leaks no
    information about the key.
    """
    if not 1 <= threshold <= MAX_SHARES:
        raise ValueError("threshold must be between 1 and 255")
    if not threshold <= total <= MAX_SHARES:
        raise ValueError("total must be between threshold and 255")
    if threshold < MIN_THRESHOLD:
        # One share reconstructs everything, which defeats the threshold goal.
        raise ValueError("threshold must be at least 2")
    if not secret:
        raise ValueError("secret must not be empty")

    ys = [bytearray() for _ in range(total)]
    for byte in secret:
        # Highest-degree coefficient first, constant term is the secret byte.
        coeffs = [secrets.randbelow(256) for _ in range(threshold - 1)] + [byte]
        for x in range(1, total + 1):
            ys[x - 1].append(gf256.poly_eval(coeffs, x))
    return [(x, bytes(y)) for x, y in enumerate(ys, start=1)]


def reconstruct_secret(shares: list[tuple[int, bytes]]) -> bytes:
    """Reconstruct the secret from shares; raise if lengths differ or x collides."""
    if not shares:
        raise ValueError("at least one share is required")
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share indices")
    length = len(shares[0][1])
    if length == 0 or any(len(y) != length for _, y in shares):
        raise ValueError("shares have inconsistent lengths")

    recovered = bytearray(length)
    points = [(x, 0) for x, _ in shares]
    for pos in range(length):
        for i, (_, y) in enumerate(shares):
            points[i] = (points[i][0], y[pos])
        recovered[pos] = gf256.lagrange_interpolate_at_zero(points)
    return bytes(recovered)


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def encode_share(session_id: str, x: int, y: bytes) -> str:
    """Compact, self-describing share token: base64url(JSON [session_id, x, y])."""
    payload = json.dumps(
        [session_id, x, _b64e(y)], separators=(",", ":"), ensure_ascii=True
    )
    return _b64e(payload.encode("ascii"))


def decode_share(token: str) -> tuple[str, int, bytes]:
    """Parse a share token. Raises ValueError on any malformed input."""
    try:
        payload = json.loads(_b64d(token))
    except (ValueError, TypeError) as exc:
        raise ValueError("malformed share token") from exc
    if (
        not isinstance(payload, list)
        or len(payload) != 3
        or not isinstance(payload[0], str)
        or not isinstance(payload[1], int)
        or not isinstance(payload[2], str)
    ):
        raise ValueError("malformed share token")
    session_id, x, y_text = payload
    if not 1 <= x <= MAX_SHARES:
        raise ValueError("invalid share index")
    try:
        y = _b64d(y_text)
    except (ValueError, TypeError) as exc:
        raise ValueError("malformed share payload") from exc
    if not y:
        raise ValueError("empty share payload")
    return session_id, x, y
