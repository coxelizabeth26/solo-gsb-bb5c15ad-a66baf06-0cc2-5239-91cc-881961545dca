"""Arithmetic in GF(2^8) using the AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).

Shamir secret sharing is performed byte-wise: every secret byte is encoded as
the constant term of a random degree-(threshold-1) polynomial over this field.
GF(256) keeps the implementation independent of prime sizes and works for
secrets of arbitrary length without padding.
"""

from __future__ import annotations

_FIELD = 0x11B


def _build_tables() -> tuple[list[int], list[int]]:
    exp = [0] * 512
    log = [0] * 256
    value = 1
    for i in range(255):
        exp[i] = value
        log[value] = i
        # Multiply by the primitive generator 3: 3v = 2v XOR v, with 2v done
        # via xtime (left shift reduced by the field polynomial).
        value <<= 1
        if value & 0x100:
            value ^= _FIELD
        value ^= exp[i]
    # Duplicate the table so exp[i + j] with i + j up to 508 needs no modulo.
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


EXP, LOG = _build_tables()


def add(a: int, b: int) -> int:
    return a ^ b


def mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]


def inverse(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("zero has no inverse in GF(256)")
    return EXP[255 - LOG[a]]


def div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return EXP[(LOG[a] - LOG[b]) % 255]


def poly_eval(coeffs: list[int], x: int) -> int:
    """Evaluate polynomial (highest-degree coefficient first) at x via Horner."""
    if x == 0:
        return coeffs[-1]
    result = 0
    for coeff in coeffs:
        result = mul(result, x) ^ coeff
    return result


def lagrange_interpolate_at_zero(points: list[tuple[int, int]]) -> int:
    """Return f(0) given >= 1 points (x_i, y_i) of a polynomial over GF(256)."""
    secret = 0
    for i, (xi, yi) in enumerate(points):
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            numerator = mul(numerator, xj)
            denominator = mul(denominator, xi ^ xj)
        secret ^= mul(yi, div(numerator, denominator))
    return secret
