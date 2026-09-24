"""Pure Python Ed25519 signature verification with support for Ed25519ph.

The cryptography package does not expose the prehashed Ed25519ph variant from
RFC 8032, which Keygen uses to sign release artifacts, so it is implemented
here. Only verification is needed, which works on public data alone.
"""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

_Point = Tuple[int, int, int, int]

_DOM2_PREFIX = b"SigEd25519 no Ed25519 collisions"


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _add(p: _Point, q: _Point) -> _Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _multiply(scalar: int, point: _Point) -> _Point:
    result: _Point = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p: _Point, q: _Point) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _decompress(data: bytes) -> Optional[_Point]:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


_BASE_Y = 4 * pow(5, _P - 2, _P) % _P
_BASE_X = _recover_x(_BASE_Y, 0)
assert _BASE_X is not None
_BASE: _Point = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)


def _domain(prehashed: bool, context: bytes) -> bytes:
    if not prehashed and not context:
        return b""
    return _DOM2_PREFIX + bytes([1 if prehashed else 0, len(context)]) + context


def verify(
    public_key: bytes,
    message: bytes,
    signature: bytes,
    *,
    prehashed: bool = False,
    context: bytes = b"",
) -> bool:
    """Verify an Ed25519, Ed25519ctx or Ed25519ph signature.

    When ``prehashed`` is true, ``message`` must already be the SHA-512
    digest of the signed data.
    """
    if len(public_key) != 32 or len(signature) != 64 or len(context) > 255:
        return False
    if prehashed and len(message) != 64:
        return False

    a = _decompress(public_key)
    if a is None:
        return False

    r_bytes = signature[:32]
    r = _decompress(r_bytes)
    if r is None:
        return False

    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False

    digest = hashlib.sha512(_domain(prehashed, context) + r_bytes + public_key + message).digest()
    k = int.from_bytes(digest, "little") % _L

    return _equal(_multiply(s, _BASE), _add(r, _multiply(k, a)))
