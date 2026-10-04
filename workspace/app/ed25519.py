"""最小 Ed25519 实现（RFC 8032），仅依赖 Python 标准库。

供离线验真使用：公钥可随发布信封导出，不依赖服务端在线状态。
"""
from __future__ import annotations

import hashlib
from typing import Tuple

Point = Tuple[int, int]

p = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, p - 2, p)) % p
I = pow(2, (p - 1) // 4, p)


def _inv(x: int) -> int:
    return pow(x, p - 2, p)


def xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = (x * I) % p
    if x % 2 != 0:
        x = p - x
    return x


By = 4 * _inv(5)
Bx = xrecover(By)
B: Point = (Bx, By)


def edwards_add(P: Point, Q: Point) -> Point:
    x1, y1 = P
    x2, y2 = Q
    den_x = _inv(1 + d * x1 * x2 * y1 * y2)
    den_y = _inv(1 - d * x1 * x2 * y1 * y2)
    x3 = (x1 * y2 + x2 * y1) * den_x
    y3 = (y1 * y2 + x1 * x2) * den_y
    return x3 % p, y3 % p


def scalarmult(P: Point, e: int) -> Point:
    if e == 0:
        return 0, 1
    Q = scalarmult(P, e // 2)
    Q = edwards_add(Q, Q)
    if e & 1:
        Q = edwards_add(Q, P)
    return Q


def encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def encodepoint(P: Point) -> bytes:
    x, y = P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes([
        sum(bits[i + j] << j for j in range(8))
        for i in range(0, 256, 8)
    ])


def bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def hint(m: bytes) -> int:
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def decodeint(s: bytes) -> int:
    return int.from_bytes(s[:32], "little")


def decodepoint(s: bytes) -> Point:
    y = 0
    for i, b in enumerate(s[:-1]):
        y += b << (8 * i)
    y += (s[-1] & 0x7F) << (8 * 31)
    x = xrecover(y)
    if (x & 1) != (s[-1] >> 7):
        x = p - x
    P = x, y
    if not is_on_curve(P):
        raise ValueError("invalid curve point")
    return P


def is_on_curve(P: Point) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - d * x * x * y * y) % p == 0


def public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed 必须是 32 字节")
    h = hashlib.sha512(seed).digest()
    a = 2**254 + sum(bit(h, i) * 2**i for i in range(3, 254))
    return encodepoint(scalarmult(B, a))


def sign(seed: bytes, m: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed 必须是 32 字节")
    h = hashlib.sha512(seed).digest()
    a = 2**254 + sum(bit(h, i) * 2**i for i in range(3, 254))
    r = hint(h[32:] + m)
    R = scalarmult(B, r)
    S = (r + hint(encodepoint(R) + public_key(seed) + m) * a) % L
    return encodepoint(R) + encodeint(S)


def verify(public: bytes, m: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    try:
        A = decodepoint(public)
        Rs = sig[:32]
        R = decodepoint(Rs)
        S = decodeint(sig[32:])
        if S >= L:
            return False
        h = hint(Rs + public + m)
        return scalarmult(B, S) == edwards_add(R, scalarmult(A, h))
    except Exception:
        return False
