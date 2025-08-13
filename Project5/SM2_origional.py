from __future__ import annotations
import os
from dataclasses import dataclass
from typing import Tuple, Optional
from gmssl import sm3, func

#椭圆曲线参数(参考国密SM2推荐曲线参数)
p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123

@dataclass
class Point:
    x: Optional[int]
    y: Optional[int]
    def is_at_infinity(self) -> bool:
        return self.x is None and self.y is None
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y

@dataclass
class SM2KeyPair:
    private: int
    public: Point
    @classmethod
    def generate(cls) -> "SM2KeyPair":
        d = int.from_bytes(os.urandom(32), "big") % n
        return cls(d, EC_mul(d, G))


#定义零点
_O = Point(None, None)

def inverse_mod(a, p):
    # 辗转相除求逆元，如果 gcd(a, p) ≠ 1，则没有逆元
    if a == 0:
        raise ZeroDivisionError('inverse does not exist')

    # 确保 a 在模 p 下为正
    a = a % p
    old_r, r = a, p
    old_s, s = 1, 0

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s

    if old_r != 1:
        raise ValueError(f"No modular inverse: {a} mod {p}")

    return old_s % p

#椭圆曲线加法
def EC_add(P: Point, Q: Point):
    if P.is_at_infinity():
        return Q
    if Q.is_at_infinity():
        return P
    if P.x == Q.x and (P.y + Q.y) % p == 0:
        return _O
    if P == Q:
        l = (3 * P.x * P.x + a) * inverse_mod(2 * P.y, p) % p
    else:
        l = (Q.y - P.y) * inverse_mod(Q.x - P.x, p) % p
    x_r = (l * l - P.x - Q.x) % p
    y_r = (l * (P.x - x_r) - P.y) % p
    return Point(x_r, y_r)

#椭圆曲线乘法
def EC_mul(k: int, P: Point):
    if k % n == 0 or P.is_at_infinity():
        return _O
    if k < 0:
        return EC_mul(-k, Point(P.x, (-P.y) % p))
    result = _O
    addend = P
    while k:
        if k & 1:
            result = EC_add(result, addend)
        addend = EC_add(addend, addend)
        k >>= 1
    return result

def Hash(msg: bytes) -> bytes:
    return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(msg)))

def Kdf(z: bytes, klen: int):
    ct = 1
    buf = b""
    while len(buf) < klen:
        buf += Hash(z + ct.to_bytes(4, "big"))
        ct += 1
    return buf[:klen]

G = Point(Gx, Gy)

def ZA_generate(PA: int, uid: bytes):
    ENTLA = (len(uid) * 8).to_bytes(2, "big")
    ZA = Hash(
        ENTLA
        + uid
        + a.to_bytes(32, "big")
        + b.to_bytes(32, "big")
        + Gx.to_bytes(32, "big")
        + Gy.to_bytes(32, "big")
        + PA.x.to_bytes(32, "big")
        + PA.y.to_bytes(32, "big")
    )
    return ZA


#加密：公钥与消息
def sm2_encrypt(PB: Point, M: bytes):
    k = int.from_bytes(os.urandom(32), "big") % n
    C1 = EC_mul(k, G)
    S = EC_mul(k, PB)
    if S.is_at_infinity():
        raise ZeroDivisionError("Zero!")
    x2y2 = S.x.to_bytes(32, "big") + S.y.to_bytes(32, "big")
    t = Kdf(x2y2, len(M))
    if int.from_bytes(t, "big") == 0:
        return sm2_encrypt(PB, M)  # 跳转回第一步
    C2 = bytes(a ^ b for a, b in zip(M, t))
    C3 = Hash(S.x.to_bytes(32, "big") + M + S.y.to_bytes(32, "big"))
    C1_byte = b"\x04" + C1.x.to_bytes(32, "big") + C1.y.to_bytes(32, "big")
    return C1_byte + C2 + C3

#解密：私钥与密文
def sm2_decrypt(dB: int, C: bytes):
    C1 = Point(int.from_bytes(C[1:33], "big"), int.from_bytes(C[33:65], "big"))
    C2 = C[65:-32]
    C3 = C[-32:]
    S = EC_mul(dB, C1)
    if S.is_at_infinity():
        raise ZeroDivisionError("Zero!")
    x2y2 = S.x.to_bytes(32, "big") + S.y.to_bytes(32, "big")
    t = Kdf(x2y2, len(C2))
    M = bytes(a ^ b for a, b in zip(C2, t))
    u = Hash(S.x.to_bytes(32, "big") + M + S.y.to_bytes(32, "big"))
    if u != C3:
        raise ValueError("Invalid cipher: hash mismatch")
    return M

#签名和验证签名过程
def sm2_sign(dA: int, M: bytes, ZA):
    e = int.from_bytes(Hash(ZA + M), "big")
    while True:
        k = int.from_bytes(os.urandom(32), "big") % n
        P1 = EC_mul(k, G)
        r = (e + P1.x) % n
        if r == 0 or r + k == n:
            continue
        s = (inverse_mod(1 + dA, n) * (k - r * dA)) % n
        if s == 0:
            continue
        return r, s


def sm2_verify(PA: Point, M: bytes, sig: Tuple[int, int], ZA):
    r, s = sig
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = int.from_bytes(Hash(ZA + M), "big")
    t = (r + s) % n
    if t == 0:
        return False
    P1 = EC_add(EC_mul(s, G), EC_mul(t, PA))
    R = (e + P1.x) % n
    return R == r


if __name__ == "__main__":
    print("Generating key pair")
    keypair = SM2KeyPair.generate()
    print("  Private key:", hex(keypair.private))
    print("  Public key:", hex(keypair.public.x))

    ZA = ZA_generate(keypair.public,uid = b"1234567812345678")

    message = b"I like cryptography!"
    print("Message is:", message.decode("utf-8"))
    sig = sm2_sign(keypair.private, message,ZA)
    print("Signature:", sig)
    assert sm2_verify(keypair.public, message, sig,ZA), "Signature failed!"
    print("Verification passed")

    cipher = sm2_encrypt(keypair.public, message)
    plain = sm2_decrypt(keypair.private, cipher)
    print("Plaintext:", plain.decode("utf-8"))
    assert plain == message, "Decrypt failed!"
    print("Decrypt successful!")

