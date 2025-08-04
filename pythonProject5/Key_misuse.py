from __future__ import annotations
import hashlib
import os
import SM2_origional as SM2

p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123

G = SM2.G


def ECDSA_sign(message: bytes, d):
    z = int.from_bytes(hashlib.sha256(message).digest(), 'big') % n
    while True:
        k = int.from_bytes(os.urandom(32), "big") % n
        x, _ = SM2.EC_mul(k, G)
        r = x % n
        if r == 0:
            continue
        s = (SM2.inverse_mod(k, n) * (z + r * d)) % n
        if s == 0:
            continue
        return (r, s)


#泄露随机数k
def leaking_k(dA: int, M: bytes, ZA):
    e = int.from_bytes(SM2.Hash(ZA + M), "big")
    while True:
        k = int.from_bytes(os.urandom(32), "big") % n
        P1 = SM2.EC_mul(k, G)
        r = (e + P1.x) % n
        if r == 0 or r + k == n:
            continue
        s = (SM2.inverse_mod(1 + dA, n) * (k - r * dA)) % n
        if s != 0:
            break

    dA_guess = ((k - s) * SM2.inverse_mod(s + r, n)) % n
    if dA_guess == dA:
        print("泄露随机数k恢复成功！")

#用户用同一随机数签名两条信息
def reusing_k(dA: int, M1: bytes, M2: bytes, ZA):
    reuse_k = 0
    #第一次签名且记录下随机数的使用
    e = int.from_bytes(SM2.Hash(ZA + M1), "big")
    while True:
        k = int.from_bytes(os.urandom(32), "big") % n
        P1 = SM2.EC_mul(k, G)
        r1 = (e + P1.x) % n
        if r1 == 0 or r1 + k == n:
            continue
        s1 = (SM2.inverse_mod(1 + dA, n) * (k - r1 * dA)) % n
        if s1 != 0:
            break

    reuse_k = k

    e = int.from_bytes(SM2.Hash(ZA + M2), "big")
    while True:
        k = reuse_k
        P1 = SM2.EC_mul(k, G)
        r2 = (e + P1.x) % n
        if r2 == 0 or r2 + k == n:
            continue
        s2 = (SM2.inverse_mod(1 + dA, n) * (k - r2 * dA)) % n
        if s2 != 0:
            break

    num = (s2 - s1) % n
    den = (s1 - s2 + r1 - r2) % n
    dA_guess = (num * SM2.inverse_mod(den, n)) % n
    if dA_guess == dA:
        print("签名两次恢复成功!")

#不同的用户共用随机数k
def reusing_k_diff(dA: int, dB: int,M: bytes, ZA,ZB):
    reuse_k = 0
    e = int.from_bytes(SM2.Hash(ZA + M), "big")
    while True:
        k = int.from_bytes(os.urandom(32), "big") % n
        P1 = SM2.EC_mul(k, G)
        r1 = (e + P1.x) % n
        if r1 == 0 or r1 + k == n:
            continue
        s1 = (SM2.inverse_mod(1 + dA, n) * (k - r1* dA)) % n
        if s1 != 0:
            break
    reuse_k = k

    e = int.from_bytes(SM2.Hash(ZB + M), "big")
    while True:
        k = reuse_k
        P1 = SM2.EC_mul(k, G)
        r2 = (e + P1.x) % n
        if r2 == 0 or r2 + k == n:
            continue
        s2 = (SM2.inverse_mod(1 + dB, n) * (k - r2 * dB)) % n
        if s2 != 0:
            break

    dB_guess = ((k - s2) * SM2.inverse_mod(s2 + r2, n)) % n
    if dB_guess == dB:
        print("共用随机数恢复成功！")

def same_dk_ECDMA(dA: int, M: bytes, ZA):
    reuse_k = 0
    z = int.from_bytes(hashlib.sha256(M).digest(), 'big') % n
    while True:
        k = int.from_bytes(os.urandom(32), "big") % n
        x= SM2.EC_mul(k, G).x
        r1 = x % n
        if r1 == 0:
            continue
        s1 = (SM2.inverse_mod(k, n) * (z + r1 * dA)) % n
        if s1 != 0:
            break
    reuse_k = k

    e = int.from_bytes(SM2.Hash(ZA + M), "big")
    while True:
        k = reuse_k
        P1 = SM2.EC_mul(k, G)
        r2 = (e + P1.x) % n
        if r2 == 0 or r2 + k == n:
            continue
        s2 = (SM2.inverse_mod(1 + dA, n) * (k - r2 * dA)) % n
        if s2 != 0:
            break

    num = (s1 * s2 - z) % n
    den = (r1 - s1 * (s2 + r2)) % n
    d = (num * SM2.inverse_mod(den, n)) % n
    if d == dA:
        print("ECDMA共用dk恢复成功！")



if __name__ == "__main__":
    print("Generating key pair")
    keypair1 = SM2.SM2KeyPair.generate()
    print("  Private key1:", hex(keypair1.private))
    print("  Public key1:", hex(keypair1.public.x))
    keypair2 = SM2.SM2KeyPair.generate()
    print("  Private key1:", hex(keypair2.private))
    print("  Public key1:", hex(keypair2.public.x))

    ZA = SM2.ZA_generate(keypair1.public,uid = b"1234567812345678")
    ZB = SM2.ZA_generate(keypair2.public,uid = b"2345678123456781")

    message1 = b"I like cryptography!"
    message2 = b"I don't like cryptography!"

    dA = keypair1.private
    dB = keypair2.private
    leaking_k(dA,message1,ZA)
    reusing_k(dA,message1,message2,ZA)
    reusing_k_diff(dA,dB,message1,ZA,ZB)
    same_dk_ECDMA(dA,message1,ZA)

