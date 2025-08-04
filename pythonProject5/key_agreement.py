from __future__ import annotations
import hashlib
import os
import SM2_origional as SM2
from gmssl import sm3, func


def _hash(msg: bytes) -> bytes:  # real SM3
    return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(msg)))

w = 127

def is_point_on_curve(P:SM2.Point, a = SM2.a, b= SM2.b, p = SM2.p) -> bool:
    x = P.x
    y = P.y
    left = pow(y, 2, p)
    right = (pow(x, 3, p) + a * x + b) % p
    return left == right

class Initiator:
    def __init__(self,ZA,ZB,dA,PA:SM2.Point,PB:SM2.Point):
        self.ZA = ZA
        self.ZB = ZB
        self.dA = dA
        self.PA = PA
        self.PB = PB

    #前三步
    def RA_generate(self):
        self.rA = int.from_bytes(os.urandom(32), "big") % SM2.n
        self.RA = SM2.EC_mul(self.rA,SM2.G)
        return self.RA

    def tA_generate(self):
        xA = self.RA.x
        xA_prime = (1 << w) + (xA % (1 << w))
        self.tA = (self.dA + xA_prime * self.rA) % SM2.n
        return self.tA

    def KA_generate(self,RB: SM2.Point , klen: int = 16):
        if not is_point_on_curve(RB):
            raise ValueError("call gen_U() first")
        xB_prime = (1 << w) + (RB.x % (1 << w))
        xB_RB = SM2.EC_mul(xB_prime, RB)
        sum_point = SM2.EC_add(self.PB, xB_RB)
        self.U = SM2.EC_mul(self.tA, sum_point)
        if self.U is None:
            raise ValueError("call gen_U() first")
        xU = self.U.x.to_bytes(32, "big")      #转字符
        yU = self.U.y.to_bytes(32, "big")
        self.K = SM2.Kdf(xU + yU + self.ZA + self.ZB, klen)
        return self.K

    def SA_generate(self, RB: SM2.Point, SB):
        xU = self.U.x.to_bytes(32, "big")
        yU = self.U.y.to_bytes(32, "big")
        msg = (
                xU + self.ZA + self.ZB +
                self.RA.x.to_bytes(32, "big") + self.RA.y.to_bytes(32, "big") +
                RB.x.to_bytes(32, "big") + RB.y.to_bytes(32, "big")
        )
        inner = hashlib.sha256(msg).digest()
        self.S1 = hashlib.sha256(b"\x02" + yU + inner).digest()
        if not self.S1 == SB:
            print(self.S1)
            print(SB)
            raise ValueError("S1 ≠ SB")
        SA = hashlib.sha256(b"\x03" + yU + inner).digest()
        return SA


class Responder:
    def __init__(self,ZA,ZB,dB,PA:SM2.Point,PB:SM2.Point):
        self.ZA = ZA
        self.ZB = ZB
        self.dB = dB
        self.PA = PA
        self.PB = PB

    def tB_generate(self):
        self.rB = int.from_bytes(os.urandom(32), "big") % SM2.n
        self.RB = SM2.EC_mul(self.rB,SM2.G)
        xB = self.RB.x
        xB_prime = (1 << w) + (xB % (1 << w))
        self.tB = (self.dB + xB_prime * self.rB) % SM2.n
        return self.tB

    def SB_generate(self,RA: SM2.Point,klen: int = 16):
        if not is_point_on_curve(RA):
            raise ValueError("call gen_U() first")
        xA_prime = (1 << w) + (RA.x % (1 << w))
        xA_RA = SM2.EC_mul(xA_prime, RA)
        sum_point = SM2.EC_add(self.PA, xA_RA)
        self.V = SM2.EC_mul(1 * self.tB, sum_point)
        if self.V is None:
            raise ValueError("call gen_U() first")
        xV = self.V.x.to_bytes(32, "big")      #转字符
        yV = self.V.y.to_bytes(32, "big")
        self.K = SM2.Kdf(xV + yV + self.ZA + self.ZB, klen)
        msg = (
                xV + self.ZA + self.ZB +
                RA.x.to_bytes(32, "big") + RA.y.to_bytes(32, "big") +
                self.RB.x.to_bytes(32, "big") + self.RB.y.to_bytes(32, "big")
        )
        inner = hashlib.sha256(msg).digest()
        self.SB = hashlib.sha256(b"\x02" + yV + inner).digest()
        return self.RB,self.SB

    def S2_generate(self, ZB: bytes, RA: SM2.Point):
        xV = self.V.x.to_bytes(32, "big")
        yV = self.V.y.to_bytes(32, "big")
        msg = (
                xV + self.ZA + self.ZB +
                RA.x.to_bytes(32, "big") + RA.y.to_bytes(32, "big") +
                self.RB.x.to_bytes(32, "big") + self.RB.y.to_bytes(32, "big")
        )
        inner = hashlib.sha256(msg).digest()
        self.S2 = hashlib.sha256(b"\x03" + yV + inner).digest()
        return self.S2



if __name__ == "__main__":

    print("Generating key pair")
    keypair1 = SM2.SM2KeyPair.generate()
    print("  Private key:", hex(keypair1.private))

    print("Generating key pair")
    keypair2 = SM2.SM2KeyPair.generate()
    print("  Private key:", hex(keypair2.private))


    ZA = SM2.ZA_generate(keypair1.public,uid = b"1234567812345678")
    ZB = SM2.ZA_generate(keypair2.public,uid = b"2345678123456781")

    dA = keypair1.private
    PA = keypair1.public
    dB = keypair2.private
    PB = keypair2.public

    A = Initiator(ZA, ZB, dA, PA, PB)
    B = Responder(ZA, ZB, dB, PA, PB)


    RA = A.RA_generate()
    tA = A.tA_generate()
    tB = B.tB_generate()
    RB, SB = B.SB_generate(RA)
    KA = A.KA_generate(RB)
    SA = A.SA_generate(RB, SB)
    S2 = B.S2_generate(ZB, RA)

    print("Key A:", KA.hex())
    print("Key B:", B.K.hex())
    print("S1 == SB:", A.S1 == SB)
    print("SA == S2:", SA == S2)

    assert KA == B.K, "双方密钥不一致"
    assert A.S1 == SB, "协商验证标签 S1 ≠ SB"
    assert SA == S2, "协商验证标签 SA ≠ S2"

    print("SM2 Key Exchange Passed.")



