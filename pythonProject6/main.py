from dataclasses import dataclass
from typing import List, Tuple, Iterable, Dict
from functools import reduce
import secrets
import hashlib
from phe import paillier

P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
)
P = int(P_HEX, 16)
Q = (P - 1) // 2
G = 2

def H_to_group(identifier: bytes):
    digest = hashlib.sha256(identifier).digest()
    h_int = int.from_bytes(digest, "big") % P
    return pow(h_int, 2, P)

class Part1:
    def __init__(self, V: List[bytes]):
        self.V = V
        self.k1: int = secrets.randbelow(Q - 1) + 1
        self.hashes: List[int] = [pow(H_to_group(v_i), self.k1, P) for v_i in self.V]

    #第一轮
    def Round1(self) -> List[int]:
        H = self.hashes.copy()
        secrets.SystemRandom().shuffle(H)
        return H

    #第三轮
    def Round3(self,pairs,z_set: set[int],pk: paillier.PaillierPublicKey,):
        J = []
        for h_w_k2, enc_t in pairs:
            h_w_k1k2 = pow(h_w_k2, self.k1, P)
            if h_w_k1k2 in z_set:
                J.append(enc_t)
        if not J:
            return pk.encrypt(0)
        total = reduce(lambda a, b: a + b, J)
        return total


class Part2:
    def __init__(self, W: List[Tuple[bytes, int]]):
        self.W = W
        self.k2: int = secrets.randbelow(Q - 1) + 1
        self.pk, self.sk = paillier.generate_paillier_keypair()

    #第二轮
    def Round2(self, H: List[int]):
        # 接受P1的信息并计算
        H2 = [pow(elem, self.k2, P) for elem in H]
        secrets.SystemRandom().shuffle(H2)

        #哈希自己的信息并同态加密
        pairs = []
        for w_j, t_j in self.W:
            h_w = H_to_group(w_j)
            h_w_k2 = pow(h_w, self.k2, P)
            Aenc = self.pk.encrypt(t_j)
            pairs.append((h_w_k2, Aenc))
        secrets.SystemRandom().shuffle(pairs)
        return H2, pairs

    def decrypt_sum(self, ciphertext):
        return self.sk.decrypt(ciphertext)



if __name__ == "__main__":
    V = [name.encode("utf-8") for name in ["张三", "李四", "王五"]]
    W = [(name.encode("utf-8"), score) for name, score in [("李四", 25), ("赵六", 20), ("张三", 50)]]
    p1 = Part1(V)
    p2 = Part2(W)

    H = p1.Round1()
    H2, pairs = p2.Round2(H)
    intersection_cipher = p1.Round3(pairs, set(H2), p2.pk)

    result = p2.decrypt_sum(intersection_cipher)
    print("交集元素总和为:", result)
