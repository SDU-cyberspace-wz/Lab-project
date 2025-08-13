from dataclasses import dataclass
from typing import List, Tuple, Iterable, Dict, Set
from functools import reduce
import secrets
import hashlib
from phe import paillier

# 大素数参数（符合密码学安全要求的模数）
P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
)
P = int(P_HEX, 16)  # 模数（大素数）
Q = (P - 1) // 2    # 子群阶数
G = 2               # 生成元


def hash_to_group(identifier: bytes) -> int:
    """
    将标识符哈希映射到指定的数学群中
    :param identifier: 输入的字节型标识符
    :return: 映射到群中的元素（模P的结果）
    """
    # 使用SHA-256哈希获取摘要
    digest = hashlib.sha256(identifier).digest()
    # 将哈希结果转换为整数并对P取模
    hash_int = int.from_bytes(digest, "big") % P
    # 返回二次幂结果作为群元素
    return pow(hash_int, 2, P)


class Participant1:
    """参与方1：负责初始化数据并执行第一轮和第三轮计算"""
    def __init__(self, elements_v: List[bytes]):
        self.elements_v = elements_v  # 参与方1的元素列表（字节型）
        # 生成参与方1的私有密钥k1（1到Q-1之间的随机整数）
        self.k1: int = secrets.randbelow(Q - 1) + 1
        # 对每个元素计算哈希并使用k1加密（指数运算）
        self.hashed_elements = [pow(hash_to_group(v_i), self.k1, P) for v_i in self.elements_v]

    def round1(self) -> List[int]:
        """
        第一轮交互：将加密后的元素打乱后发送给参与方2
        :return: 打乱后的加密元素列表
        """
        shuffled_hashes = self.hashed_elements.copy()
        # 随机打乱列表顺序
        secrets.SystemRandom().shuffle(shuffled_hashes)
        return shuffled_hashes

    def round3(self, 
               encrypted_pairs: List[Tuple[int, paillier.EncryptedNumber]],
               z_set: Set[int],
               public_key: paillier.PaillierPublicKey
               ) -> paillier.EncryptedNumber:
        """
        第三轮交互：筛选交集元素并计算加密分数总和
        :param encrypted_pairs: 参与方2发送的（加密元素, 加密分数）对列表
        :param z_set: 参与方2返回的第二轮加密元素集合
        :param public_key: 参与方2的Paillier公钥
        :return: 交集元素对应分数的加密总和
        """
        # 筛选出属于交集的加密分数
        matched_enc_scores = []
        for h_w_k2, enc_score in encrypted_pairs:
            # 计算参与方1和2密钥共同加密的元素
            h_w_k1k2 = pow(h_w_k2, self.k1, P)
            # 判断是否在交集内
            if h_w_k1k2 in z_set:
                matched_enc_scores.append(enc_score)
        
        # 若没有交集则返回加密的0，否则返回加密分数总和
        if not matched_enc_scores:
            return public_key.encrypt(0)
        return reduce(lambda a, b: a + b, matched_enc_scores)


class Participant2:
    """参与方2：负责处理交互数据并执行第二轮计算，持有Paillier密钥对"""
    def __init__(self, elements_w: List[Tuple[bytes, int]]):
        self.elements_w = elements_w  # 参与方2的元素列表（字节型, 分数）
        # 生成参与方2的私有密钥k2（1到Q-1之间的随机整数）
        self.k2: int = secrets.randbelow(Q - 1) + 1
        # 生成Paillier同态加密密钥对
        self.public_key, self.private_key = paillier.generate_paillier_keypair()

    def round2(self, received_hashes: List[int]) -> Tuple[List[int], List[Tuple[int, paillier.EncryptedNumber]]]:
        """
        第二轮交互：处理参与方1的元素并返回加密结果
        :param received_hashes: 参与方1发送的第一轮加密元素列表
        :return: 二次加密后的元素列表和（元素加密值, 分数加密值）对列表
        """
        # 对参与方1的元素进行二次加密（使用k2）
        reencrypted_hashes = [pow(elem, self.k2, P) for elem in received_hashes]
        # 随机打乱二次加密后的元素列表
        secrets.SystemRandom().shuffle(reencrypted_hashes)

        # 对自身元素计算哈希并加密，同时加密对应分数
        encrypted_pairs = []
        for w_j, score_j in self.elements_w:
            # 计算元素的哈希值
            h_w = hash_to_group(w_j)
            # 使用k2加密哈希值
            h_w_k2 = pow(h_w, self.k2, P)
            # 同态加密分数
            encrypted_score = self.public_key.encrypt(score_j)
            encrypted_pairs.append((h_w_k2, encrypted_score))
        
        # 随机打乱（元素加密值, 分数加密值）对列表
        secrets.SystemRandom().shuffle(encrypted_pairs)
        return reencrypted_hashes, encrypted_pairs

    def decrypt_result(self, ciphertext: paillier.EncryptedNumber) -> int:
        """
        解密最终的加密总和
        :param ciphertext: 参与方1返回的加密总和
        :return: 解密后的分数总和
        """
        return self.private_key.decrypt(ciphertext)


if __name__ == "__main__":
    # 参与方1的元素列表（示例：姓名）
    participant1_elements = [name.encode("utf-8") for name in ["张三", "李四", "王五"]]
    # 参与方2的元素列表（示例：姓名及其对应的分数）
    participant2_elements = [
        (name.encode("utf-8"), score) 
        for name, score in [("李四", 25), ("赵六", 20), ("张三", 50)]
    ]

    # 初始化参与方
    p1 = Participant1(participant1_elements)
    p2 = Participant2(participant2_elements)

    # 执行三轮交互协议
    round1_result = p1.round1()  # 第一轮：参与方1发送打乱的加密元素
    round2_hashes, round2_pairs = p2.round2(round1_result)  # 第二轮：参与方2处理并返回加密结果
    intersection_cipher = p1.round3(round2_pairs, set(round2_hashes), p2.public_key)  # 第三轮：参与方1计算交集总和

    # 解密并输出结果
    final_result = p2.decrypt_result(intersection_cipher)
    print("交集元素的分数总和为:", final_result)