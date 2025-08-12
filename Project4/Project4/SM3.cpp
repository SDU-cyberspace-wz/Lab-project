#define _CRT_SECURE_NO_WARNINGS
#include <cstdint>
#include <cstring>
#include <iostream>
#include <immintrin.h>
#include <stdint.h>
#include <chrono>
#include <vector>
#include <numeric>
#include <iomanip>
#include <cstdio>
#include <string>

using namespace std;

//SM3函数
uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

const uint32_t T[64] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

__m256i T_j(int j) {
    uint32_t t = (j < 16) ? 0x79CC4519 : 0x7A879D8A;
    return _mm256_set1_epi32(t);
}

uint32_t left_shift(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

__m256i ROTL_SIMD(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
}

uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int i) {
    if (i < 16) {
        return x ^ y ^ z;
    }
    else {
        return ((x & y) | (x & z) | (y & z));
    }
}

uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int i) {
    if (i < 16) {
        return x ^ y ^ z;
    }
    else {
        return ((x & y) | (~x & z));
    }
}

__m256i FF_SIMD(__m256i x, __m256i y, __m256i z, int j) {
    if (j < 16) return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
    return _mm256_or_si256(_mm256_or_si256(_mm256_and_si256(x, y),
        _mm256_and_si256(x, z)),
        _mm256_and_si256(y, z));
}

__m256i GG_SIMD(__m256i x, __m256i y, __m256i z, int j) {
    if (j < 16) return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
    return _mm256_or_si256(_mm256_and_si256(x, y),
        _mm256_and_si256(_mm256_andnot_si256(x, _mm256_set1_epi32(0xFFFFFFFF)), z));
}


// 置换函数
uint32_t P0(uint32_t x) {
    return x ^ left_shift(x, 9) ^ left_shift(x, 17);
}

uint32_t P1(uint32_t x) {
    return x ^ left_shift(x, 15) ^ left_shift(x, 23);
}

__m256i P0_SIMD(__m256i X) {
    __m256i x1 = _mm256_or_si256(_mm256_slli_epi32(X, 9), _mm256_srli_epi32(X, 23));
    __m256i x2 = _mm256_or_si256(_mm256_slli_epi32(X, 17), _mm256_srli_epi32(X, 15));
    return _mm256_xor_si256(X, _mm256_xor_si256(x1, x2));
}

__m256i P1_SIMD(__m256i X) {
    __m256i x1 = _mm256_or_si256(_mm256_slli_epi32(X, 15), _mm256_srli_epi32(X, 17));
    __m256i x2 = _mm256_or_si256(_mm256_slli_epi32(X, 23), _mm256_srli_epi32(X, 9));
    return _mm256_xor_si256(X, _mm256_xor_si256(x1, x2));
}

uint32_t from_8_to_32(const uint8_t* b) {
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}

void from_32_to_8(uint32_t mess, uint8_t* b) {
    b[0] = (mess >> 24) & 0xFF;
    b[1] = (mess >> 16) & 0xFF;
    b[2] = (mess >> 8) & 0xFF;
    b[3] = mess & 0xFF;
}

void CF(uint32_t V[8], uint8_t* block) {
    uint32_t W[68], W1[64];
    for (int i = 0; i < 16; i++)
        W[i] = from_8_to_32(block + 4 * i);
    for (int i = 16; i < 68; i++)
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ left_shift(W[i - 3], 15)) ^ left_shift(W[i - 13], 7) ^ W[i - 6];
    for (int i = 0; i < 64; i++)
        W1[i] = W[i] ^ W[i + 4];

    uint32_t A = V[0], B = V[1], C = V[2], D = V[3],  E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = left_shift(left_shift(A, 12) + E + left_shift(T[j], j), 7);
        uint32_t SS2 = SS1 ^ left_shift(A, 12);
        uint32_t TT1 = FF(A, B, C ,j) + D + SS2 + W1[j];
        uint32_t TT2 = GG(E, F, G ,j) + H + SS1 + W[j];
        D = C;
        C = left_shift(B, 9);
        B = A;
        A = TT1;
        H = G; 
        G = left_shift(F, 19);
        F = E;
        E = P0(TT2);
    }
    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

void CF_SIMD(__m256i V[8], uint8_t* block) {
    __m256i W[68], W1[64];
    for (int i = 0; i < 16; i++) {
        uint32_t temp[8];
        for (int j = 0; j < 8; j++) {
            uint8_t* p = block + j * 64 + 4 * i;
            temp[j] = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
        }
        W[i] = _mm256_loadu_si256((__m256i*)temp);
    }

    for (int i = 16; i < 68; i++) {
        __m256i Wj_16 = W[i - 16];
        __m256i Wj_9 = W[i - 9];
        __m256i Wj_3 = _mm256_or_si256(_mm256_slli_epi32(W[i - 3], 15), _mm256_srli_epi32(W[i - 3], 17));
        __m256i Wj_13 = _mm256_or_si256(_mm256_slli_epi32(W[i - 13], 7), _mm256_srli_epi32(W[i - 13], 25));
        __m256i Wj_6 = W[i - 6];
        W[i] = _mm256_xor_si256(P1_SIMD(_mm256_xor_si256(_mm256_xor_si256(Wj_16, Wj_9), Wj_3)), _mm256_xor_si256(Wj_13, Wj_6));
    }
    for (int i = 0; i < 64; i++) {
        W1[i] = _mm256_xor_si256(W[i], W[i + 4]);
    }
    __m256i A = V[0], B = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
    for (int j = 0; j < 64; j++) {
        __m256i SS1 = ROTL_SIMD(_mm256_add_epi32(ROTL_SIMD(A, 12), _mm256_add_epi32(E, ROTL_SIMD(T_j(j), j))), 7);
        __m256i SS2 = _mm256_xor_si256(SS1, ROTL_SIMD(A, 12));
        __m256i TT1 = _mm256_add_epi32(FF_SIMD(A, B, C, j), _mm256_add_epi32(D, _mm256_add_epi32(SS2, W1[j])));
        __m256i TT2 = _mm256_add_epi32(GG_SIMD(E, F, G, j), _mm256_add_epi32(H, _mm256_add_epi32(SS1, W[j])));
        D = C;
        C = ROTL_SIMD(B, 9);
        B = A;
        A = TT1;

        H = G;
        G = ROTL_SIMD(F, 19);
        F = E;
        E = P0_SIMD(TT2);
    }
    V[0] = _mm256_xor_si256(V[0], A);
    V[1] = _mm256_xor_si256(V[1], B);
    V[2] = _mm256_xor_si256(V[2], C);
    V[3] = _mm256_xor_si256(V[3], D);
    V[4] = _mm256_xor_si256(V[4], E);
    V[5] = _mm256_xor_si256(V[5], F);
    V[6] = _mm256_xor_si256(V[6], G);
    V[7] = _mm256_xor_si256(V[7], H);

}

vector<uint8_t> Message_expand(vector<uint8_t>& mess) {
    uint64_t mess_len = mess.size() * 8;
    vector<uint8_t> x = mess;

    x.push_back(0x80);
    while ((mess_len + 64) % 512 != 0) {
        x.push_back(0x00);
        mess_len = x.size() * 8;
    }

    for (int i = 7; i >= 0; i--) {
        x.push_back((mess_len >> (i * 8)) & 0xFF);
    }
    return x;
}


//加密函数
void SM3_encrypt(vector<uint8_t>& message, vector<uint8_t>& hash_output) {
    vector<uint8_t> m = Message_expand(message);
    size_t blocks = m.size() / 64;
    uint32_t V[8];
    memcpy(V, IV, sizeof(V));

    for (size_t i = 0; i < blocks; i++) {
        CF(V, &m[i * 64]);

    }
    hash_output.resize(32);
    for (int i = 0; i < 8; i++) {
        from_32_to_8(V[i], &hash_output[i * 4]);

    }
}

void SM3_encrypt_SIMD(const std::vector<std::vector<uint8_t>>& messages, std::vector<std::vector<uint8_t>>& hash_outputs) {
    const size_t batch_size = 8;
    const size_t block_size = 64;
    if (messages.size() != batch_size) {
        throw std::runtime_error("SIMD version only supports 8 messages at once");
    }
    std::vector<uint8_t> blocks(batch_size * block_size);
    for (int i = 0; i < batch_size; ++i) {
        if (messages[i].size() != block_size) {
            throw std::runtime_error("Each message must be exactly 64 bytes (1 block)");
        }
        std::memcpy(&blocks[i * block_size], messages[i].data(), block_size);
    }
    __m256i V[8];
    for (int i = 0; i < 8; ++i) {
        uint32_t tmp[8];
        for (int j = 0; j < 8; ++j) tmp[j] = IV[i];
        V[i] = _mm256_loadu_si256((__m256i*)tmp);
    }
    CF_SIMD(V, blocks.data());
    hash_outputs.resize(batch_size, std::vector<uint8_t>(32));
    for (int i = 0; i < 8; ++i) {
        uint32_t buffer[8];
        _mm256_storeu_si256((__m256i*)buffer, V[i]);
        for (int j = 0; j < 8; ++j) {
            from_32_to_8(buffer[j], &hash_outputs[j][i * 4]);
        }
    }
}

void SM3_length_extension_attack(const uint32_t IV[8], const vector<uint8_t>& data, uint64_t total_len_bits_before_data, vector<uint8_t>& hash_output) {
    uint32_t V[8];
    memcpy(V, IV, sizeof(uint32_t) * 8);

    // 拼接数据 + padding
    vector<uint8_t> m = data;
    uint64_t total_len = total_len_bits_before_data + data.size() * 8;
    //total_len_bits_before_data +
    m.push_back(0x80);
    while ((total_len + 64) % 512 != 0) {
        m.push_back(0x00);
        total_len += 8;
    }
    for (int i = 7; i >= 0; i--) {
        m.push_back((total_len >> (i * 8)) & 0xFF);
    }

    // 分块处理
    size_t blocks = m.size() / 64;
    for (size_t i = 0; i < blocks; i++) {
        CF(V, &m[i * 64]);
    }

    hash_output.resize(32);
    for (int i = 0; i < 8; i++) {
        from_32_to_8(V[i], &hash_output[i * 4]);
    }
}

// MerkleTree
class MerkleTree {
public:
    MerkleTree(const vector<vector<uint8_t>>& leaves);
    vector<uint8_t> get_root() const;
    vector<vector<uint8_t>> get_inclusion_proof(int i);
private:
    vector<vector<vector<uint8_t>>> tree_levels;
};

vector<uint8_t> rfc_node_hash(const vector<uint8_t>& left, const vector<uint8_t>& right) {
    vector<uint8_t> input = { 0x01 };
    input.insert(input.end(), left.begin(), left.end());
    input.insert(input.end(), right.begin(), right.end());
    vector<uint8_t> out;
    SM3_encrypt(input, out);
    return out;
}

vector<uint8_t> rfc_leaf_hash(const vector<uint8_t>& data) {
    vector<uint8_t> input = { 0x00 };
    input.insert(input.end(), data.begin(), data.end());
    vector<uint8_t> out;
    SM3_encrypt(input, out);
    return out;
}

MerkleTree::MerkleTree(const vector<vector<uint8_t>>& raw_leaves) {
    vector<vector<uint8_t>> current_level;
    for (const auto& data : raw_leaves) {
        current_level.push_back(rfc_leaf_hash(data));
    }
    tree_levels.push_back(current_level);

    while (current_level.size() > 1) {
        vector<vector<uint8_t>> next_level;
        for (size_t i = 0; i < current_level.size(); i += 2) {
            if (i + 1 == current_level.size()) {
                next_level.push_back(current_level[i]);
            }
            else {
                next_level.push_back(rfc_node_hash(current_level[i], current_level[i + 1]));
            }
        }
        tree_levels.push_back(next_level);
        current_level = next_level;
    }
}

vector<uint8_t> MerkleTree::get_root() const {
    return tree_levels.back()[0];
}

vector<vector<uint8_t>> MerkleTree::get_inclusion_proof(int index) {
    vector<vector<uint8_t>> proof;
    int idx = index;
    for (size_t level = 0; level < tree_levels.size() - 1; ++level) {
        const auto& layer = tree_levels[level];
        int sibling = (idx % 2 == 0) ? idx + 1 : idx - 1;
        if (sibling < layer.size()) {
            proof.push_back(layer[sibling]);
        }
        idx /= 2;
    }
    return proof;
}



bool verify_inclusion_proof(
    const vector<uint8_t>& leaf_data,
    const vector<vector<uint8_t>>& proof,
    const vector<uint8_t>& root_hash,
    int leaf_index
) {

    vector<uint8_t> computed_hash = { 0x00 };
    computed_hash.insert(computed_hash.end(), leaf_data.begin(), leaf_data.end());
    SM3_encrypt(computed_hash, computed_hash);
    int idx = leaf_index;
    for (const auto& sibling_hash : proof) {
        if (idx % 2 == 0) {
            computed_hash = rfc_node_hash(computed_hash, sibling_hash); // left || right
        }
        else {
            computed_hash = rfc_node_hash(sibling_hash, computed_hash); // left || right
        }
        idx /= 2;
    }
    return computed_hash == root_hash;
}



//各种情况的测试用例
void SM3_origional_test() {
    string input = "I love SM3!";
    vector<uint8_t> message(input.begin(), input.end());
    vector<uint8_t> hash_result;
    SM3_encrypt(message, hash_result);
    cout << "SM3 Hash: ";
    for (uint8_t byte : hash_result) {
        printf("%02x", byte);
    }
    cout << endl;
}

void SM3_SIMD_test() {
    std::vector<std::vector<uint8_t>> messages(8, std::vector<uint8_t>(64, 0x00));
    messages[0] = std::vector<uint8_t>(64, 0x61); 

    std::vector<std::vector<uint8_t>> digests;
    SM3_encrypt_SIMD(messages, digests);

    for (int i = 0; i < 8; ++i) {
        printf("Digest %d: ", i);
        for (uint8_t b : digests[i]) {
            printf("%02x", b);
        }
        printf("\n");
    }
}

void length_extension_attack_test() {
    string input = "I love SM3!";
    vector<uint8_t> hash;
    vector<uint8_t> message(input.begin(), input.end());
    SM3_encrypt(message, hash);

    uint32_t medium_hash[8];
    memcpy(medium_hash, hash.data(), 32);

    string data = "Mecious";
    vector<uint8_t> suffix(data.begin(), data.end());
    vector<uint8_t> new_hash;

    // 使用原始消息长度（bit）
    uint64_t len = message.size() * 8;
    SM3_length_extension_attack(medium_hash, suffix, len, new_hash);
    // 输出结果比较
    cout << "Attack Hash:" << endl;
    for (uint8_t byte : new_hash) printf("%02x", byte);
    cout << endl;

}

void test_merkle_tree_with_100k_leaves() {
    const int N = 100000;
    vector<vector<uint8_t>> leaves;
    for (int i = 0; i < N; ++i) {
        string s = to_string(i);
        leaves.emplace_back(s.begin(), s.end());
    }
    cout << "构建 Merkle 树..." << endl;
    MerkleTree tree(leaves);
    auto root = tree.get_root();
    cout << "Merkle Root: ";
    for (uint8_t byte : root) printf("%02x", byte);
    cout << endl;
    int index = rand() % N;
    auto leaf_data = leaves[index];
    auto proof = tree.get_inclusion_proof(index);
    bool ok = verify_inclusion_proof(leaf_data, proof, root, index);
    if (ok) {
        cout << " Inclusion proof ！Index " << index << endl;
    }
    else {
        cout << " Inclusion proof failed！Index " << index << endl;
    }
}


//运行main()函数
int main() {
    SM3_origional_test();
    SM3_SIMD_test();
    length_extension_attack_test();
    test_merkle_tree_with_100k_leaves();
    return 0;
}