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


using namespace std;
const uint8_t Sbox[256] = {
     0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
     0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
     0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
     0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
     0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
     0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
     0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
     0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
     0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
     0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
     0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
     0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
     0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
     0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
     0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
     0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
     0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
     0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
     0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
     0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
     0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
     0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
     0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
     0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
     0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
     0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
     0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
     0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
     0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
     0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
     0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
     0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };


//t_table表与GHASH优化查找表
uint32_t t_table[4][256];
uint8_t H_table_high[16][16];
uint8_t H_table_low[16][16];


// S盒查找替换
uint32_t S(uint32_t x) {
    uint8_t a[4];
    for (int i = 0; i < 4; i++)
        a[i] = Sbox[(x >> (24 - i * 8)) & 0xFF];
    return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

void hex_to_bytes(const char* hex, uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

// 线性变换L(一个用于加密，一个用于轮密钥)
uint32_t L(uint32_t b) {
    return b ^ (b << 2 | b >> (32 - 2)) ^ (b << 10 | b >> (32 - 10)) ^ (b << 18 | b >> (32 - 18)) ^ (b << 24 | b >> (32 - 24));
}
uint32_t L1(uint32_t b) {
    return b ^ (b << 13 | b >> (32 - 13)) ^ (b << 23 | b >> (32 - 23));
}

// LS的简化，由于t_table会优化整个过程，因此未优化的也设置了T函数
uint32_t T(uint32_t x) {
    return L(S(x));
}

uint32_t T1(uint32_t x) {
    return L1(S(x));
}

// T函数使用T_table优化
uint32_t T_table(uint32_t x) {
    uint8_t out[4];
    out[0] = (x >> 24) & 0xFF;
    out[1] = (x >> 16) & 0xFF;
    out[2] = (x >> 8) & 0xFF;
    out[3] = x & 0xFF;
    return t_table[0][out[0]] ^ t_table[1][out[1]] ^ t_table[2][out[2]] ^ t_table[3][out[3]];
}

// AES-NI对L变换进行效率优化
__m128i L_NI(uint32_t B) {
    __m128i B1 = _mm_cvtsi32_si128(B);
    __m128i rot2 = _mm_or_si128(_mm_slli_epi32(B1, 2), _mm_srli_epi32(B1, 30));
    __m128i rot10 = _mm_or_si128(_mm_slli_epi32(B1, 10), _mm_srli_epi32(B1, 22));
    __m128i rot18 = _mm_or_si128(_mm_slli_epi32(B1, 18), _mm_srli_epi32(B1, 14));
    __m128i rot24 = _mm_or_si128(_mm_slli_epi32(B1, 24), _mm_srli_epi32(B1, 8));

    __m128i L_B = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(rot2, rot10), rot18), rot24);
    L_B = _mm_xor_si128(B1, L_B);
    return L_B;
}

uint32_t T_NI(uint32_t x) {
    uint32_t value = _mm_extract_epi32(L_NI(S(x)), 0);
    return value;
}


void Merge(uint32_t out[], uint8_t X[], int l) {
    for (int i = 0; i < l / 4; i++) {
        out[i] = ((uint32_t)X[4 * i] << 24) |
            ((uint32_t)X[4 * i + 1] << 16) |
            ((uint32_t)X[4 * i + 2] << 8) |
            X[4 * i + 3];
    }
}

__m128i L_transform(__m128i B) {
    __m128i B2 = _mm_or_si128(_mm_slli_epi32(B, 2), _mm_srli_epi32(B, 30));
    __m128i B10 = _mm_or_si128(_mm_slli_epi32(B, 10), _mm_srli_epi32(B, 22));
    __m128i B18 = _mm_or_si128(_mm_slli_epi32(B, 18), _mm_srli_epi32(B, 14));
    __m128i B24 = _mm_or_si128(_mm_slli_epi32(B, 24), _mm_srli_epi32(B, 8));

    return _mm_xor_si128(B, _mm_xor_si128(B2,
        _mm_xor_si128(B10, _mm_xor_si128(B18, B24))));
}

//轮密钥生成
void RoundKey(uint8_t MK[16], uint32_t rk[32]) {
    uint32_t K[36];
    Merge(K, MK, 16);
    for (int i = 0; i < 32; i++) {
        K[i + 4] = K[i] ^ T1(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
        rk[i] = K[i + 4];
    }
}

//SM4基础加密实现
void EncryptBlock(const uint8_t input[16], uint8_t output[16], const uint32_t rk[32]) {
    uint32_t X[36];
    Merge(X, output, 16);
    // 迭代加密
    for (int i = 0; i < 32; i++) {
        X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);
    }
    //这里不能用拆分函数
    for (int i = 0; i < 4; i++) {
        uint32_t val = X[35 - i];
        output[4 * i] = (val >> 24) & 0xFF;
        output[4 * i + 1] = (val >> 16) & 0xFF;
        output[4 * i + 2] = (val >> 8) & 0xFF;
        output[4 * i + 3] = val & 0xFF;
    }
}

//t_table优化加密
void EncryptBlock_table(const uint8_t input[16], uint8_t output[16], const uint32_t rk[32]) {
    uint32_t X[36];
    Merge(X, output, 16);
    // 迭代加密
    for (int i = 0; i < 32; i++) {
        X[i + 4] = X[i] ^ T_table(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);
    }
    //这里不能用拆分函数
    for (int i = 0; i < 4; i++) {
        uint32_t val = X[35 - i];
        output[4 * i] = (val >> 24) & 0xFF;
        output[4 * i + 1] = (val >> 16) & 0xFF;
        output[4 * i + 2] = (val >> 8) & 0xFF;
        output[4 * i + 3] = val & 0xFF;
    }
}

// AES优化实现
void EncryptBlock_AES(const uint8_t input[16], uint8_t output[16], const uint32_t rk[32]) {
    uint32_t X[36];
    Merge(X, output, 16);
    // 迭代加密
    for (int i = 0; i < 32; i++) {
        X[i + 4] = X[i] ^ T_NI(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);
    }
    //这里不能用拆分函数
    for (int i = 0; i < 4; i++) {
        uint32_t val = X[35 - i];
        output[4 * i] = (val >> 24) & 0xFF;
        output[4 * i + 1] = (val >> 16) & 0xFF;
        output[4 * i + 2] = (val >> 8) & 0xFF;
        output[4 * i + 3] = val & 0xFF;
    }
}

//GCM的CTR优化模式
void sm4_ctr(uint8_t key[16],  uint8_t iv[16],  uint8_t* plain, uint8_t* ciphe, size_t length) {
    uint32_t rk[32];
    RoundKey(key, rk);  //轮密钥 
    uint8_t counter[16];
    memcpy(counter, iv, 16); 
    uint8_t stream_block[16];
    size_t num_blocks = length / 16;
    size_t remaining = length % 16;
    for (size_t i = 0; i < num_blocks; i++) {
        EncryptBlock_table(counter, stream_block, rk);   //使用t_table进行对CTR模式进行优化
        for (int j = 0; j < 16; j++)
            ciphe[i * 16 + j] = plain[i * 16 + j] ^ stream_block[j];
        for (int x = 15; x >= 0; --x) {
            if (++counter[x] != 0) break;
        }
    }
}

// 0通过块加密得到的值作为GMAC函数的密钥H。
void H_generate(uint8_t key[16], uint8_t H[16]) {
    uint32_t rk[32];
    RoundKey(key, rk); 
    uint8_t zero_block[16] = { 0 }; 
    EncryptBlock_table(zero_block, H, rk); 
}

// 块异或
void block_xor(uint8_t X[16], uint8_t Y[16], uint8_t Z[16]) {
    for (int i = 0; i < 16; i++) {
        Z[i] = X[i] ^ Y[i];
    }
}

void GF128_rs(uint8_t V[16]) {
    bool x = V[15] & 1;
    for (int i = 15; i > 0; i--) {
        V[i] = (V[i] >> 1) | ((V[i - 1] & 1) << 7);
    }
    V[0] >>= 1;
    if (x) {
        V[0] ^= 0xe1;
    }
}

void GF128_table_generate(const uint8_t H[16]) {
    uint8_t V[16];
    memset(H_table_high, 0, sizeof(H_table_high));
    memset(H_table_low, 0, sizeof(H_table_low));
    for (int i = 0; i < 16; i++) {
        memcpy(V, H, 16);
        for (int j = 0; j < i; j++) {
            GF128_rs(V);
        }
        memcpy(H_table_high[i], V, 16);
    }
    for (int i = 0; i < 16; i++) {
        memcpy(V, H_table_high[i], 16);
        for (int j = 0; j < 4; j++) {
            GF128_rs(V);
        }
        memcpy(H_table_low[i], V, 16);
    }
}

// 乘法表优化构造
void GF128_Mul(uint8_t X[16],uint8_t out[16]) {
    uint8_t Z[16] = { 0 };
    for (int i = 0; i < 16; i++) {
        uint8_t byte = X[i];
        uint8_t* high = H_table_high[byte >> 4];
        uint8_t* low = H_table_low[byte & 0x0F];
        block_xor(Z, high, Z);
        block_xor(Z, low, Z);
    }
    memcpy(out, Z, 16);
}


void sm4_MAC(uint8_t key[16],uint8_t AAD[],int AAD_len, uint8_t c[16],int c_len, uint8_t tag[16]) {
    uint8_t H[16];
    H_generate(key, H);
    uint8_t Y[16] = {0};
    uint8_t block[16];
    GF128_table_generate(H);


    size_t aad_blocks = (AAD_len + 15) / 16;
    for (size_t i = 0; i < aad_blocks; i++) {
        memset(block, 0, 16);
        size_t copy_len = (i < aad_blocks - 1 || AAD_len % 16 == 0) ? 16 : AAD_len % 16;
        memcpy(block, AAD + i * 16, copy_len);
        block_xor(Y, block, Y);
        GF128_Mul(Y, Y);
    }

    size_t c_blocks = (c_len + 15) / 16;
    for (size_t i = 0; i < c_blocks; i++) {
        memset(block, 0, 16);
        size_t copy_len = (i < c_blocks - 1 || c_len % 16 == 0) ? 16 : c_len % 16;
        memcpy(block, c + i * 16, copy_len);
        block_xor(Y, block, Y);
        GF128_Mul(Y, Y);
    }

    uint64_t AAD_bits = AAD_len * 8;
    uint64_t c_bits = c_len * 8;
    memset(block, 0, 16);
    for (int i = 0; i < 8; i++) {
        block[7 - i] = (AAD_bits >> (i * 8)) & 0xFF;
        block[15 - i] = (c_bits >> (i * 8)) & 0xFF;
    }
    block_xor(Y, block, Y);
    GF128_Mul(Y, Y);

    memcpy(tag, Y, 16);
}


void t_table_check() {
    // 生成t_table进行优化
    for (int i = 0; i < 256; i++) {
        uint8_t b = Sbox[i];
        uint32_t B = b << 24;
        t_table[0][i] = L(B);
        B = b << 16;
        t_table[1][i] = L(B);
        B = b << 8;
        t_table[2][i] = L(B);
        B = b;
        t_table[3][i] = L(B);
    }
    using namespace std::chrono;
    double total_time = 0;
    uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    uint8_t plain[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    uint8_t out[16];
    uint32_t rk[32];
    RoundKey(key, rk);

    for (int i = 0; i < 16; i++) {
        plain[0] = i;
        auto start = high_resolution_clock::now();
        EncryptBlock_table(plain, out, rk);
        auto end = high_resolution_clock::now();
        duration<double, std::micro> elapsed = end - start;

        total_time += elapsed.count();
        cout << "T_table check:" << endl;
        cout << "Run " << i + 1 << ": " << elapsed.count() << " us" << endl;
    }
    double avg_time = total_time / 16;
    cout << "Average time: " << avg_time << " us" << endl;
}

// 优化了L变换函数
void AES_NI_check() {
    using namespace std::chrono;
    double total_time = 0;
    uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    uint8_t plain[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                         0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    uint8_t out[16];
    uint32_t rk[32];
    RoundKey(key, rk);

    for (int i = 0; i < 16; i++) {
        plain[0] = i;
        auto start = high_resolution_clock::now();
        EncryptBlock_AES(plain, out, rk);
        auto end = high_resolution_clock::now();
        duration<double, std::micro> elapsed = end - start;

        total_time += elapsed.count();
        cout << "AES_NI check:" << endl;
        cout << "Run " << i + 1 << ": " << elapsed.count() << " us" << endl;
    }
    double avg_time = total_time / 16;
    cout << "Average encryption time: " << avg_time << " us" << endl;

}


void GCM_check() {
    const char* key_hex = "F82B569F5D3DCB61D0BE8778BF05D1B0";
    const char* iv_hex = "791004096432F985F7BE6B5CDAC79EB8";
    const char* plaintext_hex = "F76C0ADA8374F1D0C4B7EC5CC5047E03";
    const char* aad_hex = "1122334455667788";
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t plaintext[16];
    uint8_t aad[8];

    hex_to_bytes(key_hex, key, 16);
    hex_to_bytes(iv_hex, iv, 16);
    hex_to_bytes(plaintext_hex, plaintext, 16);
    hex_to_bytes(aad_hex, aad, 8);

    uint8_t tag[16];
    uint8_t ciphertext[32];
    sm4_ctr(key, iv, plaintext, ciphertext, 32);
    sm4_MAC(key, aad, sizeof(aad), ciphertext, sizeof(ciphertext), tag);

    cout << "SM4_GCM check:" << endl;
    cout << "Ciphertext:" << endl;
    for (int i = 0; i < 32; i++) {
        printf("%02X ", ciphertext[i]);
    }
    cout << endl;
    printf("Tag:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", tag[i]);
    }
}


int main() {
    t_table_check();
    AES_NI_check();
    GCM_check();
    return 0;
}

