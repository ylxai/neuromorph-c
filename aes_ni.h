/* aes_ni.h — AES-128 via AES-NI intrinsics (x86_64, -maes required) */
#ifndef AES_NI_H
#define AES_NI_H

#include <stdint.h>
#include <wmmintrin.h>

typedef struct { __m128i rk[11]; } AESNI_Key;

/* Expand a 16-byte key into 11 round keys */
static inline AESNI_Key aesni_expand(const uint8_t key[16]) {
    AESNI_Key k;
    __m128i t;
    k.rk[0] = _mm_loadu_si128((const __m128i*)key);
    
    #define AESNI_ROUND(i, rc) do { \
        t = _mm_aeskeygenassist_si128(k.rk[i], rc); \
        t = _mm_shuffle_epi32(t, _MM_SHUFFLE(3,3,3,3)); \
        k.rk[i+1] = k.rk[i]; \
        k.rk[i+1] = _mm_xor_si128(k.rk[i+1], _mm_slli_si128(k.rk[i+1], 4)); \
        k.rk[i+1] = _mm_xor_si128(k.rk[i+1], _mm_slli_si128(k.rk[i+1], 4)); \
        k.rk[i+1] = _mm_xor_si128(k.rk[i+1], _mm_slli_si128(k.rk[i+1], 4)); \
        k.rk[i+1] = _mm_xor_si128(k.rk[i+1], t); \
    } while(0)
    
    AESNI_ROUND(0, 0x01); AESNI_ROUND(1, 0x02); AESNI_ROUND(2, 0x04);
    AESNI_ROUND(3, 0x08); AESNI_ROUND(4, 0x10); AESNI_ROUND(5, 0x20);
    AESNI_ROUND(6, 0x40); AESNI_ROUND(7, 0x80); AESNI_ROUND(8, 0x1B);
    AESNI_ROUND(9, 0x36);
    
    #undef AESNI_ROUND
    return k;
}

/* One-block AES-128 encryption */
static inline __m128i aesni_encrypt_128(AESNI_Key *k, __m128i block) {
    block = _mm_xor_si128(block, k->rk[0]);
    block = _mm_aesenc_si128(block, k->rk[1]);
    block = _mm_aesenc_si128(block, k->rk[2]);
    block = _mm_aesenc_si128(block, k->rk[3]);
    block = _mm_aesenc_si128(block, k->rk[4]);
    block = _mm_aesenc_si128(block, k->rk[5]);
    block = _mm_aesenc_si128(block, k->rk[6]);
    block = _mm_aesenc_si128(block, k->rk[7]);
    block = _mm_aesenc_si128(block, k->rk[8]);
    block = _mm_aesenc_si128(block, k->rk[9]);
    block = _mm_aesenclast_si128(block, k->rk[10]);
    return block;
}

/* AES-128 encrypt one 16-byte block (bytes in/out) */
static inline void aesni_encrypt_bytes(AESNI_Key *k, const uint8_t in[16], uint8_t out[16]) {
    __m128i b = _mm_loadu_si128((const __m128i*)in);
    b = aesni_encrypt_128(k, b);
    _mm_storeu_si128((__m128i*)out, b);
}

#endif /* AES_NI_H */
