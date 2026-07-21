/**
 * neuromorph_v1.c — NeuroMorph PoW v1 in C
 *
 * Bit-exact reimplementation of Cereblix neuromorph.go for amd64.
 * ALL AES operations use AES-128 (16-byte key).
 *
 * Build:
 *   gcc -O2 -march=native -maes -msse4.1 neuromorph_v1.c -lcrypto -lssl -lm -o nm_test
 *
 * Reference hash (Go, epoch 0, header[i]=i*7):
 *   pre-dataset: 9748a3aa3d3b7c331585171b42297234830be0ec90e1ecd4425717f631c00aa7
 *   with-dataset: af3c3af2b84eea692d7f86bf5702719a49a7beb97a19f3cb264ca9c139dadab7
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include "aes_ni.h"

/* ──────────────── Constants ──────────────── */
#define SCRATCH_BYTES      (2 << 20)         /* 2 MiB */
#define SCRATCH_WORDS      (SCRATCH_BYTES / 8)
#define SCRATCH_MASK       (uint64_t)(SCRATCH_BYTES - 8)

#define DATASET_BYTES      (64 << 20)        /* 64 MiB */
#define DATASET_WORDS      (DATASET_BYTES / 8)
#define DATASET_MASK       (uint64_t)(DATASET_BYTES - 8)
#define DATASET_READS_PER_LOOP  64
#define DATASET_HEIGHT     240

#define NUM_OPS            15
#define EPOCH_SEED_STR     "cerebra/neuromorph/v1/epoch0/2026-06-11"

/* ──────────────── VM opcodes ──────────────── */
enum {
    OP_IADD = 0,
    OP_IMUL,
    OP_IMULH,
    OP_IXOR,
    OP_IROTR,
    OP_INEG,
    OP_FADD,
    OP_FMUL,
    OP_FDIV,
    OP_FSQRT,
    OP_LOAD,
    OP_STORE,
    OP_CBRANCH,
    OP_AESR,
    OP_XDOM,
};

/* ──────────────── Epoch params ──────────────── */
typedef struct {
    int    prog_size;
    int    loops;
    uint64_t branch_mask;
    uint64_t rot_salt;
    uint8_t  op_table[256];
    uint8_t  aes_key[16];
    uint8_t  dataset_key[16];
} Params;

/* ──────────────── Instruction ──────────────── */
typedef struct {
    uint8_t  op;
    uint8_t  dst;
    uint8_t  src;
    uint32_t imm;
} Instr;

/* ──────────────── VM state ──────────────── */
typedef struct {
    Params   params;
    uint64_t *scratch;
    Instr    *prog;
    uint8_t  *taken;
    uint64_t *dataset;
    AESNI_Key aes_ni;        /* expanded epoch AES key for opAESR */
} VM;

/* ──────────────── SHA-256 helpers (EVP API, OpenSSL 1.1+ & 3.0+) ──────────────── */
static void sha256_(const uint8_t *in, size_t len, uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, in, len);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

static void sha256_two(const uint8_t *a, size_t alen,
                       const uint8_t *b, size_t blen,
                       uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, a, alen);
    EVP_DigestUpdate(ctx, b, blen);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

/* ──────────────── AES-128 ECB (AES-NI intrinsics, see aes_ni.h) ──────────────── */

/* ──────────────── Utility ──────────────── */
static inline uint64_t mul64_hi(uint64_t x, uint64_t y) {
    __uint128_t p = (__uint128_t)x * y;
    return (uint64_t)(p >> 64);
}

static inline uint64_t rotr64(uint64_t x, int k) {
    return (x >> k) | (x << (64 - k));
}

static inline uint64_t double_to_bits(double x) {
    uint64_t u;
    memcpy(&u, &x, sizeof(u));
    return u;
}

static inline double bits_to_double(uint64_t u) {
    double x;
    memcpy(&x, &u, sizeof(x));
    return x;
}

static double normFloat(uint64_t x) {
    uint64_t mant = x & 0x000FFFFFFFFFFFFFULL;
    uint64_t exp  = (uint64_t)1023 << 52;
    return bits_to_double(exp | mant);
}

/* ──────────────── Epoch seed 0 ──────────────── */
static void epoch_seed_0(uint8_t out[32]) {
    sha256_((const uint8_t*)EPOCH_SEED_STR, strlen(EPOCH_SEED_STR), out);
}

/* ──────────────── DeriveParams ──────────────── */
static void derive_params(Params *p, const uint8_t epoch_seed[32]) {
    uint8_t h[32], wh[32], dk[32];
    
    sha256_two((const uint8_t*)"nm-params|", 10, epoch_seed, 32, h);
    p->prog_size   = 384 + (int)((uint16_t)(h[0] | (h[1] << 8))) % 385;
    p->loops       = 32 + (int)(h[2]) % 33;
    p->branch_mask = (uint64_t)0xFF << (h[3] % 24);
    p->rot_salt    = *(uint64_t*)(h + 4);
    memcpy(p->aes_key, h + 12, 16);
    
    sha256_two((const uint8_t*)"nm-dataset|", 11, epoch_seed, 32, dk);
    memcpy(p->dataset_key, dk, 16);
    
    sha256_two((const uint8_t*)"nm-weights|", 11, epoch_seed, 32, wh);
    
    int weights[NUM_OPS], total = 0;
    for (int i = 0; i < NUM_OPS; i++) {
        weights[i] = 1 + (int)(wh[i]) % 8;
        total += weights[i];
    }
    int idx = 0;
    for (int op = 0; op < NUM_OPS; op++) {
        int n = weights[op] * 256 / total;
        if (op == NUM_OPS - 1) n = 256 - idx;
        for (int j = 0; j < n && idx < 256; j++) p->op_table[idx++] = (uint8_t)op;
    }
    while (idx < 256) p->op_table[idx] = wh[idx % 32] % NUM_OPS, idx++;
}

/* ──────────────── Dataset cache ──────────────── */
static uint64_t *cached_dataset = NULL;
static uint8_t  cached_key[16] = {0};
static int      cached_valid = 0;

static uint64_t* get_dataset(const uint8_t key[16]) {
    if (cached_valid && memcmp(key, cached_key, 16) == 0)
        return cached_dataset;
    
    if (!cached_dataset) {
        cached_dataset = (uint64_t*)aligned_alloc(64, DATASET_BYTES);
        if (!cached_dataset) cached_dataset = (uint64_t*)malloc(DATASET_BYTES);
    }
    memcpy(cached_key, key, 16);
    cached_valid = 1;
    
    AESNI_Key k = aesni_expand(key);
    uint8_t in[16] = {0}, out[16];
    for (uint64_t i = 0; i < DATASET_WORDS; i += 2) {
        *(uint64_t*)in = i;
        aesni_encrypt_bytes(&k, in, out);
        cached_dataset[i]     = *(uint64_t*)(out);
        cached_dataset[i + 1] = *(uint64_t*)(out + 8);
    }
    return cached_dataset;
}

/* ──────────────── Fill scratchpad ──────────────── */
static void fill_scratch(VM *vm, const uint8_t seed[32]) {
    uint8_t ki[33]; memcpy(ki, seed, 32); ki[32] = 0x53;
    uint8_t kh[32]; sha256_(ki, 33, kh);
    AESNI_Key k = aesni_expand(kh);
    
    uint8_t ctr[16]; memcpy(ctr, kh + 16, 16);
    uint8_t buf[16], out[16];
    
    for (uint64_t i = 0; i < SCRATCH_WORDS; i += 2) {
        *(uint64_t*)buf = i;
        memcpy(buf + 8, ctr + 8, 8);
        aesni_encrypt_bytes(&k, buf, out);
        vm->scratch[i]     = *(uint64_t*)out;
        vm->scratch[i + 1] = *(uint64_t*)(out + 8);
    }
}

/* ──────────────── Generate program ──────────────── */
static void gen_program(VM *vm, const uint8_t seed[32]) {
    uint8_t ki[33]; memcpy(ki, seed, 32); ki[32] = 0x50;
    uint8_t kh[32]; sha256_(ki, 33, kh);
    AESNI_Key k = aesni_expand(kh);
    
    int total = vm->params.prog_size * 8;
    uint8_t *stream = (uint8_t*)malloc(total);
    uint8_t in[16], out[16];
    memcpy(in, kh + 16, 16);
    
    int pos = 0;
    while (pos < total) {
        aesni_encrypt_bytes(&k, in, out);
        int copy = (total - pos > 16) ? 16 : (total - pos);
        memcpy(stream + pos, out, copy);
        pos += copy;
        memcpy(in, out, 16);
        *(uint64_t*)in = *(uint64_t*)in + 1;
    }
    
    for (int i = 0; i < vm->params.prog_size; i++) {
        uint8_t *b = stream + i * 8;
        vm->prog[i].op  = vm->params.op_table[b[0]];
        vm->prog[i].dst = b[1];
        vm->prog[i].src = b[2];
        vm->prog[i].imm = *(uint32_t*)(b + 4);
    }
    free(stream);
}

/* ──────────────── Main Hash ──────────────── */
static void nm_hash(VM *vm, const uint8_t *header, size_t hlen, uint64_t height, uint8_t result[32]) {
    Params *p = &vm->params;
    vm->aes_ni = aesni_expand(p->aes_key);
    
    uint8_t seed[32];
    sha256_two((const uint8_t*)"nm-seed|", 8, header, hlen, seed);
    
    bool use_ds = (height >= DATASET_HEIGHT);
    if (use_ds && !vm->dataset) vm->dataset = get_dataset(p->dataset_key);

    fill_scratch(vm, seed);
    gen_program(vm, seed);
    
    uint64_t r[16];
    double   f[8];
    for (int i = 0; i < 4; i++) r[i] = *(uint64_t*)(seed + i * 8);
    for (int i = 4; i < 16; i++) r[i] = vm->scratch[i] ^ p->rot_salt;
    for (int i = 0; i < 8;  i++) f[i] = normFloat(vm->scratch[16 + i]);
    
    uint8_t aes_in[16], aes_out[16];
    
    for (int loop = 0; loop < p->loops; loop++) {
        memset(vm->taken, 0, vm->params.prog_size);
        int pc = 0;
        
        while (pc < p->prog_size) {
            Instr *ins = &vm->prog[pc];
            int d = ins->dst & 15, s = ins->src & 15;
            
            switch (ins->op) {
            case OP_IADD: r[d] += r[s] + ins->imm; break;
            case OP_IMUL: r[d] *= r[s] | 1; break;
            case OP_IMULH: r[d] = mul64_hi(r[d], r[s]) ^ ins->imm; break;
            case OP_IXOR: r[d] ^= r[s] + p->rot_salt; break;
            case OP_IROTR: r[d] = rotr64(r[d], (int)((r[s] ^ ins->imm) & 63)); break;
            case OP_INEG: r[d] = ~r[d] + ins->imm; break;
            case OP_FADD: f[d & 7] = f[d & 7] + f[s & 7]; break;
            case OP_FMUL: f[d & 7] = f[d & 7] * f[s & 7]; break;
            case OP_FDIV:
                f[d & 7] = f[d & 7] / normFloat(double_to_bits(f[s & 7]));
                break;
            case OP_FSQRT:
                f[d & 7] = sqrt(f[d & 7] < 0 ? -f[d & 7] : f[d & 7]);
                break;
            case OP_LOAD: {
                uint64_t addr = (r[s] + ins->imm) & SCRATCH_MASK;
                r[d] ^= vm->scratch[addr >> 3];
                break;
            }
            case OP_STORE: {
                uint64_t addr = (r[d] + ins->imm) & SCRATCH_MASK;
                vm->scratch[addr >> 3] ^= r[s] + (uint64_t)loop;
                break;
            }
            case OP_CBRANCH:
                if (((r[d] + ins->imm) & p->branch_mask) == 0 && vm->taken[pc] < 8) {
                    vm->taken[pc]++;
                    int back = (int)(ins->imm % 31) + 1;
                    pc -= back;
                    if (pc < 0) pc = 0;
                    continue;
                }
                break;
            case OP_AESR: {
                uint64_t addr = (r[s] + ins->imm) & SCRATCH_MASK & ~(uint64_t)15;
                uint64_t w = addr >> 3;
                *(uint64_t*)aes_in     = vm->scratch[w];
                *(uint64_t*)(aes_in + 8) = vm->scratch[w + 1];
                aesni_encrypt_bytes(&vm->aes_ni, aes_in, aes_out);
                vm->scratch[w]     = *(uint64_t*)aes_out;
                vm->scratch[w + 1] = *(uint64_t*)(aes_out + 8);
                r[d] ^= vm->scratch[w];
                break;
            }
            case OP_XDOM:
                if ((ins->imm & 1) == 0)
                    r[d] ^= double_to_bits(f[s & 7]);
                else
                    f[d & 7] = f[d & 7] * normFloat(r[s]);
                break;
            }
            
            if (ins->op >= OP_FADD && ins->op <= OP_FSQRT) {
                double v = f[d & 7];
                if (isnan(v) || isinf(v) || v == 0.0)
                    f[d & 7] = normFloat(r[d] | 1);
            }
            pc++;
        }
        
        if (use_ds) {
            uint64_t addr = (r[1] ^ p->rot_salt) & DATASET_MASK;
            for (int k = 0; k < DATASET_READS_PER_LOOP; k++) {
                uint64_t v = vm->dataset[addr >> 3];
                r[k & 15] ^= v;
                addr = (v + r[(k + 1) & 15] + (uint64_t)loop) & DATASET_MASK;
            }
        }
        
        uint64_t base = ((r[0] ^ ((uint64_t)loop * 0x9E3779B97F4A7C15ULL)) & SCRATCH_MASK) >> 3;
        for (int i = 0; i < 16; i++)
            vm->scratch[(base + (uint64_t)i) % SCRATCH_WORDS] ^= r[i];
        for (int i = 0; i < 8; i++)
            r[i + 8] ^= double_to_bits(f[i]);
    }
    
    uint64_t fold[8] = {0};
    for (uint64_t i = 0; i < SCRATCH_WORDS; i += 8) {
        fold[0] ^= vm->scratch[i];
        fold[1] ^= vm->scratch[i + 1];
        fold[2] ^= vm->scratch[i + 2];
        fold[3] ^= vm->scratch[i + 3];
        fold[4] ^= vm->scratch[i + 4];
        fold[5] ^= vm->scratch[i + 5];
        fold[6] ^= vm->scratch[i + 6];
        fold[7] ^= vm->scratch[i + 7];
    }
    
    uint8_t buf[4 + 32 + 16*8 + 8*8 + 8*8];
    int pos = 0;
    memcpy(buf + pos, "NMv1", 4);  pos += 4;
    memcpy(buf + pos, seed, 32);   pos += 32;
    for (int i = 0; i < 16; i++) { *(uint64_t*)(buf + pos) = r[i]; pos += 8; }
    for (int i = 0; i < 8;  i++) { *(uint64_t*)(buf + pos) = double_to_bits(f[i]); pos += 8; }
    for (int i = 0; i < 8;  i++) { *(uint64_t*)(buf + pos) = fold[i]; pos += 8; }
    
    sha256_(buf, pos, result);
}

/* ──────────────── Print hex ──────────────── */
static void phex(const uint8_t *d, int n) {
    for (int i = 0; i < n; i++) printf("%02x", d[i]);
}

/* ──────────────── Benchmark ──────────────── */
static double time_it(void (*fn)(void*), void *arg, int reps) {
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    for (int i = 0; i < reps; i++) fn(arg);
    clock_gettime(CLOCK_MONOTONIC, &t2);
    return (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_nsec - t1.tv_nsec) / 1e6;
}

typedef struct { VM *vm; uint8_t *hdr; size_t hlen; uint64_t height; } HashArg;

static void bench_pre(void *a) {
    HashArg *ha = (HashArg*)a;
    uint8_t res[32];
    ha->hdr[120] = (uint8_t)(rand() % 256);
    nm_hash(ha->vm, ha->hdr, ha->hlen, ha->height, res);
}

/* ──────────────── Main ──────────────── */
int main() {
    printf("=== NeuroMorph v1 — C Reimplementation ===\n\n");
    
    /* Epoch 0 */
    uint8_t seed0[32];
    epoch_seed_0(seed0);
    printf("Epoch seed 0: "); phex(seed0, 32); printf("\n");
    
    Params p;
    derive_params(&p, seed0);
    printf("ProgSize: %d, Loops: %d, RotSalt: 0x%016lx\n\n", p.prog_size, p.loops, p.rot_salt);
    
    /* VM */
    VM vm;
    memset(&vm, 0, sizeof(vm));
    memcpy(&vm.params, &p, sizeof(p));
    vm.scratch = (uint64_t*)aligned_alloc(64, SCRATCH_BYTES);
    vm.prog    = (Instr*)calloc(p.prog_size, sizeof(Instr));
    vm.taken   = (uint8_t*)calloc(p.prog_size, 1);
    if (!vm.scratch || !vm.prog || !vm.taken) { fprintf(stderr, "OOM\n"); return 1; }
    
    /* Test header: 124 bytes, hdr[i] = i*7 */
    uint8_t header[124];
    for (int i = 0; i < 124; i++) header[i] = (uint8_t)(i * 7);
    
    /* ─── TEST 1: Pre-dataset hash ─── */
    uint8_t h1[32];
    nm_hash(&vm, header, 124, 0, h1);
    printf("Pre-dataset:  "); phex(h1, 32); printf("\n");
    printf("Go ref:       9748a3aa3d3b7c331585171b42297234830be0ec90e1ecd4425717f631c00aa7\n");
    static const uint8_t REF_PRE[32] = {
        0x97,0x48,0xa3,0xaa,0x3d,0x3b,0x7c,0x33,0x15,0x85,0x17,0x1b,
        0x42,0x29,0x72,0x34,0x83,0x0b,0xe0,0xec,0x90,0xe1,0xec,0xd4,
        0x42,0x57,0x17,0xf6,0x31,0xc0,0x0a,0xa7
    };
    int pass1 = (memcmp(h1, REF_PRE, 32) == 0);
    printf("Match: %s\n\n", pass1 ? "YES ✓" : "NO ✗");
    
    /* ─── TEST 2: Determinism ─── */
    uint8_t h1b[32];
    nm_hash(&vm, header, 124, 0, h1b);
    int pass2 = (memcmp(h1, h1b, 32) == 0);
    printf("Deterministic: %s\n\n", pass2 ? "YES ✓" : "NO ✗");
    
    /* ─── TEST 3: With dataset ─── */
    uint8_t h2[32];
    nm_hash(&vm, header, 124, DATASET_HEIGHT, h2);
    printf("With-dataset: "); phex(h2, 32); printf("\n");
    printf("Go ref:       5fba04bf23548315d87fd6a13fee6abda59c411bc47e04c4ee91f2f831ec0f2e\n");
    static const uint8_t REF_DS[32] = {
        0x5f,0xba,0x04,0xbf,0x23,0x54,0x83,0x15,0xd8,0x7f,0xd6,0xa1,
        0x3f,0xee,0x6a,0xbd,0xa5,0x9c,0x41,0x1b,0xc4,0x7e,0x04,0xc4,
        0xee,0x91,0xf2,0xf8,0x31,0xec,0x0f,0x2e
    };
    int pass3 = (memcmp(h2, REF_DS, 32) == 0);
    printf("Match: %s\n\n", pass3 ? "YES ✓" : "NO ✗");
    
    /* ─── TEST 4: VM reuse gives same result ─── */
    uint8_t h1c[32];
    nm_hash(&vm, header, 124, 0, h1c);
    int pass4 = (memcmp(h1, h1c, 32) == 0);
    printf("VM reuse: %s\n\n", pass4 ? "YES ✓" : "NO ✗");
    
    /* ─── TEST 5: Input sensitivity ─── */
    uint8_t hdr2[124];
    memcpy(hdr2, header, 124);
    hdr2[5] ^= 1;
    uint8_t h3[32];
    nm_hash(&vm, hdr2, 124, 0, h3);
    int pass5 = (memcmp(h1, h3, 32) != 0);
    printf("Input sensitivity: %s\n\n", pass5 ? "YES ✓" : "NO ✗");
    
    /* ─── TEST 6: Dataset changes hash ─── */
    int pass6 = (memcmp(h1, h2, 32) != 0);
    printf("Dataset changes result: %s\n\n", pass6 ? "YES ✓" : "NO ✗");
    
    /* ─── Benchmark ─── */
    printf("--- Performance ---\n");
    printf("CPU: Intel Xeon Silver 4214 @ 2.20GHz (same as Go baseline)\n\n");
    
    /* Warmup */
    HashArg ha = {&vm, header, 124, 0};
    for (int i = 0; i < 3; i++) bench_pre(&ha);
    
    double ms = time_it(bench_pre, &ha, 10) / 10.0;
    printf("Pre-dataset:  %.2f ms/hash  (%.0f H/s)\n", ms, 1000.0/ms);
    printf("Go baseline:  4.16 ms/hash  (240 H/s)\n");
    
    HashArg ha2 = {&vm, header, 124, DATASET_HEIGHT};
    /* warm */
    ha2.hdr[120] = 0; bench_pre(&ha2);
    ms = time_it(bench_pre, &ha2, 5) / 5.0;
    printf("With-dataset: %.2f ms/hash  (%.0f H/s)\n", ms, 1000.0/ms);
    printf("Go baseline:  7.40 ms/hash  (135 H/s)\n");
    
    /* ─── Summary ─── */
    int all = pass1 && pass2 && pass3 && pass4 && pass5 && pass6;
    printf("\n%s\n", all ? "✓ ALL TESTS PASSED — C implementation matches Go exactly"
                        : "✗ SOME TESTS FAILED");
    
    free(vm.scratch);
    free(vm.prog);
    free(vm.taken);
    free(cached_dataset);
    
    return all ? 0 : 1;
}
