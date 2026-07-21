# NeuroMorph v1 — C Port (Final)

## Status
**✅ ALL TESTS PASSED** — byte-identik dengan Go reference

## Struktur
```
cereblix-source/
├── neuromorph/                ← Go reference (original)
│   ├── neuromorph.go
│   └── neuromorph_test.go
│
└── neuromorph-c/              ← C port
    ├── neuromorph_v1.c        (514 baris, clean)
    ├── aes_ni.h               (AES-NI intrinsics, 37 baris)
    ├── CELAH_V1.md            (analisis celah keamanan)
    └── NEUROMORPH_STATUS.md
```

## Performa (AES-NI vs EVP vs Go)

| Mode | EVP | AES-NI | Go ref | Percepatan |
|------|-----|--------|--------|-----------|
| Pre-dataset | 155 ms / 6 H/s | **1.14 ms / 878 H/s** | 4.16 ms / 240 H/s | **136×** dari EVP, **3.6×** dari Go |
| With-dataset | 155 ms / 6 H/s | **1.79 ms / 558 H/s** | 7.40 ms / 135 H/s | **86×** dari EVP, **4.1×** dari Go |

CPU: Intel Xeon Silver 4214 @ 2.20GHz

## Precompute Analysis (Jawaban untuk Mining)

### Pertanyaan: Apakah precompute bisa dipakai untuk mining?
**Tidak.** Setiap nonce = seed berbeda = fillScratch + program + register init berbeda total.

```
Nonce 0 → seed_A → fillScratch_A ~ AES 131K block → program_A → VM_A → Hash_A
Nonce 1 → seed_B → fillScratch_B ~ AES 131K block → program_B → VM_B → Hash_B
        ↑ 1 bit beda = 50%+ seed beda (SHA-256 avalanche)
```

Bisa di-cache SESAMA nonce (1× per hash) tapi mining butuh jutaan nonce berbeda.

### Bobot kerja per hash
| Fase | Bobot | Bisa precompute? | Berguna mining? |
|------|-------|-----------------|----------------|
| fillScratch | 131K AES (~40%) | ✅ Ya per seed | ❌ Seed selalu berubah |
| genProgram | ~500 AES (~0.2%) | ✅ Ya per seed | ❌ Seed selalu berubah |
| VM execution | 23.040 instruksi (~50%) | ❌ Tidak | — |
| Dataset walk | 2.304 read (~10%) | ❌ Tidak | — |

### Kesimpulan
Precompute **tidak berguna** untuk mining karena tiap nonce punya seed unik (SHA-256 menjamin avalanche). Ini BUKAN celah, tapi konsekuensi alami dari PoW yang memaksa sequential execution. 

### Satu-satunya celah yang valid
#6: `DatasetHeight = 240` — 240 blok pertama (≈4 jam) tanpa memory-hard dataset. Design choice untuk grace period. Fix: set 0 jika deploy dari genesis.

## Build
```bash
gcc -O2 -march=native -maes -msse4.1 neuromorph_v1.c -lcrypto -lssl -lm -o nm_test
./nm_test
```

## Ringkasan Pekerjaan
- ✅ C port written & verified byte-identik
- ✅ Bug precedence ^ vs & fixed
- ✅ 10 celah dianalisis, 2 valid (low)
- ✅ AES-NI intrinsics = 136× faster
- ✅ Zero compiler warnings
- ✅ Folder dipisah neuromorph/ + neuromorph-c/
