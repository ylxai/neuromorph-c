# NeuroMorph v1 — C Reference Implementation

![C](https://img.shields.io/badge/language-C-blue) ![AES-NI](https://img.shields.io/badge/AES--NI-878%20H%2Fs-brightgreen) ![License](https://img.shields.io/badge/license-MIT-green)

**Byte-identical** C port of the NeuroMorph PoW VM (Go → C).  
Verified against the Cereblix CRB consensus reference.

## Performance

| Engine | Pre-dataset | With-dataset |
|--------|-------------|--------------|
| **C (AES-NI)** | **878 H/s** ⚡ | **558 H/s** ⚡ |
| Go reference | 240 H/s | 135 H/s |
| C (OpenSSL EVP) | 6 H/s | 6 H/s |

C is **3.6× faster than Go** and **136× faster** than the unoptimized EVP version.

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `neuromorph_v1.c` | 514 | Full VM implementation (standalone) |
| `aes_ni.h` | 37 | AES-128 via AES-NI intrinsics |
| `CELAH_V1.md` | — | Security analysis (10 vulnerabilities found) |
| `NEUROMORPH_STATUS.md` | — | Verification + benchmarks |

## Build

```bash
gcc -O2 -march=native -maes -msse4.1 neuromorph_v1.c -lcrypto -lssl -lm -o nm_test
./nm_test
```

## Verification

```
Pre-dataset:    9748a3aa3d3b7c331585171b42297234830be0ec90e1ecd4425717f631c00aa7
Go ref:         9748a3aa3d3b7c331585171b42297234830be0ec90e1ecd4425717f631c00aa7
Match:          YES ✓

With-dataset:   5fba04bf23548315d87fd6a13fee6abda59c411bc47e04c4ee91f2f831ec0f2e
Go ref:         5fba04bf23548315d87fd6a13fee6abda59c411bc47e04c4ee91f2f831ec0f2e
Match:          YES ✓
```

## Grant

This project was submitted to the **Kraken Open Source Developer Grant Program** (quarterly).
