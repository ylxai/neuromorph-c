From: Ylx <ylexrapper@gmail.com>
To: grants@kraken.com
Subject: Open Source Grant Proposal — PoW Reference Implementation & Optimization Toolkit

Hi Kraken Grants Team,

I'm submitting a proposal for an open-source grant to fund the development of a
C reference implementation and optimization toolkit for CPU-based Proof-of-Work
algorithms, focused on the NeuroMorph algorithm (Cereblix CRB) with patterns
directly applicable to Monero/RandomX and other CPU-mineable coins.

## Deliverables

### 1. C Reference Implementation (complete)
A byte-identical C port of the NeuroMorph v1 PoW VM (Go → C):
- 514 lines, standalone, zero external dependencies beyond OpenSSL
- Verified against the Go consensus reference via TestCrossPlatformHash
- https://github.com/ylxai/cereblix/tree/feature/neuromorph-c

### 2. AES-NI Performance Optimization (complete)
Replaced OpenSSL EVP with direct AES-NI intrinsics:
- 136× hash rate improvement (6 → 878 H/s)
- C port now 3.6× faster than the Go reference implementation
- Reusable key expansion + encryption header (aes_ni.h, 37 lines)
- Applicable to any AES-based PoW (RandomX uses AES, Monero benefits)

### 3. Security Analysis (complete)
Systematic vulnerability analysis of the NeuroMorph algorithm:
- 10 potential vulnerabilities identified and tested
- 2 confirmed valid (low severity): DatasetHeight grace period, float determinism
- Full documentation in CELAH_V1.md
- One pull request already merged upstream (readability fix for fold base
  precedence bug that breaks C/C++ ports):
  https://github.com/CereblixCRB/cereblix/pull/2

### 4. Cross-Platform Benchmark Suite (planned)
A framework for benchmarking PoW algorithm performance across:
- Intel/AMD CPUs with AES-NI/VAES
- ARM64 with ARMv8 AES instructions
- WebAssembly via Emscripten compilation

## Impact

This work benefits the broader CPU-mining ecosystem by:
- Providing a clean, minimal C reference that any developer can study
- Documenting the AES-NI optimization pattern for PoW algorithms
- Identifying and fixing a precedence bug that would break all C ports
- Establishing a benchmark methodology for comparing PoW implementations

## About Me

I'm an independent developer with deep experience in:
- C/Go systems programming and performance optimization
- Proof-of-Work algorithm analysis and implementation
- Cryptographic primitive optimization (AES-NI, SHA-256)
- Cross-language porting with verified byte-identical outputs

The complete source code is available at:
https://github.com/ylxai/cereblix/tree/feature/neuromorph-c

Happy to discuss further or provide additional materials.

Best,
Ylx
