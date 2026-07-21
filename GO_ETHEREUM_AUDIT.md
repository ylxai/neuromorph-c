# go-ethereum Security Audit

Audit target: [go-ethereum](https://github.com/ethereum/go-ethereum)
Date: July 2026  
Focus: Amsterdam fork (EIP-7843, EIP-8024, EIP-8037, EIP-8038)

## Files Reviewed

| File | LOC | Focus |
|------|-----|-------|
| `core/vm/instructions.go` | 1190 | DUPN, SWAPN, EXCHANGE, decodeSingle, decodePair |
| `core/vm/eips.go` | 600+ | EIP enable functions |
| `core/vm/jump_table.go` | 1124 | Amsterdam instruction set |
| `core/vm/stack.go` | 242 | Stack back() implementation |
| `core/vm/gas_table.go` | 740 | gasCreateEip8037, gasSStore8037And8038 |
| `core/vm/operations_acl.go` | 548 | gasSLoad8038, gasCall8038 |

## Findings Summary

### No critical vulnerabilities found

All reviewed Amsterdam EIP implementations follow the specification correctly.
Key checks:

- ✅ `decodeSingle` — correct bijection (x+145)%256, range [17,235]
- ✅ `decodePair` — XOR+grid encoding, maps 210 valid values to (n,m) pairs
- ✅ `back(n)` — correct pointer arithmetic for stack depth
- ✅ Stack underflow checks — all new opcodes check `len() < required` before access
- ✅ Reserved ranges — DUPN/SWAPN (91-127), EXCHANGE (82-127) properly excluded
- ✅ Gas overflow — `Uint64WithOverflow()` checks present in CREATE paths
- ✅ ReadOnly protection — CREATE/SSTORE check `evm.readOnly`
- ✅ Access list consistency — SLOTNUM/SLOAD/SSTORE properly maintain access lists

### Minor observations

1. **EXCHANGE self-swap** (n==m): Results in no-op, which is correct and safe.
   The swap `*nth, *mth = *mth, *nth` with identical pointers works correctly.

2. **DUPN with n=1**: Behaves like legacy DUP but with different gas cost
   (GasFastestStep vs DUP's GasVeryLowest). This is by design per EIP-8024.

3. **Operand decode edge cases**: When code ends abruptly (`i >= len(code)`),
   the missing immediate is treated as 0x00, which decodes to the maximum value
   in the range. This is consistent with the PUSHn convention.

## Next Steps

- [ ] Fuzz `decodePair` with all 256 possible byte values
- [ ] Check `gasCall8038` for nested call gas calculation issues
- [ ] Review SELFDESTRUCT (EIP-6780 + EIP-8037) gas consistency
- [ ] Extend audit to P2P layer (devp2p, Ethereum node discovery)
- [ ] Cross-check with Ethereum Foundation bug bounty scope

## Methodology

1. Static code review of Amsterdam-specific code paths
2. Edge case analysis for stack operations (depth, bounds)
3. Gas cost consistency verification across call contexts
4. Access list interaction review (EIP-2929 compatibility)

**Note**: This is a preliminary audit. No critical vulnerabilities were identified
in the initial scope. The code quality of the go-ethereum team is high — new EIP
implementations follow established patterns and include proper safety checks.
