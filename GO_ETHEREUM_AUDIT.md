# go-ethereum Security Audit

Audit target: [go-ethereum](https://github.com/ethereum/go-ethereum)
Branch: `master` (commit: 6e49f8e)
Focus: Amsterdam fork (EIP-7843, EIP-8024, EIP-8037, EIP-8038)
Date: July 2026

## Methodology

1. Static analysis of new EVM opcodes in the Amsterdam fork
2. Edge case testing for integer overflow/underflow
3. Stack depth boundary analysis
4. Gas cost consistency verification

## Amsterdam Fork — New Opcodes

| EIP | Opcode | Function | Risk |
|-----|--------|----------|------|
| 7843 | SLOTNUM | `opSlotNum` | Low — simple push |
| 8024 | DUPN | `opDupN` | Medium — stack depth |
| 8024 | SWAPN | `opSwapN` | Medium — stack depth |
| 8024 | EXCHANGE | `opExchange` | Medium — pair decode |
| 8037 | CREATE gas | `gasCreateEip8037` | Medium — gas repricing |
| 8038 | SLOAD/SSTORE | `gasSLoad8038` | Medium — state gas changes |

## Analysis Notes

### EIP-8024: DUPN / SWAPN / EXCHANGE

The new `DUPN`, `SWAPN`, and `EXCHANGE` opcodes read an immediate byte operand
from the bytecode stream (`code[*pc+1]`). Reserved ranges prevent collisions
with legacy single-byte opcodes.

**DUPN**: duplicates the n-th stack item (1-indexed).  
`n = decodeSingle(x)`, where `x` is the immediate byte.

**SWAPN**: swaps the top with the (n+1)-th item.  
`n = decodeSingle(x)`.

**EXCHANGE**: swaps the (n+1)-th and (m+1)-th items.  
`n, m = decodePair(x)`.

### EIP-7843: SLOTNUM

Pushes `evm.Context.SlotNum` to the stack — the current execution slot.
Deterministic, constant gas, minimal risk.

### EIP-8037 / 8038: State Gas Metering

Reprices gas costs for state-access opcodes (CREATE, SLOAD, SSTORE, BALANCE,
EXTCODE*, CALL family, SELFDESTRUCT) using a multidimensional metering model.

## To-do

- [ ] Trace `decodePair` for out-of-range values (n, m could overlap?)
- [ ] Check `back(n)` implementation for large n values
- [ ] Verify gas cost consistency across call contexts
- [ ] Fuzz EXCHANGE with n == m (self-swap)
- [ ] Check DUPN with n=1 (should behave like DUP)
