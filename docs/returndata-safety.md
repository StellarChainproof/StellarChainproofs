# External Call Return-Value and Returndata Safety

ChainProof's returndata analysis engine (`CP-RTD-001` through `CP-RTD-016`) detects ignored call success flags, unchecked token returns, unsafe ABI decoding, and stale returndata patterns.

## Threat model

The analyzer assumes:

- Low-level calls (`.call`, `.send`, `.delegatecall`, `.staticcall`) can fail silently
- ERC20 tokens may be non-standard (no return value or false return)
- Returndata buffers are overwritten by subsequent calls
- Assembly returndata copies may read out of bounds

## Rules

| Rule | Category | Description |
|------|----------|-------------|
| CP-RTD-001 | ignored-return | Ignored call success flag |
| CP-RTD-002 | overwritten-return | Call result overwritten before check |
| CP-RTD-003 | token-return | Unchecked ERC20 transfer return |
| CP-RTD-004 | low-level-return | Unchecked low-level `.call()` return |
| CP-RTD-005 | decode-safety | Unsafe ABI decode without length check |
| CP-RTD-006 | stale-returndata | Stale returndata reuse across calls |
| CP-RTD-007 | batch-failure | Partial batch failure ignored |
| CP-RTD-008 | ignored-return | Ignored delegatecall return |
| CP-RTD-009 | ignored-return | Ignored staticcall return |
| CP-RTD-010 | ignored-return | Ignored send() return |
| CP-RTD-011 | transfer-safety | transfer() without return check |
| CP-RTD-012 | assembly-safety | Assembly returndata copy without bounds |
| CP-RTD-013 | try-catch | Try/catch swallows critical failure |
| CP-RTD-014 | multicall | Multicall partial failure not propagated |
| CP-RTD-015 | proxy-decode | Proxy delegatecall decode assumption |
| CP-RTD-016 | optional-call | Security-critical call marked optional |

## Recognized mitigations

- **SafeERC20**: `safeTransfer`, `safeTransferFrom`, `safeApprove`
- **Address utilities**: `functionCall`, `functionCallWithValue`, `sendValue`
- **Try/catch**: Wrapped external calls with explicit handling
- **Assembly bounds**: `returndatasize()` checks before `returndatacopy`

## Usage

### CLI

```bash
chainproof returndata contracts/ --format json
chainproof returndata Token.sol --exclude-rule CP-RTD-011
```

### API

```typescript
import { analyzeReturndataSource, detectReturndataSafety } from '@chainproof/core';

const report = analyzeReturndataSource(source, 'Vault.sol');
// Integrated into ordinary scan via detectReturndataSafety
```

## Slither merge

When `mergeSlither: true` is set in configuration, equivalent Slither return-value findings are merged while preserving ChainProof evidence paths and stable rule identities.

## Limitations

- Cannot distinguish all intentionally optional calls without `@dev optional` documentation
- Assembly analysis is pattern-based, not symbolic
- Does not execute contracts or simulate returndata at runtime

## Troubleshooting

- **False positive on documented optional call**: Add `@dev optional` comment or use `--exclude-rule CP-RTD-016`
- **Missing detection**: Ensure source contains `.call(`, `.transfer(`, or `abi.decode` patterns
- **Secure fixture still flagged**: Verify SafeERC20/Address patterns appear in source text
