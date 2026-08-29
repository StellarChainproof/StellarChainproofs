# Cross-Chain Bridge and Message Verification Safety

ChainProof's bridge analysis engine (`CP-BRG-001` through `CP-BRG-016`) models cross-chain bridges and message verification contracts for structural security vulnerabilities.

## Threat model

The analyzer assumes:

- Relayers, bridges, or transport layers may redeliver messages
- Validator signatures may be duplicated, unsorted, or include zero addresses
- Message payloads can be attacker-controlled
- Source chain reorgs and optimistic fraud are in scope

The analyzer does **not** prove transport-layer authenticity, oracle correctness, or live-network finality.

## Rules

| Rule | Category | Description |
|------|----------|-------------|
| CP-BRG-001 | domain-separation | Missing source chain binding on inbound messages |
| CP-BRG-002 | domain-separation | Missing destination binding on outbound messages |
| CP-BRG-003 | replay-protection | Replayable messages without nonce/ID consumption |
| CP-BRG-004 | replay-protection | Weak nonce management |
| CP-BRG-005 | validator-governance | Unsafe validator/threshold updates |
| CP-BRG-006 | verification | Proof/signature verification bypass |
| CP-BRG-007 | verification | Duplicate validators in proof loop |
| CP-BRG-008 | verification | Unsorted validator set |
| CP-BRG-009 | verification | Zero-address validator not rejected |
| CP-BRG-010 | verification | Stale Merkle/state root acceptance |
| CP-BRG-011 | validator-governance | Unsafe quorum arithmetic |
| CP-BRG-012 | payload-execution | Unvalidated payload arbitrary execution |
| CP-BRG-013 | token-bridge | Mint without verified lock |
| CP-BRG-014 | token-bridge | Release without verified burn |
| CP-BRG-015 | finality | Missing finality/challenge window |
| CP-BRG-016 | operational-safety | Missing pause/rate-limit mitigations |

## Usage

### CLI

```bash
chainproof bridge contracts/bridge/ --format markdown
chainproof bridge contracts/ --include-rule CP-BRG-003 --fail-on critical
```

### API

```typescript
import { analyzeBridgeSource, analyzeBridgeFiles } from '@chainproof/core';

const report = analyzeBridgeSource(source, 'Bridge.sol');
const files = analyzeBridgeFiles(['contracts/bridge/'], { includeModels: true });
```

## Configuration

Versioned configuration schema (`schemaVersion: 1`):

```json
{
  "schemaVersion": 1,
  "limits": { "maxFindings": 512 },
  "includeRules": ["CP-BRG-001", "CP-BRG-003"],
  "excludeRules": ["CP-BRG-016"]
}
```

## Limitations

- Static analysis only; no live-network monitoring
- Does not duplicate AI multi-contract analysis (#61)
- Framework adapters provide hints, not proofs of correctness

## Troubleshooting

- **No findings on obvious bridge**: Ensure the contract contains bridge signals (e.g. `receiveMessage`, `processedMessages`, `sourceChainId`)
- **False positives on trusted relayer paths**: Use `--exclude-rule` or document relayer authentication in code comments
- **Truncated output**: Increase `maxFindings` in configuration
