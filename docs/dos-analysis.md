# Denial-of-Service, Gas-Griefing & Unbounded-Work Analysis

ChainProof provides a deterministic, production-grade static analysis engine for detecting Denial-of-Service (DoS), gas-griefing vectors, and unbounded-work vulnerabilities in Solidity smart contracts.

---

## 1. Overview & Threat Model

Denial-of-Service vulnerabilities in Ethereum and EVM-compatible blockchains rarely involve brute-force traffic volume; instead, they exploit economic and execution constraints of the EVM:

1. **Block Gas Limit deadlocks (30M gas ceiling):** When work complexity scales linearly or quadratically with dynamic storage arrays, the gas required to execute a transaction eventually exceeds the block gas limit, permanently freezing contract state transitions.
2. **Push-Payment griefing:** Sending Ether or tokens to untrusted recipient addresses inside loops or single execution paths allows a single malicious contract recipient to revert the entire transaction.
3. **Return Bombs & Quadratic Memory Expansion:** When contracts make high-level calls or low-level calls without capping returndata copying, a malicious recipient can return an arbitrarily large payload (e.g. megabytes of data), forcing exponential memory expansion gas costs that exhaust caller gas.
4. **Mass Storage Deletion:** Deleting storage elements (`delete`) inside unbounded loops costs full gas up front, while EIP-3529 limits refunds to at most 20% of the transaction gas limit.
5. **Insufficient Gas Forwarding (63/64th Rule):** EIP-150 forwards at most 63/64 of remaining gas to sub-calls. Without explicit gas stipends, relayers can grief transactions by providing barely enough gas for outer execution.

---

## 2. Rule Catalog

| Rule ID | Title | Default Severity | Category | SWC Reference |
|---|---|---|---|---|
| `CP-DOS-001` | Unbounded Loop Iteration Over Dynamic Storage Array | `High` | `denial_of_service` | SWC-128 |
| `CP-DOS-002` | Push-Payment Pattern with Unexpected Revert Risk | `High` | `denial_of_service` | SWC-113 |
| `CP-DOS-003` | External Call Fan-Out in Loop Iteration | `Medium` | `gas_griefing` | - |
| `CP-DOS-004` | Return Bomb / Unbounded Returndata Memory Expansion | `Medium` | `gas_griefing` | - |
| `CP-DOS-005` | Unbounded Storage Clearing / Mass Deletion | `Medium` | `unbounded_work` | - |
| `CP-DOS-006` | Insufficient Gas Forwarding / 63/64th Rule Griefing | `Medium` | `gas_griefing` | - |
| `CP-DOS-007` | Single-Transaction Block Gas Limit Deadlock | `High` | `denial_of_service` | - |
| `CP-DOS-008` | Unbounded Recursion Without Depth Guard | `High` | `denial_of_service` | SWC-128 |
| `CP-DOS-009` | Attacker-Controlled Array Growth / Storage Poisoning | `Medium` | `denial_of_service` | - |
| `CP-DOS-010` | Revert Propagation in Critical Batch Operation | `Low` | `gas_griefing` | - |

---

## 3. Recognized Mitigation Patterns

ChainProof's AST analyzer recognizes secure architecture patterns to eliminate false positives:

### 1. Pagination Pattern (`CP-DOS-001` suppressed)
Contracts that pass `offset` and `limit` / `count` with explicit upper bounds:
```solidity
function distributePaginated(uint256 offset, uint256 limit) external {
    require(limit <= MAX_BATCH_SIZE, "Exceeds max batch");
    uint256 end = offset + limit;
    if (end > shareholders.length) end = shareholders.length;
    for (uint256 i = offset; i < end; i++) {
        // Safe bounded loop
    }
}
```

### 2. Pull-Payment Pattern (`CP-DOS-002` suppressed)
Contracts that track pending balances internally and offer a dedicated `withdraw()` endpoint:
```solidity
mapping(address => uint256) public pendingWithdrawals;

function creditReward(address user, uint256 amount) internal {
    pendingWithdrawals[user] += amount;
}

function withdraw() external {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0);
    pendingWithdrawals[msg.sender] = 0;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
}
```

### 3. Failure Isolation with `try/catch` (`CP-DOS-003`, `CP-DOS-010` suppressed)
Batch executors that isolate individual transaction failures:
```solidity
for (uint256 i = 0; i < targets.length; i++) {
    try IReceiver(targets[i]).processTask(taskIds[i]) {
        emit TaskSucceeded(targets[i], taskIds[i]);
    } catch (bytes memory reason) {
        emit TaskFailed(targets[i], taskIds[i], reason);
    }
}
```

### 4. Checkpointed State Machines (`CP-DOS-007` suppressed)
State machines that persist progress across multiple transactions:
```solidity
uint256 public nextIndex;

function processBatch(uint256 count) external {
    require(count <= CHUNK_SIZE);
    uint256 total = queue.length;
    uint256 processed = 0;
    while (nextIndex < total && processed < count) {
        processItem(queue[nextIndex]);
        nextIndex++;
        processed++;
    }
}
```

---

## 4. CLI Reference

### `chainproof dos inspect-loops <targets...>`
Inspects all loops in Solidity files, classifying bounds (`storage_array_bounded`, `parameter_bounded`, `constant_bounded`, `paginated`, `unbounded`) and operations.

```bash
chainproof dos inspect-loops contracts/ --format table
```

### `chainproof dos fanout <targets...>`
Inspects all external calls and push payment vectors.

```bash
chainproof dos fanout contracts/ --format json
```

### `chainproof dos audit <targets...>`
Performs a complete DoS and unbounded-work audit.

```bash
chainproof dos audit contracts/ --fail-on high --format markdown --output dos-report.md
```

---

## 5. REST API Endpoints

- `POST /dos/inspect-loops`: Inspects loops and bound classifications across posted Solidity sources.
- `POST /dos/fanout`: Inspects external call fanout and payment vectors.
- `POST /dos/audit`: Generates a structured `DosAuditReport`.
