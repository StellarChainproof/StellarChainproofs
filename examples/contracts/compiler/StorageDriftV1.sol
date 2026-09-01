// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/**
 * @title StorageDriftV1
 * @notice Baseline version 1 storage layout.
 */
contract StorageDrift {
    address public owner;     // slot 0, offset 0 (20 bytes)
    uint96 public nonce;      // slot 0, offset 20 (12 bytes)
    uint256 public balance;   // slot 1, offset 0 (32 bytes)
}
