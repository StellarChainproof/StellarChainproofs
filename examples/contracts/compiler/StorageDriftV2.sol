// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @title StorageDriftV2
 * @notice Target version 2 with storage layout slot collision and shifted offsets.
 */
contract StorageDrift {
    uint256 public balance;   // slot 0, offset 0 (32 bytes) -> Collides with owner from V1!
    address public owner;     // slot 1, offset 0 (20 bytes) -> Shifted from slot 0!
    uint96 public nonce;      // slot 1, offset 20 (12 bytes)
}
