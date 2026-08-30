// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/**
 * @title MassStorageDeletion
 * @notice Vulnerable contract attempting mass deletion in unbounded loop.
 */
contract MassStorageDeletion {
    address public admin;
    uint256[] public entries;

    constructor() {
        admin = msg.sender;
    }

    function addEntry(uint256 value) external {
        entries.push(value);
    }

    function clearAllEntries() external {
        require(msg.sender == admin, "Not admin");

        // Vulnerability: Deleting storage elements in unbounded loop (CP-DOS-005)
        for (uint256 i = 0; i < entries.length; i++) {
            delete entries[i];
        }
    }
}
