// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

/**
 * @title BroadPragmaVault
 * @notice Vault contract with an overly broad pragma spanning breaking compiler families.
 */
contract BroadPragmaVault {
    address public owner;
    uint256 public total;

    constructor() {
        owner = msg.sender;
    }

    function add(uint256 val) external {
        total += val;
    }
}
