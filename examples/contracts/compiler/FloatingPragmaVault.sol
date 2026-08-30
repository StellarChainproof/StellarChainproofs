// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FloatingPragmaVault
 * @notice Vault contract with an unpinned floating pragma.
 */
contract FloatingPragmaVault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
    }
}
