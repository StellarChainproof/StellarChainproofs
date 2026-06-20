// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * BaseAuth.sol — parent contract with tx.origin guard in modifier.
 */
contract BaseAuth {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(tx.origin == owner, "Not owner");
        _;
    }
}
