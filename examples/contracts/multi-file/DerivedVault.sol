// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import "./BaseAuth.sol";

/**
 * DerivedVault.sol — inherits tx.origin auth from BaseAuth via onlyOwner modifier.
 */
contract DerivedVault is BaseAuth {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    function adminTransfer(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
    }
}
