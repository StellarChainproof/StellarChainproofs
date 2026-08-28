// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVaultBench {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // Vulnerable: state updated after raw call (CP-107)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }

    function authenticateAdmin() external view {
        // Vulnerable: tx.origin authorization (CP-115)
        require(tx.origin == address(0x123), "Not admin");
    }
}
