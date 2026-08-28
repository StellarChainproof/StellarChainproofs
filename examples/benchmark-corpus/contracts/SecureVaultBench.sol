// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecureVaultBench {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "REENTRANCY");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // Checks-Effects-Interactions pattern
        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function authenticateAdmin() external view {
        // Safe: msg.sender authorization
        require(msg.sender == address(0x123), "Not admin");
    }
}
