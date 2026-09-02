// SPDX-License-Identifier: MIT
pragma solidity 0.8.24; // Secure: Locked pragma, modern version

contract SecureVault {
    mapping(address => uint256) private balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance");

        // Secure: State updated BEFORE external call (Checks-Effects-Interactions)
        balances[msg.sender] = 0;

        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");
    }
}
