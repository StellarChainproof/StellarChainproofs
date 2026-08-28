// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AmbiguousBench {
    mapping(address => uint256) public balances;

    function transferWithHook(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");

        // Low level call to receiver hook
        (bool success, ) = to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, amount));
        require(success, "Hook failed");

        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
