// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * @title LegacyMathVault
 * @notice Legacy 0.7 contract vulnerable to unchecked arithmetic overflow.
 */
contract LegacyMathVault {
    mapping(address => uint256) public balances;

    function addBalance(address to, uint256 amount) external {
        // In 0.7.x, this can overflow without reverting
        balances[to] += amount;
    }
}
