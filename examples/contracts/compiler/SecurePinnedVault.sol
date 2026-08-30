// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @title SecurePinnedVault
 * @notice Reference contract with pinned compiler version, custom errors, and checked math.
 */
contract SecurePinnedVault {
    address public immutable owner;
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    error Unauthorized();
    error InsufficientBalance();
    error ZeroAmount();

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        if (msg.value == 0) revert ZeroAmount();
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        if (balances[msg.sender] < amount) revert InsufficientBalance();

        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert InsufficientBalance();

        emit Withdrawn(msg.sender, amount);
    }
}
