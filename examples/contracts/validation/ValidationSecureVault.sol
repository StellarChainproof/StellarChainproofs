// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ValidationSecureVault
 * @notice Patched reference implementation for validation engine tests.
 *
 * SECURITY MITIGATIONS:
 * 1. Reentrancy: state is updated BEFORE the external call (CEI pattern).
 * 2. Auth: uses msg.sender (not tx.origin) throughout.
 * 3. Checked transfers: low-level call return values are always checked.
 * 4. Reentrancy guard: nonReentrant modifier prevents re-entry.
 */
contract ValidationSecureVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool private _locked;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    error Reentrancy();
    error InsufficientBalance(uint256 available, uint256 requested);
    error NotOwner();
    error TransferFailed();
    error ZeroAmount();

    modifier nonReentrant() {
        if (_locked) revert Reentrancy();
        _locked = true;
        _;
        _locked = false;
    }

    modifier onlyOwner() {
        // CP-115 fix: msg.sender not tx.origin
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable nonReentrant {
        if (msg.value == 0) revert ZeroAmount();
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice SECURE: effects before interactions (CEI pattern)
    function withdraw(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        uint256 bal = balances[msg.sender];
        if (bal < amount) revert InsufficientBalance(bal, amount);
        // CP-107 fix: state update BEFORE external call
        balances[msg.sender] = bal - amount;
        emit Withdrawal(msg.sender, amount);
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice SECURE: msg.sender-based auth
    function adminWithdraw(uint256 amount) external onlyOwner nonReentrant {
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice SECURE: return value always checked
    function safeTransfer(address to, uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        uint256 bal = balances[msg.sender];
        if (bal < amount) revert InsufficientBalance(bal, amount);
        balances[msg.sender] = bal - amount;
        // CP-104 fix: check the return value
        (bool ok, ) = payable(to).call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
