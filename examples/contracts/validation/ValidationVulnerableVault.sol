// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ValidationVulnerableVault
 * @notice Intentionally vulnerable ETH vault for validation engine tests.
 *
 * VULNERABILITIES (by design — do not use in production):
 * 1. Reentrancy (CP-107): `withdraw` sends ETH before updating `balances`,
 *    allowing a malicious receiver to re-enter and drain the vault.
 * 2. tx.origin auth (CP-115): `adminWithdraw` uses `tx.origin` instead of
 *    `msg.sender` for owner authentication.
 * 3. Unchecked return value (CP-104): `unsafeTransfer` does not check the
 *    return value of `payable().call{value:...}`.
 */
contract ValidationVulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice VULNERABLE: state update happens AFTER the external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        // CP-107: send before state update — reentrancy window
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    /// @notice VULNERABLE: tx.origin used for authentication
    function adminWithdraw(uint256 amount) external {
        // CP-115: should use msg.sender, not tx.origin
        require(tx.origin == owner, "Not owner");
        payable(tx.origin).transfer(amount);
    }

    /// @notice VULNERABLE: return value not checked
    function unsafeTransfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        // CP-104: low-level call return value ignored
        payable(to).call{value: amount}(""); // solhint-disable-line
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
