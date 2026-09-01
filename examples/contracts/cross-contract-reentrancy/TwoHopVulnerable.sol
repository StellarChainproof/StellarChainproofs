// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * 2-hop cross-contract reentrancy fixture (VULNERABLE)
 *
 * Attack path:
 *   VaultA.withdraw()  ──external call──►  AttackerB.execute()
 *   AttackerB.execute() ──re-enters──►  VaultA.withdraw()
 *
 * VaultA.withdraw() reads `balances[msg.sender]` before the external call
 * but only decrements it after — classic unfinalized state window.
 */

/// @dev The re-entrant attacker (Contract B)
interface IAttacker {
    function execute() external;
}

contract VaultA {
    mapping(address => uint256) public balances;

    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice Vulnerable: balance is read before the external call and only
    ///         decremented after, leaving an unfinalized-state window.
    function withdraw() external {
        uint256 amount = balances[msg.sender]; // READ before call — unfinalized state
        require(amount > 0, "nothing to withdraw");

        // External call to msg.sender — control leaves VaultA here.
        // An attacker can call withdraw() again before balances is decremented.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        balances[msg.sender] = 0; // WRITE after call — too late
        emit Withdrawal(msg.sender, amount);
    }

    /// @notice A second entry point that also reads balances — re-entry target.
    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }
}

contract AttackerB {
    VaultA public vault;
    uint256 public callCount;

    constructor(address _vault) {
        vault = VaultA(_vault);
    }

    /// @notice AttackerB.execute() re-enters VaultA.withdraw()
    function execute() external {
        if (callCount < 3) {
            callCount++;
            vault.withdraw(); // re-enters VaultA with balances still unfinalized
        }
    }

    receive() external payable {
        if (callCount < 3) {
            callCount++;
            vault.withdraw();
        }
    }
}
