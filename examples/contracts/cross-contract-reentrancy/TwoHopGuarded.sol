// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * 2-hop cross-contract reentrancy fixture (SAFE / GUARDED)
 *
 * Same structural shape as TwoHopVulnerable.sol but VaultSafe applies the
 * Checks-Effects-Interactions pattern: balances is decremented BEFORE the
 * external call, so re-entry finds a zero balance and cannot drain funds.
 *
 * CP-121 MUST produce zero findings for this contract pair.
 */

contract VaultSafe {
    mapping(address => uint256) public balances;

    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice Safe: state update (CEI) before external call.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");

        // WRITE first — CEI pattern applied correctly
        balances[msg.sender] = 0;

        // External call happens AFTER state finalization
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        emit Withdrawal(msg.sender, amount);
    }
}

/// @dev Attacker contract that mirrors TwoHopVulnerable's AttackerB
contract AttackerSafe {
    VaultSafe public vault;

    constructor(address _vault) {
        vault = VaultSafe(_vault);
    }

    function execute() external {
        vault.withdraw(); // re-entry finds balance == 0, harmless
    }

    receive() external payable {
        vault.withdraw(); // balance already zero, no effect
    }
}
