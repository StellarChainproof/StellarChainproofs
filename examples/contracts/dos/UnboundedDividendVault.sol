// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/**
 * @title UnboundedDividendVault
 * @notice Vulnerable contract containing unbounded loop iteration, push payments, and array growth.
 */
contract UnboundedDividendVault {
    address public owner;
    address[] public shareholders;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    constructor() {
        owner = msg.sender;
    }

    function registerShareholder(address user, uint256 shareAmount) external {
        // Vulnerability: Unrestricted array growth without limits or access control (CP-DOS-009)
        shareholders.push(user);
        shares[user] += shareAmount;
        totalShares += shareAmount;
    }

    function distributeDividends() external payable {
        require(msg.value > 0, "No dividends");
        require(totalShares > 0, "No shares");

        // Vulnerability: Unbounded loop over dynamic storage array (CP-DOS-001)
        for (uint256 i = 0; i < shareholders.length; i++) {
            address payable recipient = payable(shareholders[i]);
            uint256 payout = (msg.value * shares[recipient]) / totalShares;

            // Vulnerability: Push-Payment pattern inside loop (CP-DOS-002)
            // If one recipient reverts, entire distribution bricks!
            recipient.transfer(payout);
        }
    }
}
