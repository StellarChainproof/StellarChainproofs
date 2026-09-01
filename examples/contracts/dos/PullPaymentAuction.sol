// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/**
 * @title PullPaymentAuction
 * @notice Secure auction implementing pull-over-push payment pattern.
 */
contract PullPaymentAuction {
    address public highestBidder;
    uint256 public highestBid;
    mapping(address => uint256) public pendingReturns;

    function bid() external payable {
        require(msg.value > highestBid, "Bid too low");

        if (highestBidder != address(0)) {
            // Secure: Credit balance in internal ledger
            pendingReturns[highestBidder] += highestBid;
        }

        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    function withdraw() external returns (bool) {
        uint256 amount = pendingReturns[msg.sender];
        require(amount > 0, "No funds to withdraw");

        pendingReturns[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) {
            pendingReturns[msg.sender] = amount;
            return false;
        }

        return true;
    }
}
