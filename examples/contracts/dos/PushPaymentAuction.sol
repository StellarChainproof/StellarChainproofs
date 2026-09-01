// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/**
 * @title PushPaymentAuction
 * @notice Vulnerable auction performing direct push refund on outbid.
 */
contract PushPaymentAuction {
    address payable public highestBidder;
    uint256 public highestBid;

    function bid() external payable {
        require(msg.value > highestBid, "Bid too low");

        if (highestBidder != address(0)) {
            // Vulnerability: Direct push payment refund (CP-DOS-002)
            // If previous highest bidder is a malicious contract rejecting transfers, no one can outbid them!
            highestBidder.transfer(highestBid);
        }

        highestBidder = payable(msg.sender);
        highestBid = msg.value;
    }
}
