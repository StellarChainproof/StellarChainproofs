// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/**
 * @title PaginatedDividendVault
 * @notice Secure dividend vault implementing bounded pagination.
 */
contract PaginatedDividendVault {
    uint256 public constant MAX_BATCH_SIZE = 50;
    address public owner;
    address[] public shareholders;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    constructor() {
        owner = msg.sender;
    }

    function distributePaginated(uint256 offset, uint256 limit) external payable {
        require(limit <= MAX_BATCH_SIZE, "Exceeds max batch");
        require(totalShares > 0, "No shares");

        uint256 end = offset + limit;
        if (end > shareholders.length) {
            end = shareholders.length;
        }

        for (uint256 i = offset; i < end; i++) {
            address payable recipient = payable(shareholders[i]);
            uint256 payout = (msg.value * shares[recipient]) / totalShares;
            (bool ok, ) = recipient.call{value: payout}("");
            // Failure isolation
            if (!ok) {
                // Log or track failure instead of blocking
            }
        }
    }
}
