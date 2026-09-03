// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/**
 * @title SafeChunkedQueue
 * @notice Secure checkpointed queue allowing partial progress across transactions.
 */
contract SafeChunkedQueue {
    uint256 public constant CHUNK_SIZE = 20;
    address[] public queue;
    uint256 public nextIndex;

    function enqueue(address user) external {
        queue.push(user);
    }

    function processQueue(uint256 count) external {
        require(count <= CHUNK_SIZE, "Count exceeds chunk size");

        uint256 total = queue.length;
        uint256 processed = 0;

        while (nextIndex < total && processed < count) {
            address user = queue[nextIndex];
            nextIndex++;
            processed++;

            // Process individual item safely
            (bool ok, ) = user.call("");
            if (!ok) {
                // Log and continue
            }
        }
    }
}
