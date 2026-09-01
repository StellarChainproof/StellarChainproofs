// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IReceiver {
    function processTask(uint256 taskId) external;
}

/**
 * @title FailureIsolatedBatch
 * @notice Secure batch executor isolating individual task failures with try/catch.
 */
contract FailureIsolatedBatch {
    uint256 public constant MAX_BATCH = 50;

    event TaskSucceeded(address indexed target, uint256 taskId);
    event TaskFailed(address indexed target, uint256 taskId, bytes reason);

    function executeBatch(address[] calldata targets, uint256[] calldata taskIds) external {
        require(targets.length == taskIds.length, "Mismatched lengths");
        require(targets.length <= MAX_BATCH, "Exceeds max batch");

        for (uint256 i = 0; i < targets.length; i++) {
            try IReceiver(targets[i]).processTask(taskIds[i]) {
                emit TaskSucceeded(targets[i], taskIds[i]);
            } catch (bytes memory reason) {
                // Failure is isolated: does not revert the entire batch
                emit TaskFailed(targets[i], taskIds[i], reason);
            }
        }
    }
}
