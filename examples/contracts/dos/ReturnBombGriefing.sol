// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/**
 * @title ReturnBombGriefing
 * @notice Vulnerable relayer calling arbitrary targets without limiting returndata copying.
 */
contract ReturnBombGriefing {
    function executeRelay(address target, bytes calldata data) external returns (bytes memory) {
        // Vulnerability: Low-level call copying unbounded returndata (CP-DOS-004)
        (bool success, bytes memory returnData) = target.call(data);
        require(success, "Call failed");
        return returnData;
    }
}
