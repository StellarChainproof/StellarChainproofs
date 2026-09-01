// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/**
 * @title UnboundedRecursion
 * @notice Vulnerable contract with recursive function lacking depth guard.
 */
contract UnboundedRecursion {
    function computeRecursive(uint256 value) external returns (uint256) {
        if (value == 0) return 0;
        // Vulnerability: Recursive call without explicit stack depth guard (CP-DOS-008)
        return value + computeRecursive(value - 1);
    }
}
