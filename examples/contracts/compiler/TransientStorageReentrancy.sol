// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title TransientStorageReentrancy
 * @notice Demonstrates transient storage usage (EIP-1153).
 */
contract TransientStorageReentrancy {
    bytes32 private constant LOCK_SLOT = 0xb88a802f472851cf57a0572b9a1d87e02e0dfcb64a275ad67c006509f6ae0945;

    modifier nonReentrantTransient() {
        assembly {
            if tload(LOCK_SLOT) {
                revert(0, 0)
            }
            tstore(LOCK_SLOT, 1)
        }
        _;
        assembly {
            tstore(LOCK_SLOT, 0)
        }
    }

    function protectedCall() external nonReentrantTransient {
        // Safe internal logic
    }
}
