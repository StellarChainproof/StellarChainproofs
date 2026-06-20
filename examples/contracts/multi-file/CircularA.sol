// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseVault.sol";

/**
 * CircularA.sol — part of a circular import pair for warning tests.
 */
import "./CircularB.sol";

contract CircularA is BaseVault {
    CircularB public other;
}
