// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * BaseVault.sol
 *
 * Defines an unprotected _authorizeUpgrade hook inherited by UpgradeableVault.
 * Scanning this file alone flags CP-116 on BaseVault.
 */
contract BaseVault {
    address internal _owner;

    constructor() {
        _owner = msg.sender;
    }

    function _authorizeUpgrade(address) internal virtual {}
}
