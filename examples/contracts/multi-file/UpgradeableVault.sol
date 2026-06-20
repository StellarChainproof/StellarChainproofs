// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseVault.sol";

/**
 * Minimal UUPS-style interface stub for inheritance testing.
 * Real projects use @openzeppelin/contracts-upgradeable.
 */
interface IUUPSUpgradeable {
    function upgradeTo(address newImplementation) external;
}

/**
 * UpgradeableVault.sol
 *
 * Inherits BaseVault's empty _authorizeUpgrade — anyone can upgrade.
 * Scanning this file alone should still detect CP-116 via import graph resolution.
 */
contract UpgradeableVault is BaseVault, IUUPSUpgradeable {
    function upgradeTo(address newImplementation) external override {
        _authorizeUpgrade(newImplementation);
        // upgrade logic would follow in a real proxy
    }
}
