// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract IncompatibleB {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }
}
