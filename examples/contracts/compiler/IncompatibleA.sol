// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

import "./IncompatibleB.sol";

contract IncompatibleA {
    IncompatibleB public b;

    constructor(address _b) {
        b = IncompatibleB(_b);
    }
}
