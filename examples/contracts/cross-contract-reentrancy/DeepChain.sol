// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * Deep-chain reentrancy fixture (depth > default cap of 3)
 *
 * This creates a 5-hop chain: A -> B -> C -> D -> E -> A
 * With the default traversal depth of 3, CP-121 should NOT follow beyond
 * 3 hops and therefore should NOT report a finding for the tail of this chain.
 *
 * Used by the depth-limit unit test to verify the traversal cap is enforced.
 */

contract HopE {
    address public hopA;

    constructor(address _hopA) {
        hopA = _hopA;
    }

    function bounce() external {
        // 5th hop: tries to re-enter HopA, but traversal cap prevents detection
        (bool ok, ) = hopA.call(abi.encodeWithSignature("entry()"));
        require(ok, "bounce failed");
    }
}

contract HopD {
    HopE public hopE;

    constructor(address _hopE) {
        hopE = HopE(_hopE);
    }

    function relay() external {
        hopE.bounce();
    }
}

contract HopC {
    HopD public hopD;

    constructor(address _hopD) {
        hopD = HopD(_hopD);
    }

    function pass() external {
        hopD.relay();
    }
}

contract HopB {
    HopC public hopC;

    constructor(address _hopC) {
        hopC = HopC(_hopC);
    }

    function forward() external {
        hopC.pass();
    }
}

/// @notice Entry contract with unfinalized state — but the re-entry path is 5
///         hops deep, beyond the default cap of 3.
contract HopA {
    mapping(address => uint256) public ledger;
    HopB public hopB;

    constructor(address _hopB) {
        hopB = HopB(_hopB);
    }

    function deposit() external payable {
        ledger[msg.sender] += msg.value;
    }

    function entry() external {
        uint256 amount = ledger[msg.sender]; // READ — unfinalized
        require(amount > 0, "empty");

        hopB.forward(); // chain: A -> B -> C -> D -> E -> A (5 hops)

        ledger[msg.sender] = 0; // WRITE — too late, but chain too deep to flag
    }
}
