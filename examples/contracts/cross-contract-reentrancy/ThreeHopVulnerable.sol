// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * 3-hop cross-contract reentrancy fixture (VULNERABLE)
 *
 * Attack path:
 *   VaultX.withdraw()  ──calls──►  RouterY.forward()
 *   RouterY.forward()  ──calls──►  ReceiverZ.onReceive()
 *   ReceiverZ.onReceive() ──re-enters──►  VaultX.withdraw()
 *
 * VaultX.withdraw() has unfinalized `deposits[msg.sender]` when it calls
 * RouterY, which chains through to ReceiverZ, which calls back into VaultX.
 */

contract ReceiverZ {
    address public vault;

    constructor(address _vault) {
        vault = _vault;
    }

    /// @notice Called by RouterY; re-enters VaultX with unfinalized state.
    function onReceive(address target) external {
        // Re-enter VaultX directly
        (bool ok, ) = target.call(abi.encodeWithSignature("withdraw()"));
        require(ok, "reentry failed");
    }
}

contract RouterY {
    ReceiverZ public receiver;

    constructor(address _receiver) {
        receiver = ReceiverZ(_receiver);
    }

    /// @notice Intermediate hop: forwards the call to ReceiverZ.
    function forward(address origin) external {
        receiver.onReceive(origin);
    }
}

contract VaultX {
    mapping(address => uint256) public deposits;
    RouterY public router;

    event Withdrawal(address indexed user, uint256 amount);

    constructor(address _router) {
        router = RouterY(_router);
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    /// @notice Vulnerable: deposits[msg.sender] is read before router.forward()
    ///         is called. The 3-hop chain re-enters here with stale deposits.
    function withdraw() external {
        uint256 amount = deposits[msg.sender]; // READ — unfinalized
        require(amount > 0, "nothing");

        // 3-hop chain: VaultX -> RouterY -> ReceiverZ -> VaultX
        router.forward(address(this)); // external call with unfinalized state

        deposits[msg.sender] = 0; // WRITE — too late
        emit Withdrawal(msg.sender, amount);
    }
}
