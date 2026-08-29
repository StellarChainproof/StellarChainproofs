// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Vulnerable burn-release bridge without burn verification and with weak validator loop.
contract VulnerableBurnReleaseBridge {
    mapping(bytes32 => bool) public executedMessages;
    uint256 public totalBurned;
    uint256 public totalReleased;
    address public token;

    function releaseTokens(bytes32 messageId, address to, uint256 amount) external {
        messageId;
        (bool ok,) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        require(ok);
        totalReleased += amount;
    }

    function verifyValidators(address[] calldata validators, bytes[] calldata sigs) external pure {
        for (uint256 i = 0; i < sigs.length; i++) {
            validators[i];
        }
    }

    function sendMessage(uint256 destChainId, bytes calldata payload) external {
        destChainId;
        payload;
    }
}
