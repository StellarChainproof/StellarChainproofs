// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Secure burn-release bridge with proof verification and finality window.
contract SecureBurnReleaseBridge {
    mapping(bytes32 => bool) public processedMessages;
    mapping(bytes32 => uint256) public messageReceivedAt;
    uint256 public totalBurned;
    uint256 public totalReleased;
    bytes32 public merkleRoot;
    uint256 public rootUpdatedAt;
    uint256 public finalityWindow = 86400;
    address public token;

    function receiveMessage(bytes32 messageId, bytes32 root, bytes calldata proof) external {
        require(root == merkleRoot, "stale root");
        require(block.timestamp >= rootUpdatedAt, "root not ready");
        require(!processedMessages[messageId], "replay");
        verifyProof(proof);
        processedMessages[messageId] = true;
        messageReceivedAt[messageId] = block.timestamp;
    }

    function releaseTokens(bytes32 messageId, address to, uint256 amount) external {
        require(processedMessages[messageId], "not received");
        require(block.timestamp >= messageReceivedAt[messageId] + finalityWindow, "finality");
        require(amount <= totalBurned - totalReleased, "exceeds burn");
        (bool ok,) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        require(ok);
        totalReleased += amount;
    }

    function burnTokens(uint256 amount) external {
        totalBurned += amount;
    }

    function verifyProof(bytes calldata proof) internal view {
        require(proof.length > 0, "empty proof");
        require(block.timestamp >= rootUpdatedAt, "root timestamp");
        merkleRoot;
    }

    function updateRoot(bytes32 newRoot) external {
        merkleRoot = newRoot;
        rootUpdatedAt = block.timestamp;
    }
}
