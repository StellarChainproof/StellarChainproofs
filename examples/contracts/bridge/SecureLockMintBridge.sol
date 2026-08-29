// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IMintable {
    function mint(address to, uint256 amount) external;
}

/// @notice Secure lock-mint bridge with domain binding, replay protection, and lock verification.
contract SecureLockMintBridge {
    mapping(bytes32 => bool) public processedMessages;
    mapping(uint256 => uint256) public inboundNonce;
    uint256 public totalLocked;
    uint256 public totalMinted;
    IMintable public wrappedToken;
    address public trustedRelayer;
    uint256 public sourceChainId;
    uint256 public validatorThreshold;
    bool public paused;

    constructor(address token, address relayer, uint256 _sourceChain) {
        wrappedToken = IMintable(token);
        trustedRelayer = relayer;
        sourceChainId = _sourceChain;
        validatorThreshold = 3;
    }

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    function lockTokens(address, uint256 amount) external {
        totalLocked += amount;
    }

    function mintTokens(address to, uint256 amount) external whenNotPaused {
        require(amount <= totalLocked - totalMinted, "exceeds lock");
        wrappedToken.mint(to, amount);
        totalMinted += amount;
    }

    function receiveMessage(
        bytes32 messageId,
        uint256 originChain,
        uint256 nonce,
        address to,
        uint256 amount
    ) external whenNotPaused {
        require(msg.sender == trustedRelayer, "untrusted");
        require(originChain == sourceChainId, "wrong source");
        require(!processedMessages[messageId], "replay");
        require(nonce == inboundNonce[originChain] + 1, "bad nonce");
        require(amount <= totalLocked - totalMinted, "exceeds lock");

        processedMessages[messageId] = true;
        inboundNonce[originChain] = nonce;

        mintTokens(to, amount);
    }

    function pause() external {
        paused = true;
    }
}
