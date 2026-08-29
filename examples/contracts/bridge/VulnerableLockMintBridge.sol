// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IMintable {
    function mint(address to, uint256 amount) external;
}

/// @notice Vulnerable lock-mint bridge lacking replay protection, source binding, and lock verification.
contract VulnerableLockMintBridge {
    mapping(bytes32 => bool) public processedMessages;
    uint256 public totalMinted;
    IMintable public wrappedToken;
    address public relayer;

    constructor(address token, address _relayer) {
        wrappedToken = IMintable(token);
        relayer = _relayer;
    }

    function receiveMessage(bytes32 messageId, address to, uint256 amount, bytes calldata) external {
        require(msg.sender == relayer, "untrusted");
        wrappedToken.mint(to, amount);
        totalMinted += amount;
    }

    function executeMessage(bytes32, address target, bytes calldata data) external {
        (bool ok,) = target.call(data);
        require(ok);
    }

    function updateThreshold(uint256 newThreshold) external {
        // no bounds check, instant update
        newThreshold;
    }

    function verifySignatures(address[] calldata signers, bytes[] calldata) external pure returns (bool) {
        uint256 count;
        for (uint256 i = 0; i < signers.length; i++) {
            count++;
        }
        return count >= 1;
    }
}
