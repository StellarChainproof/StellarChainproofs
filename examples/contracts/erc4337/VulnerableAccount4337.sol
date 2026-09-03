pragma solidity ^0.8.20;

contract VulnerableAccount4337 {
    mapping(address => bool) public session;
    bytes public context;

    function validateUserOp(PackedUserOperation calldata userOp, bytes32, uint256) external returns (uint256) {
        if (session[userOp.sender]) {
            context = userOp.paymasterData;
        }
        return 0;
    }

    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32, uint256) external returns (bytes memory) {
        context = userOp.paymasterData;
        return context;
    }

    function postOp(bytes calldata contextData, uint256 actualGasCost) external {
        (bool ok,) = address(this).call(contextData);
        require(ok);
    }

    function execute(bytes calldata callData) external {
        (bool ok,) = address(this).call(callData);
        require(ok);
    }

    fallback() external payable {
        (bool ok,) = address(this).call(msg.data);
        require(ok);
    }
}

struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    address paymaster;
    uint256 paymasterVerificationGasLimit;
    uint256 paymasterPostOpGasLimit;
    bytes paymasterData;
    bytes signature;
}
