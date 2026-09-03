pragma solidity ^0.8.20;

contract SecureAccount4337 {
    address public immutable entryPoint;
    mapping(uint192 => uint256) private nonceSequence;
    mapping(address => bool) private session;
    mapping(address => uint256) private sponsorshipBudget;

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "entry point");
        _;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256) external onlyEntryPoint returns (uint256) {
        require(userOpHash == keccak256(abi.encode(address(this), block.chainid, entryPoint, userOp.sender, userOp.nonce, userOp.callData)), "hash");
        uint192 key = uint192(userOp.nonce >> 64);
        require(userOp.nonce == (key << 64) | nonceSequence[key], "nonce");
        nonceSequence[key]++;
        return 0;
    }

    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost) external onlyEntryPoint returns (bytes memory) {
        require(userOpHash != bytes32(0), "hash");
        require(maxCost <= sponsorshipBudget[userOp.sender], "budget");
        require(userOp.paymasterData.length >= 32, "context");
        return userOp.paymasterData;
    }

    function postOp(bytes calldata contextData, uint256 actualGasCost) external onlyEntryPoint {
        require(contextData.length >= 32, "context");
        require(actualGasCost <= sponsorshipBudget[address(this)], "cost");
        sponsorshipBudget[address(this)] -= actualGasCost;
    }

    function initialize(address expectedSession) external {
        require(!session[expectedSession], "initialized");
        session[expectedSession] = true;
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
