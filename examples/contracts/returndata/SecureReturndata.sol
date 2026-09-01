// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

library SafeERC20Mock {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        require(token.transfer(to, amount), "transfer failed");
    }
}

library AddressMock {
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory result) = target.call(data);
        require(success, "call failed");
        return result;
    }

    function sendValue(address payable to, uint256 amount) internal {
        (bool success,) = to.call{value: amount}("");
        require(success, "send failed");
    }
}

/// @notice Secure contract with checked returns and SafeERC20-style wrappers.
contract SecureReturndata {
    using SafeERC20Mock for IERC20;
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function pay(address to, uint256 amount) external {
        token.safeTransfer(to, amount);
    }

    function execute(address target, bytes calldata data) external {
        AddressMock.functionCall(target, data);
    }

    function sendEth(address payable to, uint256 amount) external {
        AddressMock.sendValue(to, amount);
    }

    function batchPay(address[] calldata recipients, uint256[] calldata amounts) external {
        require(recipients.length == amounts.length, "length");
        for (uint256 i = 0; i < recipients.length; i++) {
            token.safeTransfer(recipients[i], amounts[i]);
        }
    }

    /// @dev optional notification; failure is intentionally ignored
    function tryNotifyOptional(address to) external {
        try token.transfer(to, 1) returns (bool success) {
            success;
        } catch {}
    }
}
