// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Vulnerable contract with ignored call returns and unsafe token transfers.
contract VulnerableReturndata {
    IERC20 public token;
    address public target;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function pay(address to, uint256 amount) external {
        token.transfer(to, amount);
    }

    function execute(bytes calldata data) external {
        target.call(data);
    }

    function sendEth(address payable to) external {
        to.send(1 ether);
    }

    function batchPay(address[] calldata recipients, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            token.transfer(recipients[i], amounts[i]);
        }
    }

    function decodeResult(bytes memory data) external pure returns (uint256 value) {
        value = abi.decode(data, (uint256));
    }

    function proxyCall(address impl, bytes calldata data) external {
        impl.delegatecall(data);
    }

    function tryNotify(address to) external {
        try token.transfer(to, 1) {} catch {}
    }
}
