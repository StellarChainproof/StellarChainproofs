pragma solidity ^0.8.20;

contract VulnerableAMMProtocol {
    uint256 public reserveA;
    uint256 public reserveB;
    uint256 public totalSupply;
    uint256 public swapFee;
    uint256 public protocolFee;
    uint256 public constant WAD = 1e18;

    function initialize(uint256 amountA, uint256 amountB) external {
        reserveA = amountA;
        reserveB = amountB;
        totalSupply = 0;
    }

    function mintLiquidity(uint256 amountA, uint256 amountB) external {
        uint256 shares = amountA * amountB / totalSupply;
        totalSupply += shares;
        reserveA += amountA;
        reserveB += amountB;
    }

    function swap(address tokenIn, uint256 amountIn) external {
        uint256 fee = amountIn * swapFee / 1e18;
        uint256 amountOut = (reserveA * amountIn) / (reserveB + fee);
        reserveA += amountIn;
        reserveB -= amountOut;
    }

    function donate(uint256 amountA, uint256 amountB) external {
        reserveA += amountA;
        reserveB += amountB;
    }

    function flashSwap(uint256 amountIn, address to) external {
        reserveA += amountIn;
        reserveB -= amountIn;
        uint256 reimbursement = amountIn + (amountIn * protocolFee) / 1e18;
        require(reimbursement <= reserveA, "not fully repaid");
        reserveA -= reimbursement;
    }

    function setFees(uint256 newSwapFee, uint256 newProtocolFee) external {
        swapFee = newSwapFee;
        protocolFee = newProtocolFee;
    }

    function getAmountOut(uint256 amountIn) external view returns (uint256) {
        uint256 nominal = reserveA * amountIn;
        return nominal / reserveB;
    }
}
