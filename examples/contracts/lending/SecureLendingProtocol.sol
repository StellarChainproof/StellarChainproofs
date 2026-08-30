pragma solidity ^0.8.20;

contract SecureLendingProtocol {
    uint256 public collateralFactor = 8e17; // 80%
    uint256 public liquidationThreshold = 8e17; // 80%
    uint256 public liquidationBonus = 5e16; // 5%
    uint256 public borrowIndex = 1e18;
    uint256 public totalBorrows;
    uint256 public totalReserves;
    uint256 public exchangeRateStored = 1e18;
    uint256 public constant WAD = 1e18;
    uint256 public lastAccrual;
    uint256 public closeFactor = 5e17; // 50%
    bool public paused;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    mapping(address => uint256) public collateralShares;

    function advanceInterest() public {
        if (block.timestamp > lastAccrual) {
            uint256 elapsed = block.timestamp - lastAccrual;
            uint256 rate = 1e16;
            borrowIndex += (rate * elapsed * WAD) / 1e18;
            lastAccrual = block.timestamp;
        }
    }

    function depositCollateral(address user, uint256 amount) external {
        advanceInterest();
        collateral[user] += amount;
    }

    function takeCredit(address user, uint256 amount) external {
        advanceInterest();
        uint256 health = (collateral[user] * collateralFactor) / debt[user];
        require(health >= liquidationThreshold, "unsafe");
        debt[user] += amount;
        totalBorrows += amount;
    }

    function repayDebt(address user, uint256 amount) external {
        advanceInterest();
        debt[user] = debt[user] > amount ? debt[user] - amount : 0;
        totalBorrows = totalBorrows > amount ? totalBorrows - amount : 0;
    }

    function closePosition(address user, uint256 maxDebt) external {
        require(!paused, "paused");
        require(msg.sender != user, "no self-liq");
        uint256 debtAmount = debt[user];
        require(debtAmount <= maxDebt, "debt-too-high");
        uint256 reward = (debtAmount * liquidationBonus) / 1e18;
        require(reward <= collateral[msg.sender], "reward-too-high");
        collateral[msg.sender] -= reward;
        debt[user] = 0;
    }

    function withdrawCollateral(address user, uint256 amount) external {
        require(collateral[user] >= amount, "insufficient");
        advanceInterest();
        collateral[user] -= amount;
    }

    function balanceShift(address user, uint256 amount) external {
        advanceInterest();
        collateral[user] -= amount;
        debt[user] += amount;
    }

    function refreshOracleState() external {
        advanceInterest();
        uint256 price = 1e18;
        if (price > 0) {
            totalBorrows += 1;
        }
    }

    function updateParameters(uint256 bonus, uint256 threshold, uint256 factor) external {
        require(bonus <= factor, "bonus-too-high");
        liquidationBonus = bonus;
        liquidationThreshold = threshold;
        collateralFactor = factor;
    }
}
