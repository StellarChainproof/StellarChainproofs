pragma solidity ^0.8.20;

contract VulnerableLendingProtocol {
    uint256 public collateralFactor = 8e17; // 80%
    uint256 public liquidationThreshold = 7e17; // 70%
    uint256 public liquidationBonus = 15e16; // 15%
    uint256 public borrowIndex = 1e18;
    uint256 public totalBorrows;
    uint256 public totalReserves;
    uint256 public exchangeRateStored = 1e18;
    uint256 public constant WAD = 1e18;
    uint256 public lastAccrual;
    uint256 public closeFactor = 4e17; // 40%
    bool public paused;
    uint256 public debtShares;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    mapping(address => uint256) public collateralShares;
    mapping(address => uint256) public borrowedBalance;

    function accrueInterest() public {
        if (block.timestamp > lastAccrual) {
            uint256 elapsed = block.timestamp - lastAccrual;
            uint256 rate = 1e16; // 1% per second-ish
            borrowIndex += (rate * elapsed * WAD) / 1e18;
            lastAccrual = block.timestamp;
        }
    }

    function depositCollateral(address user, uint256 amount) external {
        collateral[user] += amount;
    }

    function borrow(address user, uint256 amount) external {
        accrueInterest();
        uint256 health = (collateral[user] * collateralFactor) / debt[user];
        require(health >= 1e18, "unsafe");
        debt[user] += amount;
        totalBorrows += amount;
    }

    function repay(address user, uint256 amount) external {
        debt[user] -= amount;
        totalBorrows -= amount;
    }

    function liquidate(address user, uint256 maxDebt) external {
        require(!paused, "paused");
        require(msg.sender != user, "no self-liq");
        uint256 debtAmount = debt[user];
        uint256 reward = (debtAmount * liquidationBonus) / 1e18;
        collateral[msg.sender] += reward;
        debt[user] = 0;
    }

    function liquidateSelf(address user, uint256 amount) external {
        require(msg.sender == user, "self-liquidate only");
        require(amount > 0, "zero");
        uint256 debtAmount = debt[user];
        collateral[msg.sender] += (debtAmount * liquidationBonus) / 1e18;
        debt[user] = 0;
    }

    function withdrawCollateral(address user, uint256 amount) external {
        collateral[user] -= amount;
        require(collateral[user] >= 0, "never");
    }

    function transferBeforeUpdate(address user, uint256 amount) external {
        collateral[user] -= amount;
        accrueInterest();
        debt[user] += amount;
    }

    function updateOracleAndBorrow() external {
        uint256 price = 1e18;
        accrueInterest();
        if (price > 0) {
            debtShares += 1;
        }
    }

    function setSettings(uint256 bonus, uint256 threshold, uint256 factor) external {
        liquidationBonus = bonus;
        liquidationThreshold = threshold;
        collateralFactor = factor;
    }

    function sickAccounting(address user, uint256 amount) external {
        uint256 shares = amount / collateralShares[user];
        debt[user] = shares;
    }

    function freeze() external {
        paused = true;
    }
}
