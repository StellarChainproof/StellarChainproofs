# Requirements Document

## Introduction

This document specifies the requirements for a production-grade lending protocol collateral, interest, and liquidation invariant analysis module for ChainProof. Lending protocols are high-value DeFi targets that fail through share accounting errors, stale interest indexes, rounding direction bugs, liquidation incentive misconfigurations, health-factor calculation mistakes, and state transition ordering errors spread across multiple contracts. This analysis module will detect these vulnerabilities deterministically through AST-based invariant checking without requiring live network interaction or symbolic execution.

## Glossary

- **Lending_Protocol_Analyzer**: The deterministic static analysis engine that checks lending protocol invariants
- **Interest_Index**: The accumulated interest multiplier used to convert between normalized debt/supply amounts and current amounts
- **Health_Factor**: The ratio of collateral value to borrowed value adjusted by collateral factors that determines liquidation eligibility
- **Collateral_Factor**: The maximum borrow capacity percentage for a given collateral asset (e.g., 80% means $100 collateral enables $80 borrowing)
- **Liquidation_Bonus**: The percentage incentive a liquidator receives above the repaid debt amount
- **Close_Factor**: The maximum percentage of a position that can be liquidated in a single transaction
- **Share_Token**: A representation of protocol deposits using shares that appreciate via exchange rate changes
- **Normalized_Amount**: The debt or supply amount divided by the current interest index, representing the "principal" before interest accrual
- **Isolation_Mode**: A lending mode where certain collateral assets can only be used to borrow specific approved assets
- **Bad_Debt**: Debt positions with insufficient collateral to cover liquidation, resulting in protocol insolvency
- **Accrual_Function**: A function that updates interest indexes based on time elapsed and utilization rates
- **Rebasing_Token**: A token whose balance automatically changes over time (e.g., stETH, aToken)
- **Fixed_Rate_Debt**: Debt with a predetermined interest rate that doesn't change based on utilization
- **Variable_Rate_Debt**: Debt with an interest rate that adjusts based on pool utilization
- **Liquidation_Threshold**: The collateral factor percentage at which a position becomes eligible for liquidation (typically lower than collateral factor)
- **Reserve_Factor**: The percentage of interest that accrues to protocol reserves rather than suppliers
- **Exchange_Rate**: The ratio between share tokens and underlying asset amounts
- **Oracle_Price**: The price data from an external oracle used for collateral and debt valuation
- **Flash_Loan**: A loan that must be repaid within the same transaction, often used in liquidations
- **Entry_Function**: A public or external function that users or other contracts can call directly
- **State_Transition**: A sequence of storage variable modifications within a transaction
- **Cross_Contract_Call**: An external call from the lending protocol to another contract that could trigger reentrancy
- **Rounding_Direction**: Whether arithmetic operations round up or down, critical for preventing value extraction
- **Precision_Loss**: Loss of value due to integer division and fixed-point arithmetic
- **Self_Liquidation**: An exploit where a user liquidates their own position to extract liquidation bonuses
- **Bonus_Inversion**: A configuration error where liquidation bonuses create perverse incentives
- **Stale_Index**: An interest index that hasn't been updated recently, causing incorrect debt or supply calculations
- **Under_Collateralized_Borrow**: A borrow operation that succeeds despite insufficient collateral
- **Debt_Share_Inconsistency**: Mismatch between debt shares and actual debt amounts due to incorrect index usage
- **Transfer_Before_Update**: Dangerous pattern of transferring tokens before updating internal accounting state
- **Oracle_Before_Update**: Dangerous pattern of reading oracle prices before updating interest accrual state
- **Partial_Liquidation**: Liquidation of only a portion of a position rather than the entire position
- **Safe_Fixture**: A test contract that correctly implements lending invariants
- **Vulnerable_Fixture**: A test contract that intentionally violates lending invariants for testing
- **False_Positive_Control**: A test case designed to ensure the analyzer doesn't incorrectly flag safe code
- **Boundary_Condition**: Edge cases like zero amounts, maximum uint256 values, or single-wei precision
- **Performance_Safeguard**: Limits on analysis depth, time, or complexity to prevent hanging on adversarial input
- **Protocol_Terminology**: Configurable naming conventions (e.g., "supply" vs "deposit", "borrow" vs "loan")
- **Function_Annotation**: User-provided hints about function roles when naming conventions are ambiguous
- **API_Surface**: The public TypeScript API exported from @chainproof/core for programmatic usage
- **CLI_Command**: The command-line interface entry point for running lending protocol analysis
- **Versioned_Output**: Analysis results with a schema version identifier for stable parsing
- **Source_Location**: File path and line number information for each finding
- **Evidence_Path**: The concrete call chain or state access pattern that constitutes a vulnerability
- **Assumption**: An explicit condition the analysis relies on (e.g., "oracle is trusted", "token is not rebasing")
- **Confidence_Level**: High, medium, or low confidence rating for each finding based on signal strength
- **Config_Validation**: Schema checking and error reporting for user-provided configuration files
- **Config_Migration**: Automatic upgrade of configuration files from older schema versions
- **Corruption_Handling**: Graceful error recovery when configuration files are malformed or truncated
- **Error_Context**: Actionable information in error messages without leaking sensitive data like private keys
- **Security_Assumption**: Documented threat model boundaries (e.g., "assumes oracle is not compromised")
- **Compatibility_Note**: Version requirements and integration constraints with other ChainProof modules
- **Troubleshooting_Guide**: Documentation for diagnosing and resolving common analysis issues
- **Monorepo_Package**: One of the NPM packages in the ChainProof workspace (core, cli, server, etc.)
- **AI_Economic_Analysis**: The complementary LLM-based economic exploit detection in issue #60
- **Deterministic_Analysis**: Analysis that produces identical output for identical input, required for CI reproducibility

## Requirements

### Requirement 1: Core Detection Capabilities

**User Story:** As a smart contract developer, I want the analyzer to detect critical lending protocol vulnerabilities, so that I can prevent exploits before deployment.

#### Acceptance Criteria

1. WHEN a contract implements deposit or supply functions, THE Lending_Protocol_Analyzer SHALL detect under-collateralized borrows where Health_Factor calculations are bypassed or incorrect
2. WHEN Interest_Index updates occur, THE Lending_Protocol_Analyzer SHALL detect stale accrual where indexes are not updated before state transitions
3. WHEN share-to-amount conversions are performed, THE Lending_Protocol_Analyzer SHALL detect incorrect Rounding_Direction that enables value extraction
4. WHEN liquidation functions are analyzed, THE Lending_Protocol_Analyzer SHALL detect Self_Liquidation vulnerabilities where users can liquidate their own positions for profit
5. WHEN Liquidation_Bonus and Liquidation_Threshold parameters are evaluated, THE Lending_Protocol_Analyzer SHALL detect Bonus_Inversion where bonuses exceed collateral factors
6. WHEN Close_Factor logic is analyzed, THE Lending_Protocol_Analyzer SHALL detect close-factor errors allowing over-liquidation or under-liquidation
7. WHEN debt shares and normalized amounts are tracked, THE Lending_Protocol_Analyzer SHALL detect Debt_Share_Inconsistency between shares and actual debt
8. WHEN state transitions involve external calls, THE Lending_Protocol_Analyzer SHALL detect dangerous ordering of Transfer_Before_Update, Oracle_Before_Update, and accrual timing
9. WHEN Rebasing_Token collateral is detected, THE Lending_Protocol_Analyzer SHALL flag Precision_Loss and share accounting risks specific to rebasing assets
10. WHEN Bad_Debt scenarios are possible, THE Lending_Protocol_Analyzer SHALL detect insufficient safeguards against protocol insolvency
11. WHEN Isolation_Mode restrictions are implemented, THE Lending_Protocol_Analyzer SHALL detect bypass vulnerabilities in isolation mode enforcement
12. WHEN both Variable_Rate_Debt and Fixed_Rate_Debt are present, THE Lending_Protocol_Analyzer SHALL detect inconsistent interest rate application across debt types

### Requirement 2: Modeling and State Tracking

**User Story:** As a security auditor, I want the analyzer to accurately model complex lending protocol state, so that I can trust the analysis results for production audits.

#### Acceptance Criteria

1. THE Lending_Protocol_Analyzer SHALL model deposits, borrows, repayments, withdrawals, and liquidations as State_Transition sequences
2. THE Lending_Protocol_Analyzer SHALL track Collateral_Factor, Liquidation_Threshold, Liquidation_Bonus, Close_Factor, and Reserve_Factor configurations per asset
3. THE Lending_Protocol_Analyzer SHALL model Interest_Index accumulation for both supply and borrow sides
4. THE Lending_Protocol_Analyzer SHALL track Normalized_Amount to current amount conversions with Rounding_Direction
5. THE Lending_Protocol_Analyzer SHALL model Exchange_Rate calculations for Share_Token implementations
6. THE Lending_Protocol_Analyzer SHALL track Oracle_Price reads and their timing relative to State_Transition updates
7. THE Lending_Protocol_Analyzer SHALL model Cross_Contract_Call edges and reentrancy surfaces in liquidation flows
8. THE Lending_Protocol_Analyzer SHALL track decimal precision for multi-asset protocols with different token decimals
9. THE Lending_Protocol_Analyzer SHALL model Partial_Liquidation logic and health factor updates after liquidation
10. THE Lending_Protocol_Analyzer SHALL track reserve accumulation and distinguish between user-owned and protocol-owned funds

### Requirement 3: Configuration and Terminology

**User Story:** As a DeFi protocol developer, I want to configure the analyzer for my protocol's specific terminology and architecture, so that analysis is accurate without requiring code changes.

#### Acceptance Criteria

1. THE Lending_Protocol_Analyzer SHALL accept configurable Protocol_Terminology mappings (e.g., "mint" → "deposit", "redeem" → "withdraw")
2. WHEN function names don't match standard patterns, THE Lending_Protocol_Analyzer SHALL support Function_Annotation to specify roles explicitly
3. THE Lending_Protocol_Analyzer SHALL support versioned configuration with Config_Validation to reject invalid schemas
4. WHEN configuration schema versions change, THE Lending_Protocol_Analyzer SHALL perform Config_Migration automatically with user notification
5. IF a configuration file is malformed or truncated, THEN THE Lending_Protocol_Analyzer SHALL apply Corruption_Handling and report actionable errors
6. THE Lending_Protocol_Analyzer SHALL validate that configured collateral factors and liquidation thresholds satisfy safety constraints
7. THE Lending_Protocol_Analyzer SHALL support per-asset configuration for protocols with heterogeneous collateral types

### Requirement 4: Integration and API Surface

**User Story:** As a ChainProof user, I want the lending protocol analyzer to integrate seamlessly with existing ChainProof workflows, so that I can use it through CLI, API, and CI/CD pipelines.

#### Acceptance Criteria

1. THE Lending_Protocol_Analyzer SHALL expose a public TypeScript API_Surface through @chainproof/core exports
2. THE Lending_Protocol_Analyzer SHALL provide CLI_Command entry points following the pattern of `chainproof staking` and `chainproof governance`
3. THE Lending_Protocol_Analyzer SHALL integrate with the existing ChainProof scan pipeline without duplicating functionality
4. THE Lending_Protocol_Analyzer SHALL complement (not duplicate) the AI_Economic_Analysis module referenced in issue #60
5. THE Lending_Protocol_Analyzer SHALL share AST parsing, import graph resolution, and MergedContractView infrastructure with existing modules
6. THE Lending_Protocol_Analyzer SHALL reuse the existing Finding, Evidence_Path, Assumption, and Confidence_Level data structures
7. THE Lending_Protocol_Analyzer SHALL integrate with existing report generators for JSON, Markdown, and table output formats

### Requirement 5: Determinism and Reproducibility

**User Story:** As a CI/CD engineer, I want the analyzer to produce identical results for identical inputs, so that my build gates are stable and reproducible.

#### Acceptance Criteria

1. THE Lending_Protocol_Analyzer SHALL implement Deterministic_Analysis producing byte-identical output for identical input
2. THE Lending_Protocol_Analyzer SHALL sort findings by file path, line number, and rule ID for stable ordering
3. THE Lending_Protocol_Analyzer SHALL use Versioned_Output with schema version identifiers in all reports
4. THE Lending_Protocol_Analyzer SHALL generate precise Source_Location information (file path and line number) for every finding
5. THE Lending_Protocol_Analyzer SHALL never require network access to external services for core analysis functionality
6. THE Lending_Protocol_Analyzer SHALL produce Evidence_Path arrays showing concrete call chains for each vulnerability
7. THE Lending_Protocol_Analyzer SHALL document all Assumption values that findings depend on for reviewer evaluation

### Requirement 6: Error Handling and Robustness

**User Story:** As a developer debugging analysis failures, I want clear error messages with actionable context, so that I can resolve issues quickly.

#### Acceptance Criteria

1. WHEN analysis errors occur, THE Lending_Protocol_Analyzer SHALL provide Error_Context with actionable information
2. THE Lending_Protocol_Analyzer SHALL never leak sensitive information like private keys, API tokens, or internal file paths in error messages
3. WHEN Performance_Safeguard limits are exceeded, THE Lending_Protocol_Analyzer SHALL emit informational findings rather than hanging or crashing
4. THE Lending_Protocol_Analyzer SHALL gracefully handle malformed Solidity ASTs with parse error reporting
5. THE Lending_Protocol_Analyzer SHALL validate configuration files with clear schema violation messages
6. THE Lending_Protocol_Analyzer SHALL detect and report circular import dependencies without infinite loops
7. THE Lending_Protocol_Analyzer SHALL handle contracts that exceed analysis complexity budgets with partial results and warnings

### Requirement 7: Testing and Validation

**User Story:** As a ChainProof maintainer, I want comprehensive test coverage for the lending analyzer, so that I can confidently release and maintain it.

#### Acceptance Criteria

1. THE Lending_Protocol_Analyzer SHALL include Safe_Fixture contracts that correctly implement lending invariants and produce zero findings
2. THE Lending_Protocol_Analyzer SHALL include Vulnerable_Fixture contracts that intentionally violate each rule and produce expected findings
3. THE Lending_Protocol_Analyzer SHALL include False_Positive_Control tests ensuring safe patterns are not incorrectly flagged
4. THE Lending_Protocol_Analyzer SHALL test Boundary_Condition cases including zero amounts, maximum uint256 values, and single-wei precision
5. THE Lending_Protocol_Analyzer SHALL include performance tests validating Performance_Safeguard limits prevent unbounded execution time
6. THE Lending_Protocol_Analyzer SHALL test Config_Migration for all supported schema versions
7. THE Lending_Protocol_Analyzer SHALL test both Variable_Rate_Debt and Fixed_Rate_Debt implementations
8. THE Lending_Protocol_Analyzer SHALL test Rebasing_Token handling with realistic rebasing scenarios
9. THE Lending_Protocol_Analyzer SHALL test Isolation_Mode bypass detection
10. THE Lending_Protocol_Analyzer SHALL test Bad_Debt detection with underwater positions

### Requirement 8: Documentation and Usability

**User Story:** As a first-time user of the lending analyzer, I want clear documentation with examples, so that I can quickly understand how to use it effectively.

#### Acceptance Criteria

1. THE Lending_Protocol_Analyzer SHALL provide documentation of Security_Assumption values and threat model boundaries
2. THE Lending_Protocol_Analyzer SHALL document Compatibility_Note requirements including ChainProof version and Node.js version
3. THE Lending_Protocol_Analyzer SHALL provide working examples showing common lending protocol patterns
4. THE Lending_Protocol_Analyzer SHALL include a Troubleshooting_Guide for common analysis issues and false positives
5. THE Lending_Protocol_Analyzer SHALL document the relationship with AI_Economic_Analysis and when to use each approach
6. THE Lending_Protocol_Analyzer SHALL provide configuration examples for major lending protocol architectures (Compound-like, Aave-like, isolated pools)
7. THE Lending_Protocol_Analyzer SHALL document all exported API functions with TypeScript signatures and usage examples

### Requirement 9: Output Quality and Actionability

**User Story:** As a security reviewer, I want findings with sufficient context and confidence levels, so that I can prioritize and validate issues efficiently.

#### Acceptance Criteria

1. WHEN a finding is reported, THE Lending_Protocol_Analyzer SHALL include a Confidence_Level (high, medium, or low)
2. WHEN a finding is reported, THE Lending_Protocol_Analyzer SHALL include Evidence_Path showing the concrete vulnerability trace
3. WHEN a finding is reported, THE Lending_Protocol_Analyzer SHALL list all Assumption values the finding depends on
4. THE Lending_Protocol_Analyzer SHALL provide actionable recommendations for each finding type
5. THE Lending_Protocol_Analyzer SHALL distinguish between critical (immediate fix), high (fix before deploy), and medium (review recommended) severities
6. THE Lending_Protocol_Analyzer SHALL include code snippets showing the vulnerable pattern when available
7. THE Lending_Protocol_Analyzer SHALL cross-reference related findings (e.g., stale index combined with transfer ordering)

### Requirement 10: Scope and Integration Boundaries

**User Story:** As a ChainProof architect, I want clear boundaries between the lending analyzer and other modules, so that the system remains maintainable and coherent.

#### Acceptance Criteria

1. THE Lending_Protocol_Analyzer SHALL focus on lending-specific invariants and NOT duplicate generic reentrancy detection (CP-107, CP-CB-*)
2. THE Lending_Protocol_Analyzer SHALL focus on deterministic static analysis and NOT duplicate economic exploit modeling from AI_Economic_Analysis
3. THE Lending_Protocol_Analyzer SHALL integrate with but NOT replace the existing compiler analysis, DoS detection, and governance modules
4. THE Lending_Protocol_Analyzer SHALL reuse AST infrastructure and NOT implement a separate Solidity parser
5. THE Lending_Protocol_Analyzer SHALL operate within the existing Monorepo_Package structure (packages/core/src/lending/)
6. THE Lending_Protocol_Analyzer SHALL follow the established pattern from staking and governance modules for API design
7. THE Lending_Protocol_Analyzer SHALL complement callback reentrancy analysis for Flash_Loan interactions without duplicating hook detection
