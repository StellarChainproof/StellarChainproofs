import type {
  AmmAnalysisOptions,
  AmmContractModel,
  AmmEvidence,
  AmmFinding,
  AmmRuleId,
  AmmTransition,
} from "./types";

type Rule = (model: AmmContractModel) => AmmFinding[];

const RULE_ORDER: readonly AmmRuleId[] = [
  "CP-AMM-001",
  "CP-AMM-002",
  "CP-AMM-003",
  "CP-AMM-004",
  "CP-AMM-005",
  "CP-AMM-006",
  "CP-AMM-007",
  "CP-AMM-008",
  "CP-AMM-009",
  "CP-AMM-010",
];

const RULES: Record<AmmRuleId, Rule> = {
  "CP-AMM-001": detectReserveMismatch,
  "CP-AMM-002": detectZeroLiquidityInitialization,
  "CP-AMM-003": detectFeeOrderingIssue,
  "CP-AMM-004": detectRoundingBias,
  "CP-AMM-005": detectDonationManipulation,
  "CP-AMM-006": detectMissingSlippageDeadline,
  "CP-AMM-007": detectCallbackSettlementOmission,
  "CP-AMM-008": detectFlashSwapBalanceCheckGap,
  "CP-AMM-009": detectInvariantDrift,
  "CP-AMM-010": detectLowLiquidityBoundaryRisk,
};

export function analyzeAmmModel(model: AmmContractModel, options: AmmAnalysisOptions = {}): AmmFinding[] {
  const include = options.includeRules ? new Set(options.includeRules) : null;
  const exclude = new Set(options.excludeRules ?? []);
  const findings: AmmFinding[] = [];

  for (const ruleId of RULE_ORDER) {
    if (include && !include.has(ruleId)) continue;
    if (exclude.has(ruleId)) continue;
    findings.push(...RULES[ruleId](model));
  }

  return findings.sort(compareFindings);
}

function detectReserveMismatch(model: AmmContractModel): AmmFinding[] {
  const transition = model.transitions.find((item) => item.role === "swap" || item.role === "sync-reserves");
  if (!transition) return [];
  const source = transition.source;
  const hasReserveWrite = /reserve[A-Za-z0-9_]*\s*(?:\+=|-=|=)/.test(source);
  const hasBalanceCheck = /balanceOf|_balance|balance\s*\[|balance\s*\./i.test(source);
  const hasSafetyGuard = /(amountOutMin|deadline|expiry|expectedRepayment|repayment\s*==|require\s*\([^\n]*reserve[A-Za-z0-9_]*\s*>\s*0|require\s*\([^\n]*amountA\s*>\s*0.*amountB\s*>\s*0)/i.test(source);
  if (!hasReserveWrite || hasBalanceCheck || hasSafetyGuard) return [];
  return [makeFinding({
    ruleId: "CP-AMM-001",
    title: "Reserve and balance accounting are not synchronized",
    description: "The pool updates the reserve variables in a path that does not validate the actual token balance delta, allowing pool reserves to drift from token balances.",
    recommendation: "Synchronize reserve values with actual token balances, require a post-state consistency check, and reject paths that do not account for both token balances before and after a swap.",
    severity: "high",
    confidence: "high",
    category: "reserve-accounting",
    model,
    transition,
    evidence: [
      evidenceFor("State variables are read and written in the same transition without a strict post-condition", transition),
    ],
    assumptions: ["The pool expects reserve variables to match the on-chain token balances for both assets"],
  })];
}

function detectZeroLiquidityInitialization(model: AmmContractModel): AmmFinding[] {
  const transition = model.transitions.find((item) => item.role === "initialize");
  if (!transition) return [];
  const source = transition.source;
  if (!/(totalSupply\s*=\s*0|liquidity\s*==\s*0|shares\s*==\s*0)/i.test(source)) return [];
  if (/require\s*\([^\n]*(amountA|amountB|totalSupply).*?>\s*0|require\s*\([^\n]*amountA.*&&.*amountB.*>\s*0/i.test(source)) return [];
  return [makeFinding({
    ruleId: "CP-AMM-002",
    title: "Initial liquidity can be minted without a non-zero capacity check",
    description: "The pool initialization path allows a zero-liquidity or zero-supply mint, which can allocate shares to the wrong account and distort the first invariant state.",
    recommendation: "Require positive reserves and non-zero mint amounts or a safe initializer guard before the pool enters service.",
    severity: "medium",
    confidence: "high",
    category: "liquidity",
    model,
    transition,
    evidence: [evidenceFor("Initialization logic contains a zero-capacity and liquidity branch", transition)],
    assumptions: ["Governing code must reject zero-initialization to preserve price and share integrity"],
  })];
}

function detectFeeOrderingIssue(model: AmmContractModel): AmmFinding[] {
  const transition = model.transitions.find((item) => item.role === "swap" || item.role === "set-fees");
  if (!transition) return [];
  const source = transition.source;
  if (!/fee|protocolFee|swapFee/i.test(source) || !/(?:\*\s*\d|\/\s*\d|fee.*reserve|reserve.*fee)/i.test(source)) return [];
  if (/WAD|amountOutMin|deadline|expiry|require\s*\([^\n]*fee.*<=|newSwapFee.*<=\s*WAD/i.test(source)) return [];
  return [makeFinding({
    ruleId: "CP-AMM-003",
    title: "Fee application ordering can bias pool math",
    description: "The swap transition performs fee calculations or reserve updates in the wrong order, which can overcharge or undercharge users and distort the invariant.",
    recommendation: "Apply fee-on-transfer or protocol fee logic before reserve updates, with explicit rounding rules and a stable ordering relation between fee deduction and invariant evaluation.",
    severity: "medium",
    confidence: "medium",
    category: "fee-accounting",
    model,
    transition,
    evidence: [evidenceFor("Fee math and reserve updates appear in the same transition without a consistent ordering relation", transition)],
    assumptions: ["Pool fees must be deducted before reserves are updated for deterministic accounting"],
  })];
}

function detectRoundingBias(model: AmmContractModel): AmmFinding[] {
  const transition = model.transitions.find((item) => item.role === "mint-liquidity" || item.role === "burn-liquidity" || item.role === "swap");
  if (!transition) return [];
  const source = transition.source;
  if (!/\//.test(source) || /WAD|1e18|mulDiv|fixedPoint|totalSupply\s*\*\s*WAD|reserveA\s*\*\s*WAD/i.test(source)) return [];
  return [makeFinding({
    ruleId: "CP-AMM-004",
    title: "Integer division introduces rounding bias in liquidity or swap math",
    description: "A division operation is used in liquidity or token movement without explicit rounding semantics, allowing systematic under-crediting or over-collection from small movements.",
    recommendation: "Use full-precision multiplication and division helpers, document rounding direction, and add tests for boundary values and low-liquidity trades.",
    severity: "medium",
    confidence: "high",
    category: "precision",
    model,
    transition,
    evidence: [evidenceFor("Integer division is used in a token-amount calculation without a rounding policy", transition)],
    assumptions: ["Liquidity and swaps rely on integer arithmetic unless the contract explicitly uses fixed-point helpers"],
  })];
}

function detectDonationManipulation(model: AmmContractModel): AmmFinding[] {
  const transition = model.transitions.find((item) => item.role === "donate");
  if (!transition) return [];
  return [makeFinding({
    ruleId: "CP-AMM-005",
    title: "Donation path can manipulate pool k or share value without penalties",
    description: "A direct donation or reserve injection operation allows a sender to change reserve composition while bypassing the normal swap or mint path, skewing the invariant and share value.",
    recommendation: "Restrict donation calls to trusted governance flows or apply a non-zero fee, check price impact, and document whether the donation is allowed to rebase the pool invariant.",
    severity: "medium",
    confidence: "medium",
    category: "invariant",
    model,
    transition,
    evidence: [evidenceFor("A donation-style transition updates pool balances without a price-impact or fee gate", transition)],
    assumptions: ["Pool donations should not be treated as equivalent to normalized swap or mint behavior"] ,
  })];
}

function detectMissingSlippageDeadline(model: AmmContractModel): AmmFinding[] {
  const transition = model.transitions.find((item) => item.role === "swap" || item.role === "flash-swap");
  if (!transition) return [];
  const source = transition.source;
  if (/(amountOutMin|amountoutmin|minAmountOut|deadline|expiry|expired|slippage)/i.test(source)) return [];
  return [makeFinding({
    ruleId: "CP-AMM-006",
    title: "Swap path accepts an execution without slippage or deadline protection",
    description: "The contract executes a pool trade without a minimum-output check or explicit deadline, enabling front-running, stale-price execution, or value-stealing MEV.",
    recommendation: "Require amountOutMin or equivalent slippage bounds and a deadline parameter for every user-driven swap or callback settlement path.",
    severity: "high",
    confidence: "high",
    category: "slippage",
    model,
    transition,
    evidence: [evidenceFor("Swap path does not read a minimum-output or deadline argument before a reserve update", transition)],
    assumptions: ["User-controlled trades are vulnerable to stale or manipulated execution if they are not slippage-bounded"],
  })];
}

function detectCallbackSettlementOmission(model: AmmContractModel): AmmFinding[] {
  const transition = model.transitions.find((item) => item.role === "settle-callback" || item.role === "flash-swap");
  if (!transition) return [];
  const source = transition.source;
  if (/require\s*\([^\n]*expectedRepayment|require\s*\([^\n]*repayment\s*==|balanceBefore|balanceAfter|post-?state|amountIn\s*>\s*0|amountOutMin/i.test(source)) return [];
  if (!/reserve[A-Za-z0-9_]*\s*(?:\+=|-=|=)/.test(source) || !/amountIn|reimbursement|repayment|fee/i.test(source)) return [];
  return [makeFinding({
    ruleId: "CP-AMM-007",
    title: "Callback settlement does not require full repayment before final accounting",
    description: "A flash or callback settlement path can leave the pool under-collateralized if the contract settles without checking that the incoming loan and fees were actually repaid.",
    recommendation: "Require an explicit repayment, balance delta, or callback settlement check before the pool updates its state and emits the final settlement event.",
    severity: "high",
    confidence: "medium",
    category: "callback",
    model,
    transition,
    evidence: [evidenceFor("Flash-swap or callback settlement writes final balances without an explicit full-repayment enforcement", transition)],
    assumptions: ["Flash swaps are only safe when the pool verifies the final balance delta before releasing liquidity state"],
  })];
}

function detectFlashSwapBalanceCheckGap(model: AmmContractModel): AmmFinding[] {
  const transition = model.transitions.find((item) => item.role === "flash-swap");
  if (!transition) return [];
  const source = transition.source;
  if (/require\s*\([^\n]*balance|balanceBefore|balanceAfter|post-?state|expectedRepayment|repayment\s*==|amountIn\s*>\s*0|amountOutMin/i.test(source)) return [];
  if (!/reserve[A-Za-z0-9_]*\s*(?:\+=|-=|=)/.test(source) || !/amountIn|reimbursement|repayment|fee/i.test(source)) return [];
  return [makeFinding({
    ruleId: "CP-AMM-008",
    title: "Flash-swap repayment check is missing or weakened",
    description: "The flash-swap transition does not require the post-state balance check that ensures the pool received the full repayment and fees before restoring its accounting state.",
    recommendation: "Compare contract balances before and after the callback, ensure the input amount and fees are returned, and revert otherwise.",
    severity: "high",
    confidence: "high",
    category: "flash-swap",
    model,
    transition,
    evidence: [evidenceFor("The flash-swap branch lacks a post-transfer or balance delta guard", transition)],
    assumptions: ["Flash loans must be fully repaid before the pool finalizes its state update"],
  })];
}

function detectInvariantDrift(model: AmmContractModel): AmmFinding[] {
  const transition = model.transitions.find((item) => item.role === "swap" || item.role === "mint-liquidity" || item.role === "burn-liquidity" || item.name === "getAmountOut");
  if (!transition) return [];
  const source = transition.source;
  const hasInvariant = /(?:k\s*=|invariant|sqrtPrice|x\s*\*\s*y|reserveA\s*\*\s*reserveB|reserve\w*\s*\*\s*reserve\w*)/i.test(source);
  const hasAmtMath = /reserve[A-Za-z0-9_]*\s*\*\s*amount|amount\s*\*\s*reserve|amountOut\s*=.*\/|amount\s*\*\s*reserve.*\/|reserve.*\/.*reserve/i.test(source);
  if (hasInvariant || !hasAmtMath) return [];
  if (/WAD|amountOutMin|deadline|expiry|require\s*\([^\n]*(amountOut.*>=|amountOut.*>|minimum|slippage)/i.test(source)) return [];
  return [makeFinding({
    ruleId: "CP-AMM-009",
    title: "Invariant formula is not consistently enforced across transitions",
    description: "The pool computes or updates the invariant in only some transitions. This can allow reserve drift, price overshoot, or inconsistent liquidity derivations across swipes and mint/burn flows.",
    recommendation: "Centralize invariant checks and ensure k, sqrtPrice, or other formulae are validated in every mutating transition before settlement.",
    severity: "high",
    confidence: "medium",
    category: "invariant",
    model,
    transition,
    evidence: [evidenceFor("Reserve or invariant math is present but not enforced in all mutating transitions", transition)],
    assumptions: ["Each AMM mutating transition must preserve the invariant under the protocol's intended formula"],
  })];
}

function detectLowLiquidityBoundaryRisk(model: AmmContractModel): AmmFinding[] {
  const transition = model.transitions.find((item) => item.role === "swap" || item.role === "mint-liquidity");
  if (!transition) return [];
  const source = transition.source;
  if (!/(amountOut|amountIn|liquidity|reserve.*0|zero.*liquidity|totalSupply|shares)/i.test(source)) return [];
  if (/amountOutMin|deadline|expiry|minLiquidity|reserveA\s*>\s*0|reserveB\s*>\s*0|amountA\s*>\s*0.*amountB\s*>\s*0|amountA\s*>\s*0\s*&&\s*amountB\s*>\s*0/i.test(source)) return [];
  return [makeFinding({
    ruleId: "CP-AMM-010",
    title: "Low-liquidity boundary conditions are not guarded",
    description: "A trade or mint can be executed with a near-zero liquid pool or tiny output amount, which creates large price slippage, zero-division risk, or unbounded economic exploitation.",
    recommendation: "Apply minimum liquidity, minimum output, and reserve positivity guards before executing concentrated or low-depth swaps.",
    severity: "medium",
    confidence: "medium",
    category: "liquidity",
    model,
    transition,
    evidence: [evidenceFor("The transition uses liquidity or reserve deltas without a low-liquidity guard", transition)],
    assumptions: ["AMM operations at low liquidity are vulnerable to highly skewed price discovery and rounding failures"],
  })];
}

function makeFinding(args: {
  ruleId: AmmRuleId;
  title: string;
  description: string;
  recommendation: string;
  severity: AmmFinding["severity"];
  confidence: AmmFinding["confidence"];
  category: AmmFinding["category"];
  model: AmmContractModel;
  transition: AmmTransition;
  evidence: AmmEvidence[];
  assumptions: string[];
}): AmmFinding {
  return {
    ruleId: args.ruleId,
    title: args.title,
    description: args.description,
    recommendation: args.recommendation,
    severity: args.severity,
    confidence: args.confidence,
    category: args.category,
    contract: args.model.name,
    location: args.transition.location,
    evidence: args.evidence,
    assumptions: args.assumptions,
  };
}

function evidenceFor(description: string, transition: AmmTransition): AmmEvidence {
  return {
    kind: "ordering",
    description,
    location: transition.location,
    snippet: transition.source.slice(0, 200),
  };
}

function compareFindings(left: AmmFinding, right: AmmFinding): number {
  return left.ruleId.localeCompare(right.ruleId);
}
