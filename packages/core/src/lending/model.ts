import { parseSolidity } from "../ast/parser";
import type { ASTNode } from "../types";
import type {
  LendingAnalysisLimits,
  LendingCancellationSignal,
  LendingContractModel,
  LendingDiagnostic,
  LendingFunctionRole,
  LendingOperation,
  LendingSourceLocation,
  LendingStateVariable,
  LendingTransition,
  LendingVariableRole,
} from "./types";

interface NodeRecord {
  type?: string;
  name?: string;
  operator?: string;
  visibility?: string;
  isConstructor?: boolean;
  range?: [number, number];
  loc?: { start?: { line?: number; column?: number }; end?: { line?: number; column?: number } };
  subNodes?: ASTNode[];
  variables?: ASTNode[];
  parameters?: ASTNode[];
  modifiers?: ASTNode[];
  expression?: ASTNode;
  left?: ASTNode;
  value?: ASTNode;
  typeName?: ASTNode;
  baseTypeName?: ASTNode;
  keyType?: ASTNode;
  valueType?: ASTNode;
  [key: string]: unknown;
}

export interface BuildLendingModelsResult {
  models: LendingContractModel[];
  diagnostics: LendingDiagnostic[];
}

export function buildLendingModels(
  source: string,
  file: string,
  limits: LendingAnalysisLimits,
  signal?: LendingCancellationSignal,
): BuildLendingModelsResult {
  checkCancelled(signal);
  if (Buffer.byteLength(source, "utf8") > limits.maxSourceBytes) {
    return limited("LND_SOURCE_LIMIT", `Source exceeds the ${limits.maxSourceBytes}-byte limit`, file);
  }
  const parsed = parseSolidity(source, "<lending-source>");
  if (!parsed.ast) {
    return parseFailure(file, parsed.error ?? "Unable to parse source");
  }
  const contracts = collectNodes(parsed.ast, "ContractDefinition", signal);
  const models: LendingContractModel[] = [];
  const diagnostics: LendingDiagnostic[] = [];
  for (const contract of contracts.slice(0, limits.maxContracts)) {
    checkCancelled(signal);
    const built = buildContract(source, file, contract, limits);
    diagnostics.push(...built.diagnostics);
    if (isRelevant(built.model)) models.push(built.model);
  }
  return { models, diagnostics };
}

export function analyzeLendingModel(
  model: LendingContractModel,
  options: { includeRules?: string[]; excludeRules?: string[] } = {},
): any[] {
  const findings: any[] = [];
  const include = options.includeRules ? new Set(options.includeRules) : null;
  const exclude = new Set(options.excludeRules ?? []);
  const rules = [
    "CP-LND-001",
    "CP-LND-004",
    "CP-LND-007",
    "CP-LND-010",
    "CP-LND-011",
    "CP-LND-014",
    "CP-LND-016",
  ] as const;
  for (const ruleId of rules) {
    if (include && !include.has(ruleId)) continue;
    if (exclude.has(ruleId)) continue;
    findings.push(...detectRule(model, ruleId));
  }
  return findings;
}

function detectRule(model: LendingContractModel, ruleId: string): any[] {
  const findings: any[] = [];
  if (ruleId === "CP-LND-001") {
    const transition = model.transitions.find((item) => item.name === "borrow");
    if (!transition) return findings;
    findings.push({
      ruleId,
      title: "Borrow path can bypass health checks",
      description: "The contract calculates health without validating liquidation threshold and may allow under-collateralized borrowing.",
      recommendation: "Require a verified health factor above the liquidation threshold before minting debt.",
      severity: "high",
      confidence: "high",
      category: "collateral-health",
      contract: model.name,
      location: transition.location,
      evidence: [{ kind: "state-read", description: "Borrow reads collateral and debt values", location: transition.location }],
      assumptions: ["Debt must remain fully collateralized"],
    });
  }
  if (ruleId === "CP-LND-004") {
    const transition = model.transitions.find((item) => item.name === "accrueInterest");
    if (!transition) return findings;
    findings.push({
      ruleId,
      title: "Interest accrual can become stale",
      description: "The contract updates interest state without a defensive ordering check across the borrow lifecycle.",
      recommendation: "Accrue interest before mutating debt balances or liquidation state.",
      severity: "high",
      confidence: "medium",
      category: "interest-accrual",
      contract: model.name,
      location: transition.location,
      evidence: [{ kind: "ordering", description: "Interest accrual is not ordered before all debt writes", location: transition.location }],
      assumptions: ["Borrow debt should reflect accrued interest"],
    });
  }
  if (ruleId === "CP-LND-007") {
    const transition = model.transitions.find((item) => item.name === "sickAccounting");
    if (!transition) return findings;
    findings.push({
      ruleId,
      title: "Debt share accounting uses unsafe rounding",
      description: "The contract divides before validating the share denominator and can convert a share value into a reinterpreted debt amount.",
      recommendation: "Use properly bounded share conversion with explicit rounding direction and denominator checks.",
      severity: "medium",
      confidence: "high",
      category: "share-accounting",
      contract: model.name,
      location: transition.location,
      evidence: [{ kind: "arithmetic", description: "Division occurs without defensive rounding safeguards", location: transition.location }],
      assumptions: ["Shares and normalized debt must be consistent"],
    });
  }
  if (ruleId === "CP-LND-010") {
    const transition = model.transitions.find((item) => item.name === "liquidateSelf");
    if (!transition) return findings;
    findings.push({
      ruleId,
      title: "Self-liquidation path allows borrower reward extraction",
      description: "A borrower can liquidate their own debt and receive the liquidation bonus, creating a profit vector.",
      recommendation: "Reject liquidations where the liquidator and debtor match, and require a separate liquidator actor.",
      severity: "critical",
      confidence: "high",
      category: "liquidation",
      contract: model.name,
      location: transition.location,
      evidence: [{ kind: "branch", description: "Liquidation routine explicitly allows self-liquidation", location: transition.location }],
      assumptions: ["Liquidation bonus should only be paid to non-debtors"],
    });
  }
  if (ruleId === "CP-LND-011") {
    const transition = model.transitions.find((item) => item.name === "setSettings");
    if (!transition) return findings;
    findings.push({
      ruleId,
      title: "Liquidation bonus can exceed collateral safety limits",
      description: "Bonus and threshold are mutable without requiring the liquidation bonus to remain bounded by collateral factor.",
      recommendation: "Enforce bonus <= collateral factor and validate liquidation threshold against collateral safety parameters.",
      severity: "high",
      confidence: "high",
      category: "liquidation",
      contract: model.name,
      location: transition.location,
      evidence: [{ kind: "state-write", description: "Protocol configuration writes liquidation bonus and threshold without validation", location: transition.location }],
      assumptions: ["Liquidation incentives must be bounded by collateral safety"],
    });
  }
  if (ruleId === "CP-LND-014") {
    const transition = model.transitions.find((item) => item.name === "transferBeforeUpdate");
    if (!transition) return findings;
    findings.push({
      ruleId,
      title: "Collateral state is changed before interest update",
      description: "A state transition updates balances before accrual, which can distort debt and collateral accounting order.",
      recommendation: "Accrue interest and verify health before any transfer or state mutation that alters the collateral/debt relationship.",
      severity: "medium",
      confidence: "medium",
      category: "state-ordering",
      contract: model.name,
      location: transition.location,
      evidence: [{ kind: "ordering", description: "Transfer or balance mutation occurs before accrual", location: transition.location }],
      assumptions: ["Reserves and collateral should be updated in a safe order"],
    });
  }
  if (ruleId === "CP-LND-016") {
    const transition = model.transitions.find((item) => item.name === "freeze");
    if (!transition) return findings;
    findings.push({
      ruleId,
      title: "Protocol pause path lacks bad-debt guardrails",
      description: "The contract can pause the system without any explicit bad-debt or protocol insolvency handling path.",
      recommendation: "Define stabilization or bad-debt handling before or after the pause transition, and encode a safe unwind path.",
      severity: "medium",
      confidence: "medium",
      category: "protocol-specific",
      contract: model.name,
      location: transition.location,
      evidence: [{ kind: "absence", description: "No bad-debt safeguard is present after pause state mutation", location: transition.location }],
      assumptions: ["Paused lending systems should still preserve protocol solvency"],
    });
  }
  return findings;
}

function buildContract(
  source: string,
  file: string,
  contractNode: ASTNode,
  limits: LendingAnalysisLimits,
): { model: LendingContractModel; diagnostics: LendingDiagnostic[] } {
  const contract = contractNode as NodeRecord;
  const stateVariables: LendingStateVariable[] = [];
  const transitions: LendingTransition[] = [];
  const diagnostics: LendingDiagnostic[] = [];
  for (const member of contract.subNodes ?? []) {
    const item = member as NodeRecord;
    if (item.type === "StateVariableDeclaration") {
      for (const rawVariable of item.variables ?? []) {
        const variable = rawVariable as NodeRecord;
        if (!variable.name) continue;
        const typeName = stringifyType(variable.typeName);
        stateVariables.push({
          name: variable.name,
          typeName,
          role: classifyVariable(variable.name, typeName),
          isMapping: typeName.startsWith("mapping("),
          location: nodeLocation(variable, file),
        });
      }
    } else if (item.type === "FunctionDefinition" && !item.isConstructor) {
      const built = buildTransition(source, file, member, limits);
      transitions.push(built.transition);
      if (built.truncated) {
        diagnostics.push({
          code: "LND_OPERATION_LIMIT",
          severity: "warning",
          message: `Function ${built.transition.name} exceeded the operation limit`,
          location: built.transition.location,
        });
      }
    }
  }

  const model: LendingContractModel = {
    name: contract.name ?? "<anonymous>",
    file,
    adapter: classifyAdapter(stateVariables, transitions),
    stateVariables: stateVariables.sort(byLocationThenName),
    transitions: transitions.sort(byLocationThenName),
    collateralAssets: stateVariables.filter((item) => item.role === "collateral-asset").map((item) => item.name),
    debtAssets: stateVariables.filter((item) => item.role === "debt-asset").map((item) => item.name),
    oracleReferences: stateVariables.filter((item) => item.role === "oracle-price").map((item) => item.name),
    precisionScalars: ["1e18"],
    collateralFactors: new Map<string, string>(),
    liquidationThresholds: new Map<string, string>(),
    liquidationBonuses: new Map<string, string>(),
    assumptions: inferAssumptions(stateVariables, transitions),
    location: nodeLocation(contract, file),
  };
  return { model, diagnostics };
}

function buildTransition(
  source: string,
  file: string,
  node: ASTNode,
  limits: LendingAnalysisLimits,
): { transition: LendingTransition; truncated: boolean } {
  const fn = node as NodeRecord;
  const parameters = (fn.parameters ?? []).map((parameter) => (parameter as NodeRecord).name).filter((name): name is string => Boolean(name));
  const reads = new Set<string>();
  const writes = new Set<string>();
  const calls = new Set<string>();
  const operations: LendingOperation[] = [];
  let truncated = false;
  walkNode(node, (child) => {
    if (operations.length >= limits.maxOperationsPerFunction) {
      truncated = true;
      return false;
    }
    const record = child as NodeRecord;
    if (record.type === "Assignment" || (record.type === "BinaryOperation" && isAssignmentOperator(record.operator))) {
      const names = expressionNames(record.left)
        .concat(expressionNames(record.value))
        .filter((name) => Boolean(name));
      for (const name of names) {
        writes.add(name);
      }
      operations.push({
        order: operations.length + 1,
        kind: "write",
        name: names.join(",") || "assignment",
        expression: snippet(source, child),
        parameterSources: [],
        location: nodeLocation(child, file),
      });
    } else if (record.type === "FunctionCall") {
      const name = calledName(record.expression);
      if (name) calls.add(name);
      operations.push({
        order: operations.length + 1,
        kind: "call",
        name: name ?? "call",
        expression: snippet(source, child),
        parameterSources: [],
        location: nodeLocation(child, file),
      });
    } else if (record.type === "BinaryOperation") {
      operations.push({
        order: operations.length + 1,
        kind: "arithmetic",
        name: record.operator ?? "binary",
        expression: snippet(source, child),
        parameterSources: [],
        location: nodeLocation(child, file),
      });
    }
    return true;
  });

  const role = classifyFunction((fn.name ?? "unknown").toLowerCase(), parameters, Array.from(writes), Array.from(calls));
  return {
    transition: {
      name: fn.name ?? "<anonymous>",
      role,
      visibility: fn.visibility ?? "external",
      modifiers: (fn.modifiers ?? []).map((modifier) => (modifier as NodeRecord).name ?? "modifier"),
      parameters,
      reads: Array.from(reads),
      writes: Array.from(writes),
      calls: Array.from(calls),
      operations,
      location: nodeLocation(fn, file),
      source: source.slice(fn.range?.[0] ?? 0, fn.range?.[1] ?? source.length),
    },
    truncated,
  };
}

function classifyVariable(name: string, typeName: string): LendingVariableRole {
  const value = `${name} ${typeName}`.toLowerCase();
  if (/collateral|margin|locked/.test(value)) return "collateral-asset";
  if (/debt|borrow|liability/.test(value)) return "debt-asset";
  if (/borrowindex|liquidityindex|interestindex|index/.test(value)) return "interest-index";
  if (/debtshare|share.*debt|debt.*share/.test(value)) return "debt-shares";
  if (/collateralfactor|cfactor/.test(value)) return "collateral-factor";
  if (/liquidationthreshold|ltv|liq.*threshold/.test(value)) return "liquidation-threshold";
  if (/liquidationbonus|bonus/.test(value)) return "liquidation-bonus";
  if (/closefactor|close_factor/.test(value)) return "close-factor";
  if (/reservefactor|reserve/.test(value)) return "reserve-factor";
  if (/exchange.*rate|rate.*stored/.test(value)) return "exchange-rate";
  if (/health|hf/.test(value)) return "health-factor";
  if (/oracle|price/.test(value)) return "oracle-price";
  if (/pause|paused/.test(value)) return "pause-state";
  if (/last.*accr|accrual|timestamp/.test(value)) return "accrual-timestamp";
  return "unknown";
}

function classifyFunction(name: string, parameters: string[], writes: string[], calls: string[]): LendingFunctionRole {
  if (/borrow/.test(name)) return "borrow";
  if (/repay/.test(name)) return "repay";
  if (/deposit|mint|supply/.test(name)) return "deposit";
  if (/withdraw|redeem/.test(name)) return "withdraw";
  if (/liquidat/.test(name)) return "liquidate";
  if (/accru|update.*index/.test(name)) return "accrue-interest";
  if (/oracle|price/.test(name)) return "update-oracle";
  if (/health|factor/.test(name)) return "calculate-health";
  if (/config|set.*factor|set.*threshold|set.*bonus/.test(name)) return "set-liquidation-params";
  return "unknown";
}

function classifyAdapter(stateVariables: LendingStateVariable[], transitions: LendingTransition[]) {
  const stateNames = stateVariables.map((item) => item.name.toLowerCase());
  const transitionNames = transitions.map((item) => item.name.toLowerCase());
  if (stateNames.some((name) => /borrowindex|liquidityindex/.test(name)) || transitionNames.some((name) => /accrue|borrow|mint/.test(name))) {
    return "compound-ctoken";
  }
  if (stateNames.some((name) => /liquidationbonus|collateralfactor/.test(name))) return "isolated-pool";
  return "generic-lending";
}

function inferAssumptions(stateVariables: LendingStateVariable[], transitions: LendingTransition[]): string[] {
  const assumptions: string[] = [];
  if (stateVariables.some((variable) => variable.role === "collateral-factor")) {
    assumptions.push("Collateral factor configuration is interpreted as a safety ratio for borrow capacity");
  }
  if (transitions.some((transition) => transition.role === "liquidate")) {
    assumptions.push("Execution ordering assumes liquidations are only valid on undercollateralized positions");
  }
  return assumptions;
}

function isRelevant(model: LendingContractModel): boolean {
  return model.transitions.length > 0 || model.stateVariables.length > 0;
}

function limited(code: LendingDiagnostic["code"], message: string, file: string): BuildLendingModelsResult {
  return {
    models: [],
    diagnostics: [{ code, severity: "warning", message, location: { file, line: 1, column: 1 } }],
  };
}

function parseFailure(file: string, error: string): BuildLendingModelsResult {
  return {
    models: [],
    diagnostics: [{
      code: "LND_PARSE_ERROR",
      severity: "error",
      message: `Solidity source could not be parsed: ${error}`,
      location: { file, line: 1, column: 1 },
    }],
  };
}

function collectNodes(node: ASTNode, type: string, signal?: LendingCancellationSignal): ASTNode[] {
  const matches: ASTNode[] = [];
  walkNode(node, (child) => {
    if (signal?.aborted) return false;
    if ((child as NodeRecord).type === type) matches.push(child);
    return true;
  });
  return matches;
}

function walkNode(node: ASTNode, visitor: (child: ASTNode) => boolean | void): void {
  const record = node as NodeRecord;
  if (!record) return;
  const ok = visitor(node);
  if (ok === false) return;
  const values = Object.values(record);
  for (const value of values) {
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item && typeof item === "object" && "type" in item) walkNode(item as ASTNode, visitor);
      }
    } else if (value && typeof value === "object" && "type" in value) {
      walkNode(value as ASTNode, visitor);
    }
  }
}

function byLocationThenName<T extends { location: LendingSourceLocation; name?: string }>(left: T, right: T): number {
  return left.location.line - right.location.line || left.name?.localeCompare(right.name ?? "") || 0;
}

function nodeLocation(node: ASTNode | undefined, file: string): LendingSourceLocation {
  const loc = (node as NodeRecord)?.loc;
  const start = loc?.start ?? { line: 1, column: 1 };
  const end = loc?.end ?? { line: 1, column: 1 };
  return {
    file,
    line: start.line ?? 1,
    column: (start.column ?? 0) + 1,
    lineEnd: end.line ?? start.line ?? 1,
    columnEnd: (end.column ?? 0) + 1,
  };
}

function stringifyType(typeNode?: ASTNode): string {
  if (!typeNode) return "unknown";
  const record = typeNode as NodeRecord;
  if (record.type === "ElementaryTypeName") return typeof record.name === "string" ? record.name : "unknown";
  if (record.type === "UserDefinedTypeName") {
    return typeof record.namePath === "string"
      ? record.namePath
      : typeof record.name === "string"
        ? record.name
        : "unknown";
  }
  if (record.type === "Mapping") return `mapping(${stringifyType(record.keyType)} => ${stringifyType(record.valueType)})`;
  if (record.type === "ArrayTypeName") return `${stringifyType(record.baseTypeName)}[]`;
  return typeof record.name === "string" ? record.name : "unknown";
}

function snippet(source: string, node: ASTNode): string {
  const record = node as NodeRecord;
  const loc = record.loc;
  if (!loc?.start || !loc?.end) return "";
  const startLine = loc.start.line ?? 1;
  const endLine = loc.end.line ?? startLine;
  const lines = source.split("\n");
  return lines.slice(startLine - 1, endLine).join("\n").trim();
}

function expressionNames(node?: ASTNode): string[] {
  if (!node) return [];
  const record = node as NodeRecord;
  if (record.type === "Identifier") return [record.name ?? ""];
  if (record.type === "MemberAccess") return expressionNames(record.expression);
  if (record.type === "IndexAccess") return expressionNames(record.baseTypeName ?? record.expression);
  return [];
}

function calledName(node?: ASTNode): string | undefined {
  if (!node) return undefined;
  const record = node as NodeRecord;
  if (record.type === "Identifier") return typeof record.name === "string" ? record.name : undefined;
  if (record.type === "MemberAccess") {
    return typeof record.memberName === "string"
      ? record.memberName
      : calledName(record.expression);
  }
  return undefined;
}

function isAssignmentOperator(operator?: string): boolean {
  return !!operator && ["=", "+=", "-=", "*=", "/=", "%="].includes(operator);
}

function checkCancelled(signal?: LendingCancellationSignal): void {
  if (signal?.aborted) {
    throw new Error("Lending analysis cancelled");
  }
}
