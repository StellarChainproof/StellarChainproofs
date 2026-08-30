import type {
  AmmAnalysisLimits,
  AmmCancellationSignal,
  AmmContractModel,
  AmmDiagnostic,
  AmmFunctionRole,
  AmmOperation,
  AmmSourceLocation,
  AmmStateVariable,
  AmmTransition,
  AmmVariableRole,
} from "./types";
import { AmmAnalysisCancelledError } from "./config";
import { matchAmmFrameworkAdapter } from "./adapters";

export interface BuildAmmModelsResult {
  models: AmmContractModel[];
  diagnostics: AmmDiagnostic[];
}

export function buildAmmModels(
  source: string,
  file: string,
  limits: AmmAnalysisLimits,
  signal?: AmmCancellationSignal,
): BuildAmmModelsResult {
  const diagnostics: AmmDiagnostic[] = [];
  if (source.length > limits.maxSourceBytes) {
    diagnostics.push({
      code: "AMM_SOURCE_LIMIT",
      severity: "warning",
      message: `Source exceeds ${limits.maxSourceBytes} bytes; analysis truncated`,
      location: { file, line: 1, column: 1 },
    });
  }

  const contractNames = extractContractNames(source);
  const models: AmmContractModel[] = [];
  for (const name of contractNames.slice(0, limits.maxContracts)) {
    if (signal?.aborted) throw new AmmAnalysisCancelledError();
    const stateVariables = extractStateVariables(source, file, name);
    const transitions = extractTransitions(source, file, name, limits.maxOperationsPerFunction, limits.maxFunctionsPerContract);
    const model: AmmContractModel = {
      name,
      file,
      adapter: matchAmmFrameworkAdapter({ stateVariables, transitions }).adapter,
      stateVariables,
      transitions,
      precisionScalars: extractPrecisionScalars(source),
      tokenPairs: extractTokenPairs(source),
      assumptions: [
        "Deterministic analysis is based on the contract's source-level state and transition ordering.",
      ],
      location: { file, line: 1, column: 1 },
    };
    models.push(model);
  }

  if (contractNames.length > limits.maxContracts) {
    diagnostics.push({
      code: "AMM_CONTRACT_LIMIT",
      severity: "warning",
      message: `Only the first ${limits.maxContracts} contracts were analyzed`,
      location: { file, line: 1, column: 1 },
    });
  }

  return { models, diagnostics };
}

function extractContractNames(source: string): string[] {
  const names = Array.from(source.matchAll(/contract\s+([A-Za-z_][A-Za-z0-9_]*)/g), (match) => match[1]);
  return [...new Set(names)];
}

function extractStateVariables(source: string, file: string, contractName: string): AmmStateVariable[] {
  const matches = Array.from(source.matchAll(/(?:^|\s)(?:mapping\([^)]*\)|[A-Za-z_][\w\[\]<>.,\s]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;/g));
  return matches.map((match, index) => {
    const name = match[1];
    const role = inferVariableRole(name, source);
    return {
      name,
      typeName: "unknown",
      role,
      isMapping: /mapping\s*\(/.test(match[0]),
      location: { file, line: 1 + source.slice(0, match.index ?? 0).split("\n").length - 1, column: 1 },
    };
  }).filter((variable) => variable.name !== contractName && variable.name !== "owner");
}

function extractTransitions(
  source: string,
  file: string,
  contractName: string,
  maxOperationsPerFunction: number,
  maxFunctionsPerContract: number,
): AmmTransition[] {
  const functionRegex = /function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*(?:public|external|internal|private)?[^\{]*\{/g;
  const matches = Array.from(source.matchAll(functionRegex));
  const transitions: AmmTransition[] = [];
  for (const match of matches.slice(0, maxFunctionsPerContract)) {
    const name = match[1];
    const start = match.index ?? 0;
    const bodyStart = source.indexOf("{", start);
    const bodyEnd = findMatchingBrace(source, bodyStart);
    const body = source.slice(bodyStart + 1, bodyEnd);
    const operations = extractOperations(body, file, maxOperationsPerFunction);
    transitions.push({
      name,
      role: inferFunctionRole(name, body),
      visibility: "public",
      modifiers: [],
      parameters: [],
      reads: extractIdentifiers(body, /\b(?:reserve|balance|fee|total|liquidity|deadline|amount|k|price)\w*\b/g),
      writes: extractIdentifiers(body, /\b(?:reserve|balance|total|liquidity|fee|price|deadline)\w*\b/g),
      calls: extractIdentifiers(body, /\b[a-zA-Z_][A-Za-z0-9_]*\s*\(/g),
      operations,
      location: { file, line: 1 + source.slice(0, start).split("\n").length - 1, column: 1 },
      source: body,
    });
  }
  return transitions.filter((transition) => transition.name !== contractName);
}

function extractOperations(body: string, file: string, maxOperationsPerFunction: number): AmmOperation[] {
  const operations: AmmOperation[] = [];
  const statements = body.split(/[;\n]+/).filter(Boolean);
  for (const [index, statement] of statements.slice(0, maxOperationsPerFunction).entries()) {
    const trimmed = statement.trim();
    if (!trimmed) continue;
    const kind = inferOperationKind(trimmed);
    operations.push({
      order: index,
      kind,
      name: kind === "arithmetic" ? "/" : trimmed.split("=")[0].trim().split(/\s+/).slice(-1)[0],
      expression: trimmed,
      location: { file, line: 1, column: 1 },
    });
  }
  return operations;
}

function inferVariableRole(name: string, source: string): AmmVariableRole {
  const lower = name.toLowerCase();
  if (/(reserve|token0|token1|x|y)/.test(lower) && /(balance|amount|reserve)/.test(lower)) return "reserve-balance-a";
  if (/(total|supply|shares)/.test(lower)) return "total-supply";
  if (/(fee|protocol|swap)/.test(lower)) return "fee-rate";
  if (/(deadline|slippage|minout|amountoutmin)/.test(lower)) return "slippage-bound";
  if (/(price|sqrt|tick|bound)/.test(lower)) return "price-bound";
  if (/(liquidity|shares)/.test(lower)) return "liquidity-balances";
  if (/(tick|sqrt)/.test(lower)) return "invariant";
  return "unknown";
}

function inferFunctionRole(name: string, body: string): AmmFunctionRole {
  const lower = name.toLowerCase();
  if (lower.includes("init")) return "initialize";
  if (lower.includes("mint") || lower.includes("addliquidity")) return "mint-liquidity";
  if (lower.includes("burn") || lower.includes("removeliquidity")) return "burn-liquidity";
  if (lower.includes("flashswap") || lower.includes("flash_swap") || /flash[-_]?swap/.test(lower)) return "flash-swap";
  if (lower.includes("swap") || lower.includes("trade")) return "swap";
  if (lower.includes("donate")) return "donate";
  if (lower.includes("fee") || lower.includes("setfee")) return "set-fees";
  if (lower.includes("sync")) return "sync-reserves";
  if (lower.includes("oracle") || lower.includes("price")) return "update-oracle";
  if (lower.includes("pause")) return "pause";
  if (lower.includes("unpause")) return "unpause";
  if (lower.includes("settle") || lower.includes("callback")) return "settle-callback";
  return "unknown";
}

function inferOperationKind(statement: string): AmmOperation["kind"] {
  if (/\b(?:\+|\-|\*|\/|%|\+=|\-=|\*=|\/=)\b/.test(statement)) return "arithmetic";
  if (/\b(?:if|require|assert)\b/.test(statement)) return "guard";
  if (/\b(?:call|transfer|withdraw|deposit|swap|mint|burn)\b/.test(statement)) return "call";
  if (/=/.test(statement)) return "write";
  return "read";
}

function findMatchingBrace(source: string, openingIndex: number): number {
  let depth = 0;
  for (let i = openingIndex; i < source.length; i++) {
    if (source[i] === "{") depth += 1;
    if (source[i] === "}") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return source.length;
}

function extractIdentifiers(source: string, regex: RegExp): string[] {
  return Array.from(source.matchAll(regex), (match) => match[0].replace(/\s*\(/g, "").trim()).filter(Boolean);
}

function extractPrecisionScalars(source: string): string[] {
  return Array.from(new Set(Array.from(source.matchAll(/(?:1e|1E)\d+|\b(?:WAD|RAY|SECONDS_PER_YEAR)\b/g), (match) => match[0])));
}

function extractTokenPairs(source: string): string[] {
  const pairs = new Set<string>();
  for (const match of source.matchAll(/(?:token0|token1|assetA|assetB|reserveA|reserveB|x\b|y\b)/g)) {
    pairs.add(match[0]);
  }
  return [...pairs];
}
