import { parseSolidity } from "../ast/parser";
import type { ASTNode } from "../types";
import { matchBridgeFramework } from "./adapters";
import { BridgeAnalysisCancelledError } from "./config";
import { detectMitigations } from "./mitigations";
import type {
  BridgeAnalysisLimits,
  BridgeCancellationSignal,
  BridgeContractModel,
  BridgeDiagnostic,
  BridgeFunctionRole,
  BridgeOperation,
  BridgeSourceLocation,
  BridgeStateVariable,
  BridgeTransition,
  BridgeVariableRole,
} from "./types";

interface NodeRecord {
  type?: string;
  name?: string;
  namePath?: string;
  memberName?: string;
  operator?: string;
  visibility?: string;
  isConstructor?: boolean;
  range?: [number, number];
  loc?: {
    start?: { line?: number; column?: number };
    end?: { line?: number; column?: number };
  };
  subNodes?: ASTNode[];
  variables?: ASTNode[];
  parameters?: ASTNode[];
  modifiers?: ASTNode[];
  expression?: ASTNode;
  left?: ASTNode;
  condition?: ASTNode;
  typeName?: ASTNode;
  baseTypeName?: ASTNode;
  keyType?: ASTNode;
  valueType?: ASTNode;
  [key: string]: unknown;
}

export interface BuildBridgeModelsResult {
  models: BridgeContractModel[];
  diagnostics: BridgeDiagnostic[];
}

export function buildBridgeModels(
  source: string,
  file: string,
  limits: BridgeAnalysisLimits,
  signal?: BridgeCancellationSignal,
): BuildBridgeModelsResult {
  checkCancelled(signal);
  if (Buffer.byteLength(source, "utf8") > limits.maxSourceBytes) {
    return limited("BRG_SOURCE_LIMIT", `Source exceeds the ${limits.maxSourceBytes}-byte limit`, file);
  }
  const shape = preflightSourceShape(source);
  if (shape.contracts > limits.maxContracts) {
    return limited("BRG_CONTRACT_LIMIT", `Source declares more than ${limits.maxContracts} contracts`, file);
  }
  if (shape.functions > limits.maxFunctionsPerFile) {
    return limited("BRG_FUNCTION_LIMIT", `Source declares more than ${limits.maxFunctionsPerFile} functions`, file);
  }

  const parsed = parseSolidity(source, "<bridge-source>");
  if (!parsed.ast) {
    return parseFailure(file, sanitizeParseError(parsed.error));
  }
  const tolerantErrors = (parsed.ast as {
    errors?: Array<{ message?: string; line?: number; column?: number }>;
  }).errors;
  if (tolerantErrors?.length) {
    const first = tolerantErrors[0];
    return {
      models: [],
      diagnostics: [{
        code: "BRG_PARSE_ERROR",
        severity: "error",
        message: `Solidity source could not be parsed: ${sanitizeParserMessage(first.message)}`,
        location: { file, line: first.line ?? 1, column: (first.column ?? 0) + 1 },
      }],
    };
  }

  const contracts = collectNodes(parsed.ast, "ContractDefinition", signal);
  const diagnostics: BridgeDiagnostic[] = [];
  if (contracts.length > limits.maxContracts) {
    diagnostics.push({
      code: "BRG_CONTRACT_LIMIT",
      severity: "warning",
      message: `Only the first ${limits.maxContracts} contracts were analyzed`,
      location: startLocation(file),
    });
  }
  const models: BridgeContractModel[] = [];
  for (const contract of contracts.slice(0, limits.maxContracts)) {
    checkCancelled(signal);
    const built = buildContract(source, file, contract, limits);
    diagnostics.push(...built.diagnostics);
    if (isRelevant(built.model)) models.push(built.model);
  }
  return { models, diagnostics };
}

function buildContract(
  source: string,
  file: string,
  contractNode: ASTNode,
  limits: BridgeAnalysisLimits,
): { model: BridgeContractModel; diagnostics: BridgeDiagnostic[] } {
  const contract = contractNode as NodeRecord;
  const stateVariables: BridgeStateVariable[] = [];
  const functions: ASTNode[] = [];
  const diagnostics: BridgeDiagnostic[] = [];
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
      functions.push(member);
    }
  }

  if (functions.length > limits.maxFunctionsPerContract) {
    diagnostics.push({
      code: "BRG_FUNCTION_LIMIT",
      severity: "warning",
      message: `Contract ${contract.name ?? "<anonymous>"} exceeds the function limit`,
      location: nodeLocation(contract, file),
    });
  }
  const stateNames = new Set(stateVariables.map((variable) => variable.name));
  const transitions: BridgeTransition[] = [];
  for (const fn of functions.slice(0, limits.maxFunctionsPerContract)) {
    const built = buildTransition(source, file, fn, stateNames, limits);
    transitions.push(built.transition);
    if (built.truncated) {
      diagnostics.push({
        code: "BRG_OPERATION_LIMIT",
        severity: "warning",
        message: `Function ${built.transition.name} exceeded the operation limit`,
        location: built.transition.location,
      });
    }
  }

  const base: BridgeContractModel = {
    name: contract.name ?? "<anonymous>",
    file,
    adapter: "none",
    stateVariables: stateVariables.sort(byLocationThenName),
    transitions: transitions.sort(byLocationThenName),
    privilegedCalls: [],
    messageControlledCalls: [],
    assumptions: [],
    location: nodeLocation(contract, file),
  };
  base.privilegedCalls = transitions.flatMap((transition) =>
    transition.operations.filter((operation) =>
      operation.kind === "call" && isPrivilegedCall(operation.name, operation.expression),
    ),
  ).sort(byOperation);
  base.messageControlledCalls = base.privilegedCalls.filter((operation) =>
    operation.parameterSources.length > 0,
  );
  base.adapter = matchBridgeFramework(base).adapter;
  base.assumptions = inferAssumptions(base);
  return { model: base, diagnostics };
}

function buildTransition(
  source: string,
  file: string,
  node: ASTNode,
  stateNames: Set<string>,
  limits: BridgeAnalysisLimits,
): { transition: BridgeTransition; truncated: boolean } {
  const fn = node as NodeRecord;
  const parameters = (fn.parameters ?? [])
    .map((parameter) => (parameter as NodeRecord).name)
    .filter((name): name is string => Boolean(name));
  const parameterSet = new Set(parameters);
  const reads = new Set<string>();
  const writes = new Set<string>();
  const calls = new Set<string>();
  const operations: BridgeOperation[] = [];
  let truncated = false;

  walkNode(node, (child) => {
    if (operations.length >= limits.maxOperationsPerFunction) {
      truncated = true;
      return false;
    }
    const record = child as NodeRecord;
    if (record.type === "Assignment" ||
      (record.type === "BinaryOperation" && isAssignmentOperator(record.operator))) {
      const names = expressionNames(record.left);
      for (const name of names) if (stateNames.has(name)) writes.add(name);
      addOperation(operations, "write", [...names].join(",") || "assignment", child, source, file, parameterSet);
    } else if (record.type === "UnaryOperation" && ["++", "--", "delete"].includes(record.operator ?? "")) {
      const names = expressionNames(record.expression);
      for (const name of names) if (stateNames.has(name)) writes.add(name);
      addOperation(operations, "write", [...names].join(",") || "unary", child, source, file, parameterSet);
    } else if (record.type === "FunctionCall") {
      const name = calledName(record.expression);
      if (name) {
        calls.add(name);
        addOperation(
          operations,
          name === "require" || name === "assert" ? "guard" : "call",
          name,
          child,
          source,
          file,
          parameterSet,
        );
      }
    } else if (record.type === "ForStatement" || record.type === "WhileStatement" || record.type === "DoWhileStatement") {
      addOperation(operations, "loop", record.type ?? "loop", child, source, file, parameterSet);
    } else if (record.type === "IfStatement" && record.condition) {
      addOperation(operations, "guard", "if", record.condition, source, file, parameterSet);
    } else if (record.type === "BinaryOperation") {
      addOperation(operations, "arithmetic", record.operator ?? "binary", child, source, file, parameterSet);
    } else if (record.type === "Identifier" && record.name && stateNames.has(record.name)) {
      reads.add(record.name);
    } else if (record.type === "MemberAccess" && record.memberName && stateNames.has(record.memberName)) {
      reads.add(record.memberName);
    }
    return true;
  });

  const name = fn.name ?? "<fallback>";
  const transitionSource = nodeSnippet(source, fn);
  const built: BridgeTransition = {
    name,
    role: classifyFunction(name),
    visibility: fn.visibility ?? "default",
    modifiers: (fn.modifiers ?? []).map(modifierName).filter((value): value is string => Boolean(value)).sort(),
    parameters,
    reads: [...reads].sort(),
    writes: [...writes].sort(),
    calls: [...calls].sort(),
    operations: operations.sort(byOperation),
    location: nodeLocation(fn, file),
    source: transitionSource,
    mitigations: [],
  };
  built.mitigations = detectMitigations(built).map((item) => item.kind);
  return {
    transition: built,
    truncated,
  };
}

function addOperation(
  operations: BridgeOperation[],
  kind: BridgeOperation["kind"],
  name: string,
  node: ASTNode,
  source: string,
  file: string,
  parameters: Set<string>,
): void {
  const record = node as NodeRecord;
  const expression = compact(nodeSnippet(source, record));
  operations.push({
    order: record.range?.[0] ?? operations.length,
    kind,
    name,
    expression,
    parameterSources: [...parameters].filter((parameter) =>
      new RegExp(`\\b${escapeRegExp(parameter)}\\b`).test(expression),
    ).sort(),
    location: nodeLocation(record, file),
  });
}

function classifyVariable(name: string, typeName: string): BridgeVariableRole {
  const value = normalize(name);
  if (/(sourcechainid|sourcechain|originchain|fromchain)/.test(value)) return "source-chain";
  if (/(destchainid|destchain|destinationchain|tochain|targetchain)/.test(value)) return "destination-chain";
  if (/(chainid|domainseparator|domain|endpointid)/.test(value)) return "chain-domain";
  if (/(messageid|processedmessages|consumedmessages|handledmessages|executedmessages)/.test(value)) return "message-id";
  if (/(nonce|nonces|inboundnonce|outboundnonce)/.test(value)) return "nonce";
  if (/(processed|executed|handled|consumed)/.test(value) && typeName.startsWith("mapping(")) return "processed-messages";
  if (/(replay|seenmessages|usednonces)/.test(value)) return "replay-map";
  if (/(validators|signers|owners|guardians|committee)/.test(value) &&
    (typeName.startsWith("mapping(") || typeName.endsWith("[]"))) return "validator-set";
  if (/(validatorthreshold|signaturethreshold|multisigthreshold|quorum|threshold)/.test(value)) return "validator-threshold";
  if (/(merkleroot|root|stateRoot|latestroot)/.test(value)) return "merkle-root";
  if (/(stateroot|confirmedroot|finalizedroot)/.test(value)) return "state-root";
  if (/(finalitywindow|finalitydelay|confirmationblocks|challengeperiod)/.test(value)) return "finality-window";
  if (/(lockedamount|totallocked|deposits|escrowed)/.test(value)) return "lock-amount";
  if (/(mintedamount|totalminted|wrappedsupply)/.test(value)) return "mint-amount";
  if (/(burnedamount|totalburned)/.test(value)) return "burn-amount";
  if (/(releasedamount|totalreleased|unlocked)/.test(value)) return "release-amount";
  if (/(paused|isPaused|bridgePaused)/.test(value)) return "bridge-paused";
  if (/(ratelimit|messagelimit|dailyLimit|hourlyLimit)/.test(value)) return "rate-limit";
  if (/(messagequeue|pendingmessages|inboundqueue)/.test(value)) return "message-queue";
  if (/(relayer|authorizedrelayer|trustedrelayer)/.test(value)) return "relayer-role";
  if (/(upgradeauthority|upgrader|proxyadmin)/.test(value)) return "upgrade-authority";
  return "unknown";
}

function classifyFunction(name: string): BridgeFunctionRole {
  const value = normalize(name);
  if (/^(sendmessage|dispatch|send|sendtokens|bridgeout|lzsend|sendpayload)$/.test(value)) return "send-message";
  if (/^(receivemessage|handlemessage|onmessage|lzreceive|processmessage|delivermessage)$/.test(value)) return "receive-message";
  if (/^(verifyproof|verifymerkleproof|checkproof|validateproof)$/.test(value)) return "verify-proof";
  if (/^(checksignatures|validatesignatures|verifysignatures|verifyvalidators)$/.test(value)) return "verify-signatures";
  if (/^(lock|locktokens|deposit|bridgein|escrow)$/.test(value)) return "lock-tokens";
  if (/^(mint|minttokens|wrap|mintwrapped)$/.test(value)) return "mint-tokens";
  if (/^(burn|burntokens|unwrap|burnwrapped)$/.test(value)) return "burn-tokens";
  if (/^(release|releasetokens|unlock|withdraw|claim)$/.test(value)) return "release-tokens";
  if (/^(updatevalidators|setvalidators|addvalidator|removevalidator|rotatevalidators)$/.test(value)) return "update-validator-set";
  if (/^(updatethreshold|setthreshold|changethreshold)$/.test(value)) return "update-threshold";
  if (/^(updateroot|setroot|updatemerkleroot|commitroot)$/.test(value)) return "update-root";
  if (/^(executemessage|relaymessage|finalizemessage|completeTransfer)$/.test(value)) return "execute-message";
  if (/^(relay|retry|resend|resubmitmessage)$/.test(value)) return "relay-message";
  if (/^(pause|pausebridge|emergencypause)$/.test(value)) return "pause-bridge";
  if (/^(unpause|unpausebridge|resume)$/.test(value)) return "unpause-bridge";
  if (/^(upgradeto|upgradetoandcall|authorizeupgrade|upgrade)$/.test(value)) return "upgrade";
  return "unknown";
}

function isRelevant(model: BridgeContractModel): boolean {
  if (model.transitions.length === 1 && model.stateVariables.length === 0) return false;
  const roles = new Set(model.transitions.map((transition) => transition.role));
  const variableRoles = model.stateVariables.filter((variable) => variable.role !== "unknown");
  return roles.has("send-message") || roles.has("receive-message") || roles.has("verify-proof") ||
    roles.has("verify-signatures") || roles.has("lock-tokens") || roles.has("mint-tokens") ||
    roles.has("burn-tokens") || roles.has("release-tokens") || roles.has("execute-message") ||
    roles.has("relay-message") || variableRoles.length >= 3;
}

function inferAssumptions(model: BridgeContractModel): string[] {
  const assumptions: string[] = [];
  if (model.transitions.some((transition) => transition.role === "receive-message")) {
    assumptions.push("The cross-chain transport may redeliver a previously accepted message");
  }
  if (model.transitions.some((transition) => ["mint-tokens", "release-tokens"].includes(transition.role))) {
    assumptions.push("Token minting or release implies economic value transfer across chains");
  }
  if (model.transitions.some((transition) => transition.role === "verify-signatures")) {
    assumptions.push("Validator signatures are the sole authorization for message acceptance");
  }
  if (model.transitions.some((transition) => transition.role === "execute-message")) {
    assumptions.push("Message payloads can invoke privileged external state transitions");
  }
  return assumptions;
}

function isPrivilegedCall(name: string, expression: string): boolean {
  return /^(call|delegatecall|functionCall|functionCallWithValue|upgradeTo|upgradeToAndCall|execute)$/i.test(name) ||
    /\.call\s*\{|\.delegatecall\s*\(|upgradeTo(?:AndCall)?\s*\(/i.test(expression);
}

function stringifyType(node: ASTNode | undefined): string {
  if (!node) return "unknown";
  const type = node as NodeRecord;
  if (type.type === "Mapping") return `mapping(${stringifyType(type.keyType)}=>${stringifyType(type.valueType)})`;
  if (type.type === "ArrayTypeName") return `${stringifyType(type.baseTypeName)}[]`;
  return type.name ?? type.namePath ?? type.type ?? "unknown";
}

function calledName(node: ASTNode | undefined): string | undefined {
  const value = node as NodeRecord | undefined;
  return value?.name ?? value?.memberName ?? value?.namePath ?? calledName(value?.expression);
}

function modifierName(node: ASTNode): string | undefined {
  const value = node as NodeRecord;
  return value.name ?? value.namePath;
}

function expressionNames(root: ASTNode | undefined): Set<string> {
  const names = new Set<string>();
  if (!root) return names;
  walkNode(root, (node) => {
    const value = node as NodeRecord;
    if (value.type === "Identifier" && value.name) names.add(value.name);
    if (value.type === "MemberAccess" && value.memberName) names.add(value.memberName);
    return true;
  });
  return names;
}

function collectNodes(root: ASTNode, type: string, signal?: BridgeCancellationSignal): ASTNode[] {
  const nodes: ASTNode[] = [];
  walkNode(root, (node) => {
    checkCancelled(signal);
    if ((node as NodeRecord).type === type) nodes.push(node);
    return true;
  });
  return nodes;
}

function walkNode(root: unknown, visitor: (node: ASTNode) => boolean): void {
  const stack: unknown[] = [root];
  const seen = new WeakSet<object>();
  while (stack.length) {
    const value = stack.pop();
    if (!value || typeof value !== "object") continue;
    if (Array.isArray(value)) {
      for (let index = value.length - 1; index >= 0; index--) stack.push(value[index]);
      continue;
    }
    if (seen.has(value)) continue;
    seen.add(value);
    if (!visitor(value as ASTNode)) continue;
    const record = value as Record<string, unknown>;
    for (const key of Object.keys(record).filter((key) => key !== "loc" && key !== "range").sort().reverse()) {
      stack.push(record[key]);
    }
  }
}

function preflightSourceShape(source: string): { contracts: number; functions: number } {
  const code = source.replace(
    /\/\*[\s\S]*?\*\/|\/\/[^\n\r]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g,
    " ",
  );
  return {
    contracts: countMatches(code, /\b(?:contract|interface|library)\s+[A-Za-z_$][\w$]*/g),
    functions: countMatches(code, /\bfunction\b/g),
  };
}

function countMatches(value: string, expression: RegExp): number {
  let count = 0;
  while (expression.exec(value)) count += 1;
  return count;
}

function nodeLocation(node: NodeRecord, file: string): BridgeSourceLocation {
  return {
    file,
    line: node.loc?.start?.line ?? 1,
    column: (node.loc?.start?.column ?? 0) + 1,
    ...(node.loc?.end?.line ? { lineEnd: node.loc.end.line } : {}),
    ...(node.loc?.end?.column !== undefined ? { columnEnd: node.loc.end.column + 1 } : {}),
  };
}

function nodeSnippet(source: string, node: NodeRecord): string {
  if (node.range) return source.slice(node.range[0], node.range[1] + 1);
  const start = node.loc?.start?.line;
  const end = node.loc?.end?.line;
  return start && end ? source.split("\n").slice(start - 1, end).join("\n") : "";
}

function compact(value: string): string {
  const result = value.replace(/\s+/g, " ").trim();
  return result.length > 280 ? `${result.slice(0, 277)}...` : result;
}

function isAssignmentOperator(operator: string | undefined): boolean {
  return operator !== undefined && ["=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "<<=", ">>="].includes(operator);
}

function byOperation(left: BridgeOperation, right: BridgeOperation): number {
  return left.order - right.order || left.kind.localeCompare(right.kind) || left.name.localeCompare(right.name);
}

function byLocationThenName<T extends { location: BridgeSourceLocation; name: string }>(left: T, right: T): number {
  return left.location.line - right.location.line || left.location.column - right.location.column ||
    left.name.localeCompare(right.name);
}

function limited(
  code: "BRG_SOURCE_LIMIT" | "BRG_CONTRACT_LIMIT" | "BRG_FUNCTION_LIMIT",
  message: string,
  file: string,
): BuildBridgeModelsResult {
  return { models: [], diagnostics: [{ code, severity: "warning", message, location: startLocation(file) }] };
}

function parseFailure(file: string, message: string): BuildBridgeModelsResult {
  return {
    models: [],
    diagnostics: [{ code: "BRG_PARSE_ERROR", severity: "error", message, location: startLocation(file) }],
  };
}

function sanitizeParseError(error: string | undefined): string {
  const detail = error?.replace(/^Parse error in <bridge-source>:\s*/, "").replace(/\s+/g, " ").trim();
  return `Solidity source could not be parsed${detail ? `: ${detail.slice(0, 300)}` : ""}`;
}

function sanitizeParserMessage(message: string | undefined): string {
  return (message ?? "syntax error").replace(/[\r\n]+/g, " ").slice(0, 300);
}

function startLocation(file: string): BridgeSourceLocation {
  return { file, line: 1, column: 1 };
}

function checkCancelled(signal?: BridgeCancellationSignal): void {
  if (signal?.aborted) throw new BridgeAnalysisCancelledError();
}

function normalize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
