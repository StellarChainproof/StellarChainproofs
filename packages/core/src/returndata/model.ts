import { parseSolidity } from "../ast/parser";
import type { ASTNode } from "../types";
import { ReturndataAnalysisCancelledError } from "./config";
import { matchReturndataFramework } from "./adapters";
import { classifyCallKind } from "./call-classifier";
import type {
  CallKind,
  ReturndataAnalysisLimits,
  ReturndataCancellationSignal,
  ReturndataContractModel,
  ReturndataDiagnostic,
  ReturndataFunctionRole,
  ReturndataOperation,
  ReturndataSourceLocation,
  ReturndataStateVariable,
  ReturndataTransition,
  ReturndataVariableRole,
} from "./types";

interface NodeRecord {
  type?: string;
  name?: string;
  memberName?: string;
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
  right?: ASTNode;
  condition?: ASTNode;
  typeName?: ASTNode;
  [key: string]: unknown;
}

export interface BuildReturndataModelsResult {
  models: ReturndataContractModel[];
  diagnostics: ReturndataDiagnostic[];
}

export function buildReturndataModels(
  source: string,
  file: string,
  limits: ReturndataAnalysisLimits,
  signal?: ReturndataCancellationSignal,
): BuildReturndataModelsResult {
  checkCancelled(signal);
  if (Buffer.byteLength(source, "utf8") > limits.maxSourceBytes) {
    return limited("RTD_SOURCE_LIMIT", `Source exceeds the ${limits.maxSourceBytes}-byte limit`, file);
  }
  const parsed = parseSolidity(source, "<returndata-source>");
  if (!parsed.ast) {
    return parseFailure(file, sanitizeParseError(parsed.error));
  }
  const contracts = collectNodes(parsed.ast, "ContractDefinition", signal);
  const models: ReturndataContractModel[] = [];
  const diagnostics: ReturndataDiagnostic[] = [];
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
  limits: ReturndataAnalysisLimits,
): { model: ReturndataContractModel; diagnostics: ReturndataDiagnostic[] } {
  const contract = contractNode as NodeRecord;
  const stateVariables: ReturndataStateVariable[] = [];
  const functions: ASTNode[] = [];
  for (const member of contract.subNodes ?? []) {
    const item = member as NodeRecord;
    if (item.type === "StateVariableDeclaration") {
      for (const raw of item.variables ?? []) {
        const variable = raw as NodeRecord;
        if (!variable.name) continue;
        stateVariables.push({
          name: variable.name,
          typeName: stringifyType(variable.typeName),
          role: classifyVariable(variable.name),
          location: nodeLocation(variable, file),
        });
      }
    } else if (item.type === "FunctionDefinition" && !item.isConstructor) {
      functions.push(member);
    }
  }
  const transitions: ReturndataTransition[] = [];
  const diagnostics: ReturndataDiagnostic[] = [];
  for (const fn of functions.slice(0, limits.maxFunctionsPerContract)) {
    transitions.push(buildTransition(source, file, fn, limits));
  }
  const base: ReturndataContractModel = {
    name: contract.name ?? "<anonymous>",
    file,
    adapter: "none",
    stateVariables: stateVariables.sort(byLocation),
    transitions: transitions.sort(byLocation),
    externalCalls: [],
    assumptions: [],
    location: nodeLocation(contract, file),
  };
  base.externalCalls = transitions.flatMap((t) =>
    t.operations.filter((op) => op.kind === "call"),
  ).sort((a, b) => a.order - b.order);
  base.adapter = matchReturndataFramework(base).adapter;
  base.assumptions = inferAssumptions(base);
  return { model: base, diagnostics };
}

function buildTransition(
  source: string,
  file: string,
  node: ASTNode,
  limits: ReturndataAnalysisLimits,
): ReturndataTransition {
  const fn = node as NodeRecord;
  const operations: ReturndataOperation[] = [];
  const guards: string[] = [];
  let _truncated = false;

  walkNode(node, (child) => {
    if (operations.length >= limits.maxOperationsPerFunction) {
      _truncated = true;
      return false;
    }
    const record = child as NodeRecord;
    if (record.type === "FunctionCall") {
      const isDecode = calledName(record.expression) === "abi.decode";
      if (isDecode) {
        operations.push({
          order: record.range?.[0] ?? operations.length,
          kind: "decode",
          callKind: "unknown",
          name: "abi.decode",
          expression: compact(nodeSnippet(source, record)),
          capturesReturn: true,
          checksSuccess: false,
          usesSafeWrapper: false,
          location: nodeLocation(record, file),
        });
      } else {
        const callInfo = classifyCall(record, source);
        if (callInfo) {
          operations.push({
            order: record.range?.[0] ?? operations.length,
            kind: "call",
            callKind: callInfo.kind,
            name: callInfo.name,
            expression: compact(nodeSnippet(source, record)),
            capturesReturn: callInfo.capturesReturn,
            checksSuccess: callInfo.checksSuccess,
            usesSafeWrapper: callInfo.usesSafeWrapper,
            location: nodeLocation(record, file),
          });
        }
      }
    } else if (record.type === "InlineAssemblyStatement" || record.type === "InLineAssemblyStatement") {
      operations.push({
        order: record.range?.[0] ?? operations.length,
        kind: "assembly",
        callKind: "unknown",
        name: "assembly",
        expression: compact(nodeSnippet(source, record)),
        capturesReturn: false,
        checksSuccess: false,
        usesSafeWrapper: false,
        location: nodeLocation(record, file),
      });
    } else if (record.type === "TryStatement") {
      guards.push("try-catch");
    } else if (record.type === "IfStatement" && record.condition) {
      const cond = compact(nodeSnippet(source, record.condition));
      operations.push({
        order: record.range?.[0] ?? operations.length,
        kind: "guard",
        callKind: "unknown",
        name: "if",
        expression: cond,
        capturesReturn: false,
        checksSuccess: /require\s*\(|revert|!\s*\w+|success/i.test(cond),
        usesSafeWrapper: false,
        location: nodeLocation(record, file),
      });
      if (/success|require|revert/i.test(cond)) guards.push(cond);
    } else if (record.type === "VariableDeclarationStatement" || record.type === "Assignment") {
      const expr = (record as { initialValue?: ASTNode; expression?: ASTNode }).initialValue ??
        (record as { expression?: ASTNode }).expression ?? record.right;
      if (expr && (expr as NodeRecord).type === "FunctionCall") {
        const leftText = compact(nodeSnippet(source, record.left ?? record));
        if (/bool|success|=/.test(leftText)) {
          const lastCall = operations[operations.length - 1];
          if (lastCall?.kind === "call") lastCall.capturesReturn = true;
        }
      }
    }
    return true;
  });

  const name = fn.name ?? "<fallback>";
  const fnSource = nodeSnippet(source, fn);
  const role = classifyFunction(name, operations, fnSource);
  return {
    name,
    role,
    visibility: fn.visibility ?? "default",
    modifiers: (fn.modifiers ?? []).map(modifierName).filter(Boolean) as string[],
    parameters: (fn.parameters ?? []).map((p) => (p as NodeRecord).name).filter(Boolean) as string[],
    operations: operations.sort((a, b) => a.order - b.order),
    location: nodeLocation(fn, file),
    source: fnSource,
    guards,
  };
}

function classifyCall(record: NodeRecord, source: string): {
  kind: CallKind;
  name: string;
  capturesReturn: boolean;
  checksSuccess: boolean;
  usesSafeWrapper: boolean;
} | null {
  const expr = record.expression as NodeRecord | undefined;
  if (!expr) return null;
  const snippet = compact(nodeSnippet(source, record));
  const kind = classifyCallKind(snippet, expr);
  if (kind === "unknown" && !/\.call|\.send|\.transfer|\.delegatecall|\.staticcall/i.test(snippet)) {
    const name = calledName(expr);
    if (!name || /^(require|assert|revert|emit|abi\.encode)/i.test(name)) return null;
    return { kind: "interface-call", name, capturesReturn: false, checksSuccess: false, usesSafeWrapper: false };
  }
  if (kind === "unknown") return null;
  const usesSafeWrapper = /SafeERC20|Address\.functionCall|SafeCall|lowLevelCall/i.test(snippet);
  return {
    kind,
    name: calledName(expr) ?? kind,
    capturesReturn: false,
    checksSuccess: usesSafeWrapper,
    usesSafeWrapper,
  };
}

function classifyVariable(name: string): ReturndataVariableRole {
  const v = name.toLowerCase();
  if (/success|ok|result/.test(v)) return "success-flag";
  if (/returndata|returnData|data/.test(v)) return "return-buffer";
  if (/length|size/.test(v)) return "return-length";
  return "unknown";
}

function classifyFunction(name: string, operations: ReturndataOperation[], source: string): ReturndataFunctionRole {
  const v = name.toLowerCase();
  if (/safetransfer|safeapprove|safeerc20/i.test(name)) return "safe-wrapper";
  if (/batch|multicall|aggregate|batchpay/i.test(v)) return "batch-operation";
  if (/try/.test(v) || operations.some((op) => op.expression.includes("try"))) return "try-catch-wrapper";
  if (operations.some((op) => op.kind === "decode")) return "abi-decode";
  if (operations.some((op) => op.kind === "assembly")) return "assembly-copy";
  if (operations.some((op) => op.callKind === "transfer" || op.callKind === "interface-call")) return "token-transfer";
  if (operations.some((op) => op.kind === "call")) return "external-call";
  return "unknown";
}

function isRelevant(model: ReturndataContractModel): boolean {
  return model.externalCalls.length > 0 ||
    model.transitions.some((t) => t.role !== "unknown");
}

function inferAssumptions(model: ReturndataContractModel): string[] {
  const assumptions: string[] = [];
  if (model.externalCalls.some((c) => c.callKind === "interface-call")) {
    assumptions.push("External tokens may be non-standard and omit return values");
  }
  if (model.externalCalls.some((c) => c.callKind === "call")) {
    assumptions.push("Low-level calls can fail silently without a success check");
  }
  return assumptions;
}

function collectNodes(root: ASTNode, type: string, signal?: ReturndataCancellationSignal): ASTNode[] {
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
      for (let i = value.length - 1; i >= 0; i--) stack.push(value[i]);
      continue;
    }
    if (seen.has(value)) continue;
    seen.add(value);
    if (!visitor(value as ASTNode)) continue;
    const record = value as Record<string, unknown>;
    for (const key of Object.keys(record).filter((k) => k !== "loc" && k !== "range").sort().reverse()) {
      stack.push(record[key]);
    }
  }
}

function calledName(node: ASTNode | undefined, depth = 0): string | undefined {
  if (!node || depth > 8) return undefined;
  const value = node as NodeRecord;
  if (value.name) return value.name;
  if (value.memberName) return value.memberName;
  return calledName(value.expression as ASTNode | undefined, depth + 1);
}

function modifierName(node: ASTNode): string | undefined {
  return (node as NodeRecord).name;
}

function stringifyType(node: ASTNode | undefined): string {
  if (!node) return "unknown";
  const type = node as NodeRecord;
  if (typeof type.name === "string") return type.name;
  if (typeof type.namePath === "string") return type.namePath;
  if (typeof type.type === "string") return type.type;
  return "unknown";
}

function nodeLocation(node: NodeRecord, file: string): ReturndataSourceLocation {
  return {
    file,
    line: node.loc?.start?.line ?? 1,
    column: (node.loc?.start?.column ?? 0) + 1,
    ...(node.loc?.end?.line ? { lineEnd: node.loc.end.line } : {}),
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

function byLocation<T extends { location: ReturndataSourceLocation; name?: string }>(a: T, b: T): number {
  return a.location.line - b.location.line || (a.name ?? "").localeCompare(b.name ?? "");
}

function limited(code: string, message: string, file: string): BuildReturndataModelsResult {
  return { models: [], diagnostics: [{ code, severity: "warning", message, location: { file, line: 1, column: 1 } }] };
}

function parseFailure(file: string, message: string): BuildReturndataModelsResult {
  return { models: [], diagnostics: [{ code: "RTD_PARSE_ERROR", severity: "error", message, location: { file, line: 1, column: 1 } }] };
}

function sanitizeParseError(error: string | undefined): string {
  return `Solidity source could not be parsed${error ? `: ${error.slice(0, 300)}` : ""}`;
}

function checkCancelled(signal?: ReturndataCancellationSignal): void {
  if (signal?.aborted) throw new ReturndataAnalysisCancelledError();
}
