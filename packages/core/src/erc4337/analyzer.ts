import type { ASTNode, Finding } from "../types";
import { getSnippet, visit } from "../ast/parser";
import { detectERC4337Version } from "./adapters";
import {
  DEFAULT_ERC4337_ANALYSIS_LIMITS,
  type ERC4337AnalysisLimits,
  type ERC4337AnalysisOptions,
  type ERC4337AnalysisResult,
  type ERC4337Component,
  type ERC4337Diagnostic,
  type ERC4337DiagnosticCode,
  type ERC4337Evidence,
  type ERC4337Version,
  type EntryPointModel,
  type NonceModel,
  type PaymasterModel,
  type UserOperationField,
  type UserOperationModel,
  type ValidationDataModel,
} from "./types";

const USER_OPERATION_FIELDS = [
  "sender", "nonce", "initCode", "callData", "callGasLimit", "verificationGasLimit",
  "preVerificationGas", "maxFeePerGas", "maxPriorityFeePerGas", "paymasterAndData",
  "signature", "factory", "factoryData", "paymaster", "paymasterVerificationGasLimit",
  "paymasterPostOpGasLimit", "paymasterData",
];

const FUNCTION_PATTERN = /function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)[^{]*\{/g;
const HASH_CALL_PATTERN = /(?:keccak256|hash|userOpHash|_getUserOpHash)\s*\(([^)]*)\)/g;
const MAX_SOURCE_LENGTH = DEFAULT_ERC4337_ANALYSIS_LIMITS.maxSourceLength;

export function detectERC4337(
  ast: ASTNode,
  source: string,
  filePath: string,
  options: ERC4337AnalysisOptions = {},
): Finding[] {
  return toFindings(analyzeERC4337(ast, source, filePath, options), source);
}

export function analyzeERC4337(
  ast: ASTNode,
  source: string,
  filePath: string,
  options: ERC4337AnalysisOptions = {},
): ERC4337AnalysisResult {
  const limits = normalizeLimits(options.limits);
  const version = resolveVersion(source, options.version ?? "auto");
  const result: ERC4337AnalysisResult = {
    schemaVersion: "erc4337-analysis-1",
    protocol: "erc-4337",
    version,
    components: [],
    diagnostics: [],
    truncated: false,
  };

  if (source.length > limits.maxSourceLength) {
    result.truncated = true;
    return result;
  }
  if (options.signal?.aborted) return result;

  const functions = collectFunctions(source, limits.maxFunctions);
  if (functions.truncated) result.truncated = true;
  const lowerSource = source.toLowerCase();
  const hasUserOperation = /useroperation|packeduseroperation/.test(lowerSource);
  const hasEntryPoint = /entrypoint|handleops|handleaggregatedops/.test(lowerSource);
  const hasPaymaster = /paymaster|validatepaymasteruserop|postop/.test(lowerSource);
  const hasFactory = /create2|factory|initcode|factorydata/.test(lowerSource);
  const hasAggregator = /aggregator|aggregatedsignature|validateuseropsignature/.test(lowerSource);

  if (hasUserOperation) {
    result.components.push("account");
    result.userOperation = modelUserOperation(version, source, functions.names);
    result.validationData = modelValidationData(source);
    result.nonce = modelNonce(source);
    addUserOperationDiagnostics(result, filePath, source, limits);
  }
  if (hasEntryPoint) {
    result.components.push("entryPoint");
    result.entryPoint = modelEntryPoint(version, source);
    addEntryPointDiagnostics(result, filePath, source, limits);
  }
  if (hasPaymaster) {
    result.components.push("paymaster");
    result.paymaster = modelPaymaster(source);
    addPaymasterDiagnostics(result, filePath, source, limits);
  }
  if (hasFactory) {
    result.components.push("factory");
    addFactoryDiagnostics(result, filePath, source, limits);
  }
  if (hasAggregator) {
    result.components.push("aggregator");
    addAggregatorDiagnostics(result, filePath, source, limits);
  }
  if (/session|module|fallback|upgrade|initialize/.test(lowerSource)) {
    addModuleAndLifecycleDiagnostics(result, filePath, source, limits);
  }

  result.components = [...new Set(result.components)];
  result.diagnostics.sort((left, right) => left.line - right.line || left.code.localeCompare(right.code));
  return result;
}

function normalizeLimits(limits?: Partial<ERC4337AnalysisLimits>): ERC4337AnalysisLimits {
  const candidate = { ...DEFAULT_ERC4337_ANALYSIS_LIMITS, ...limits };
  return {
    maxSourceLength: clamp(candidate.maxSourceLength, 1_000, MAX_SOURCE_LENGTH),
    maxFunctions: clamp(candidate.maxFunctions, 1, 10_000),
    maxDiagnostics: clamp(candidate.maxDiagnostics, 1, 1_000),
    maxEvidenceItems: clamp(candidate.maxEvidenceItems, 1, 32),
  };
}

function clamp(value: number, min: number, max: number): number {
  return Number.isFinite(value) ? Math.min(max, Math.max(min, Math.floor(value))) : min;
}

function resolveVersion(source: string, requested: ERC4337AnalysisOptions["version"]): ERC4337Version {
  if (requested && requested !== "auto") return requested;
  return detectERC4337Version(source);
}

function collectFunctions(source: string, limit: number): { names: string[]; truncated: boolean } {
  const names: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = FUNCTION_PATTERN.exec(source)) !== null) {
    names.push(match[1]);
    if (names.length >= limit) return { names, truncated: true };
  }
  return { names, truncated: false };
}

function modelUserOperation(version: ERC4337Version, source: string, functions: string[]): UserOperationModel {
  const fields: UserOperationField[] = USER_OPERATION_FIELDS.map((name) => ({
    name,
    type: name === "nonce" ? "uint256" : "bytes",
    required: version === "0.6" ? !["factory", "factoryData", "paymaster", "paymasterData"].includes(name) : true,
    hashBound: hashBindsField(source, name),
  }));
  return {
    version,
    fields,
    hasPaymaster: /paymaster|paymasteranddata/i.test(source),
    hasFactory: /factory|initcode/i.test(source),
    hasAggregator: /aggregator|aggregatedsignature/i.test(source),
    hashFunctions: functions.filter((name) => /hash|signature|validate/i.test(name.toLowerCase())),
    nonceFunctions: functions.filter((name) => /nonce|validate|execute/i.test(name.toLowerCase())),
  };
}

function modelValidationData(source: string): ValidationDataModel {
  return {
    hasAuthorizer: /authorizer|validationdata/i.test(source),
    hasTimeRange: /validafter|validuntil|validity|timeRange/i.test(source),
    usesPackedEncoding: /validationdata|abi\.encodepacked|uint48/i.test(source),
    rejectsInvalidAuthorizer: /authorizer\s*==\s*address\(0\)|authorizer\s*!==\s*address\(0\)/i.test(source),
    sourceLine: lineOf(source, /validationdata|authorizer/i),
  };
}

function modelNonce(source: string): NonceModel {
  return {
    hasNonceStorage: /mapping\s*\([^)]*\)\s*(?:public\s*)?nonces?|uint256\s+(?:public\s+)?nonce/i.test(source),
    usesKeyedNonce: /mapping\s*\s*\(\s*uint192\s*=>|nonce\s*>>\s*64|nonce\s*\/\s*2\*\*\s*64/i.test(source),
    incrementsBeforeExecution: /nonce[^;]*(\+\+|\+=\s*1)|\+\+[^;]*nonce/i.test(source),
    validatesNonce: /nonce[^;]*(==|!=|require|revert)|require\s*\([^)]*nonce/i.test(source),
    sourceLine: lineOf(source, /nonce/i),
  };
}

function modelEntryPoint(version: ERC4337Version, source: string): EntryPointModel {
  return {
    version,
    functions: functionNames(source).filter((name) => /handle|simulate|deposit|stake|nonce/i.test(name)),
    bindsChainId: /chainid|block\.chainid/i.test(source),
    bindsEntryPoint: /entrypoint|address\(this\)|msg\.sender/i.test(source),
    validatesSender: /sender|validateuserop|validateaccount/i.test(source),
    hasDepositAccounting: /deposit|withdraw|stake|balance/i.test(source),
    sourceLine: lineOf(source, /entrypoint|handleops/i),
  };
}

function modelPaymaster(source: string): PaymasterModel {
  return {
    hasValidation: /validatepaymasteruserop|validatepaymaster/i.test(source),
    hasPostOp: /postop/i.test(source),
    validatesGasLimits: /verificationgas|postopgas|maxgas|gasleft/i.test(source),
    validatesContext: /context|paymasterdata/i.test(source),
    tracksDeposit: /deposit|withdraw|balance/i.test(source),
    hasSponsorshipLimit: /limit|quota|allowance|budget|sponsor/i.test(source),
    externalContextCalls: /context[^;]*(call|transfer|send)|(?:call|transfer|send)[^;]*context/i.test(source),
    sourceLine: lineOf(source, /paymaster/i),
  };
}

function addUserOperationDiagnostics(result: ERC4337AnalysisResult, filePath: string, source: string, limits: ERC4337AnalysisLimits): void {
  const model = result.userOperation!;
  for (const field of model.fields) {
    if (!field.hashBound && ["sender", "nonce", "callData", "paymasterAndData", "factory"].includes(field.name)) {
      addDiagnostic(result, limits, diagnostic("AA001_HASH_BINDING", "account", result.version, "UserOperation hash omits security-critical field", `The ${field.name} field appears in the UserOperation model but is not visibly bound into the signed hash.`, "Include every operation-defining field in the canonical hash before signature validation.", "high", filePath, lineOf(source, new RegExp(field.name, "i")) ?? 1, [{ path: `UserOperation.${field.name}`, description: "Field is modeled but no matching hash input was found." }], ["The detector relies on recognizable field names and hash construction in source."], "medium"));
    }
  }
  if (!model.nonceFunctions.some((name) => /nonce/i.test(name)) || !result.nonce?.validatesNonce) {
    addDiagnostic(result, limits, diagnostic("AA003_NONCE_REPLAY", "account", result.version, "UserOperation nonce is not clearly validated", "The account exposes UserOperation execution or validation but no bounded nonce validation was identified.", "Validate the nonce against the EntryPoint nonce domain and consume it exactly once before execution.", "high", filePath, result.nonce?.sourceLine ?? 1, [{ path: "account.validateUserOp.nonce", description: "No recognizable nonce comparison or rejection was found." }], ["A custom nonce abstraction may be implemented outside recognizable Solidity expressions."], "low"));
  }
  if (result.validationData && result.validationData.hasTimeRange && !result.validationData.rejectsInvalidAuthorizer) {
    addDiagnostic(result, limits, diagnostic("AA004_VALIDATION_EXECUTION", "account", result.version, "Validation data is not rejected consistently", "Validation data or an authorizer is decoded, but invalid authorization is not clearly rejected before execution.", "Reject failed authorizers and enforce validAfter/validUntil semantics in the EntryPoint validation path.", "high", filePath, result.validationData.sourceLine ?? 1, [{ path: "validationData.authorizer", description: "Time-range or authorizer fields are decoded without a visible invalid-value guard." }], [], "medium"));
  }
}

function addEntryPointDiagnostics(result: ERC4337AnalysisResult, filePath: string, source: string, limits: ERC4337AnalysisLimits): void {
  const model = result.entryPoint!;
  if (!model.bindsChainId) addDiagnostic(result, limits, diagnostic("AA002_ENTRYPOINT_DOMAIN", "entryPoint", result.version, "UserOperation domain omits chain identity", "The EntryPoint/account hash path does not visibly bind the operation to block.chainid.", "Bind the chain ID and canonical EntryPoint address into the UserOperation hash.", "high", filePath, model.sourceLine ?? 1, [{ path: "EntryPoint.getUserOpHash.domain", description: "No chain ID binding was found." }], [], "medium"));
  if (!model.bindsEntryPoint) addDiagnostic(result, limits, diagnostic("AA002_ENTRYPOINT_DOMAIN", "entryPoint", result.version, "UserOperation domain omits EntryPoint identity", "The operation hash path does not visibly bind the canonical EntryPoint address.", "Include the trusted EntryPoint address in the signed domain and reject calls from other EntryPoints.", "high", filePath, model.sourceLine ?? 1, [{ path: "EntryPoint.getUserOpHash.entryPoint", description: "No EntryPoint binding was found." }], [], "medium"));
  if (model.hasDepositAccounting && !/onlyentrypoint|msg\.sender\s*==\s*entrypoint|trustedentrypoint/i.test(source)) addDiagnostic(result, limits, diagnostic("AA007_PAYMASTER_DEPOSIT", "entryPoint", result.version, "Deposit accounting lacks visible EntryPoint authorization", "Deposit or stake accounting is exposed without a recognizable EntryPoint-only access check.", "Restrict deposit, stake, and withdrawal accounting to the canonical EntryPoint and validate beneficiary ownership.", "high", filePath, model.sourceLine ?? 1, [{ path: "EntryPoint.deposit", description: "Deposit accounting exists without a trusted-caller guard." }], [], "low"));
}

function addPaymasterDiagnostics(result: ERC4337AnalysisResult, filePath: string, source: string, limits: ERC4337AnalysisLimits): void {
  const model = result.paymaster!;
  if (model.hasValidation && !model.validatesGasLimits) addDiagnostic(result, limits, diagnostic("AA006_PAYMASTER_LIMIT", "paymaster", result.version, "Paymaster validation omits visible gas-limit checks", "The paymaster validates sponsorship without recognizable verification or post-operation gas-limit validation.", "Validate all sponsored gas limits and bound the maximum liability before returning context.", "high", filePath, model.sourceLine ?? 1, [{ path: "Paymaster.validatePaymasterUserOp.gas", description: "No gas-limit validation was found." }], [], "medium"));
  if (model.hasPostOp && !model.tracksDeposit) addDiagnostic(result, limits, diagnostic("AA007_PAYMASTER_DEPOSIT", "paymaster", result.version, "Paymaster postOp lacks visible deposit accounting", "postOp is implemented but no accounting path ties actual cost or failure handling to the paymaster deposit.", "Charge bounded actual cost, handle postOp failure deterministically, and maintain sufficient EntryPoint deposit.", "high", filePath, model.sourceLine ?? 1, [{ path: "Paymaster.postOp.deposit", description: "postOp exists without recognizable deposit accounting." }], [], "medium"));
  if (model.hasPostOp && model.externalContextCalls) addDiagnostic(result, limits, diagnostic("AA008_PAYMASTER_POSTOP", "paymaster", result.version, "Paymaster postOp performs context-sensitive external work", "postOp uses externally supplied context around an external call, creating a griefing or state-confusion surface.", "Authenticate and length-bound context, isolate external work, and make postOp failure and replay behavior explicit.", "high", filePath, model.sourceLine ?? 1, [{ path: "Paymaster.postOp.context", description: "Context and external call patterns overlap." }], [], "medium"));
  if (model.hasValidation && model.validatesContext && !/calldatasize|length|bytes4|decode/i.test(source)) addDiagnostic(result, limits, diagnostic("AA009_PAYMASTER_CONTEXT", "paymaster", result.version, "Paymaster context is not visibly validated", "The paymaster accepts context from validation without recognizable length, selector, or encoding checks.", "Treat validation context as untrusted data: authenticate its origin, validate its encoding and bounds, and avoid trusting mutable fields in postOp.", "medium", filePath, model.sourceLine ?? 1, [{ path: "Paymaster.context", description: "Context is used without recognizable structural validation." }], [], "low"));
  if (model.hasValidation && !model.hasSponsorshipLimit) addDiagnostic(result, limits, diagnostic("AA006_PAYMASTER_LIMIT", "paymaster", result.version, "Paymaster sponsorship has no visible policy limit", "The paymaster sponsors operations without a recognizable per-user, per-token, or budget limit.", "Bound sponsorship by caller, account, token, time window, and total budget; fail closed when limits are exhausted.", "medium", filePath, model.sourceLine ?? 1, [{ path: "Paymaster.sponsorshipPolicy", description: "No sponsorship quota or budget guard was identified." }], [], "low"));
}

function addFactoryDiagnostics(result: ERC4337AnalysisResult, filePath: string, source: string, limits: ERC4337AnalysisLimits): void {
  if (/create2/i.test(source) && !/keccak256|salt/i.test(source)) addDiagnostic(result, limits, diagnostic("AA011_CREATE2_DERIVATION", "factory", result.version, "CREATE2 account derivation is incomplete", "The factory uses CREATE2 without a recognizable salt or init-code hash derivation path.", "Derive the counterfactual address from deployer, salt, and init-code hash, and verify the deployed account before execution.", "high", filePath, lineOf(source, /create2/i) ?? 1, [{ path: "Factory.getAddress.create2", description: "CREATE2 appears without explicit salt and init-code hashing." }], [], "medium"));
  if (/initialize|initcode|factorydata/i.test(source) && !/onlyfactory|msg\.sender|initialized|initializer/i.test(source)) addDiagnostic(result, limits, diagnostic("AA010_FACTORY_INIT", "factory", result.version, "Counterfactual account initialization lacks visible authorization", "Initialization data or an initializer is exposed without a recognizable one-time or trusted-factory guard.", "Bind initialization to the expected factory or deploy transaction, consume it once, and reject re-initialization.", "high", filePath, lineOf(source, /initialize|initcode|factorydata/i) ?? 1, [{ path: "Factory.initialize", description: "Initialization surface lacks a visible authorization or one-time guard." }], [], "medium"));
}

function addAggregatorDiagnostics(result: ERC4337AnalysisResult, filePath: string, source: string, limits: ERC4337AnalysisLimits): void {
  if (/aggregatedsignature/i.test(source) && !/userop|useroperation/i.test(source)) addDiagnostic(result, limits, diagnostic("AA005_AGGREGATOR_SIGNATURE", "aggregator", result.version, "Aggregated signature is not visibly bound to operations", "An aggregated signature is processed without a recognizable UserOperation association.", "Validate the aggregate against the exact ordered operation set and reject missing, duplicate, or reordered operations.", "high", filePath, lineOf(source, /aggregatedsignature/i) ?? 1, [{ path: "Aggregator.validateSignatures.userOps", description: "Aggregate validation does not visibly consume UserOperations." }], [], "low"));
}

function addModuleAndLifecycleDiagnostics(result: ERC4337AnalysisResult, filePath: string, source: string, limits: ERC4337AnalysisLimits): void {
  const lowerSource = source.toLowerCase();
  if (/session/.test(lowerSource) && !/expiry|validuntil|nonce|revoke|disable/i.test(source)) addDiagnostic(result, limits, diagnostic("AA013_SESSION_KEY", "module", result.version, "Session key has no visible expiry or revocation", "A session-key surface is present without recognizable temporal, nonce, or revocation constraints.", "Bind session keys to a narrow scope, expiry, nonce domain, and explicit revocation path.", "high", filePath, lineOf(source, /session/i) ?? 1, [{ path: "SessionModule.authorize", description: "No expiry, nonce, or revocation control was found." }], [], "low"));
  if (/module/.test(lowerSource) && !/onlyowner|authorized|isolation|allowlist|whitelist|msg\.sender/i.test(source)) addDiagnostic(result, limits, diagnostic("AA012_MODULE_AUTH", "module", result.version, "Module authorization is not visible", "A module or plugin execution surface is present without a recognizable authorization boundary.", "Use an explicit trusted module registry and authenticate module installation, removal, and execution.", "high", filePath, lineOf(source, /module/i) ?? 1, [{ path: "Account.module", description: "Module capability exists without a visible authorization guard." }], [], "low"));
  if (/upgrade/.test(lowerSource) && !/onlyowner|authorized|timelock|accesscontrol|msg\.sender/i.test(source)) addDiagnostic(result, limits, diagnostic("AA014_UPGRADE_AUTH", "account", result.version, "Account upgrade path lacks visible authorization", "An upgrade surface is present without a recognizable owner, role, or timelock check.", "Authorize upgrades with an explicit role or timelock and protect the implementation and initialization state.", "critical", filePath, lineOf(source, /upgrade/i) ?? 1, [{ path: "Account.upgrade", description: "Upgrade function lacks a recognizable authorization boundary." }], [], "low"));
  if (/fallback/.test(lowerSource) && !/msg\.sender|selector|allowlist|authorized/i.test(source)) addDiagnostic(result, limits, diagnostic("AA015_FALLBACK_AUTH", "fallback", result.version, "Fallback dispatch lacks visible authorization", "A fallback or selector dispatch surface is present without recognizable selector or caller restrictions.", "Allowlist selectors, authenticate module calls, and preserve value and calldata isolation in fallback dispatch.", "high", filePath, lineOf(source, /fallback/i) ?? 1, [{ path: "Account.fallback", description: "Fallback dispatch lacks a visible authorization boundary." }], [], "low"));
}

function addDiagnostic(result: ERC4337AnalysisResult, limits: ERC4337AnalysisLimits, value: ERC4337Diagnostic): void {
  if (result.diagnostics.length < limits.maxDiagnostics) result.diagnostics.push({ ...value, evidence: value.evidence.slice(0, limits.maxEvidenceItems) });
  else result.truncated = true;
}

function diagnostic(code: ERC4337DiagnosticCode, component: ERC4337Component, version: ERC4337Version, title: string, description: string, recommendation: string, severity: ERC4337Diagnostic["severity"], file: string, line: number, evidence: ERC4337Evidence[], assumptions: string[], confidence: ERC4337Diagnostic["confidence"]): ERC4337Diagnostic {
  return { code, component, version, title, description, recommendation, severity, file, line: Math.max(1, line), evidence, assumptions, confidence };
}

function toFindings(result: ERC4337AnalysisResult, source: string): Finding[] {
  return result.diagnostics.map((diagnostic) => ({
    id: `CP-4337-${diagnostic.code.slice(6)}`,
    title: diagnostic.title,
    description: diagnostic.description,
    recommendation: diagnostic.recommendation,
    severity: diagnostic.severity,
    file: diagnostic.file,
    line: diagnostic.line,
    snippet: source.split("\n")[diagnostic.line - 1]?.trim(),
    evidence: diagnostic.evidence.map((item) => ({ description: `${item.path}: ${item.description}`, file: diagnostic.file, line: item.line ?? diagnostic.line })),
    assumptions: diagnostic.assumptions,
    confidence: diagnostic.confidence,
  }));
}

function functionNames(source: string): string[] { return collectFunctions(source, DEFAULT_ERC4337_ANALYSIS_LIMITS.maxFunctions).names; }
function hashBindsField(source: string, field: string): boolean { return [...source.matchAll(HASH_CALL_PATTERN)].some((match) => match[1].toLowerCase().includes(field.toLowerCase())); }
function lineOf(source: string, pattern: RegExp): number | undefined { const index = source.search(pattern); return index < 0 ? undefined : source.slice(0, index).split("\n").length; }
