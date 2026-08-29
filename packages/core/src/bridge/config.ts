import * as fs from "fs";
import {
  BRIDGE_CONFIG_SCHEMA_VERSION,
  type BridgeAnalysisConfigInput,
  type BridgeAnalysisConfigV1,
  type BridgeAnalysisLimits,
  type BridgeDiagnostic,
  type BridgeRuleId,
  type ValidatedBridgeConfig,
} from "./types";

export const DEFAULT_BRIDGE_LIMITS: Readonly<BridgeAnalysisLimits> = Object.freeze({
  maxSourceBytes: 2 * 1024 * 1024,
  maxFiles: 256,
  maxContracts: 128,
  maxFunctionsPerFile: 512,
  maxFunctionsPerContract: 512,
  maxOperationsPerFunction: 2048,
  maxFindings: 1024,
  maxEvidencePerFinding: 12,
});

const RULE_IDS = new Set<string>(Array.from({ length: 16 }, (_, index) =>
  `CP-BRG-${String(index + 1).padStart(3, "0")}`,
));

const LIMIT_KEYS: Array<keyof BridgeAnalysisLimits> = [
  "maxSourceBytes",
  "maxFiles",
  "maxContracts",
  "maxFunctionsPerFile",
  "maxFunctionsPerContract",
  "maxOperationsPerFunction",
  "maxFindings",
  "maxEvidencePerFinding",
];

export class BridgeConfigError extends Error {
  readonly code = "BRG_CONFIG_INVALID";

  constructor(message: string) {
    super(message);
    this.name = "BridgeConfigError";
  }
}

export class BridgeAnalysisCancelledError extends Error {
  readonly code = "BRG_CANCELLED";

  constructor() {
    super("Bridge safety analysis was cancelled");
    this.name = "BridgeAnalysisCancelledError";
  }
}

export function resolveBridgeLimits(
  input?: Partial<BridgeAnalysisLimits>,
): BridgeAnalysisLimits {
  if (input !== undefined && !isRecord(input)) {
    throw new BridgeConfigError("limits must be an object");
  }
  const result: BridgeAnalysisLimits = { ...DEFAULT_BRIDGE_LIMITS };
  for (const key of LIMIT_KEYS) {
    const value = input?.[key];
    if (value === undefined) continue;
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new BridgeConfigError(`${key} must be a positive safe integer`);
    }
    result[key] = value;
  }
  return result;
}

export function migrateBridgeConfig(
  input: BridgeAnalysisConfigInput,
): ValidatedBridgeConfig {
  if (!isRecord(input)) throw new BridgeConfigError("configuration root must be an object");
  if (input.schemaVersion === BRIDGE_CONFIG_SCHEMA_VERSION) return validateV1(input);
  if (input.schemaVersion !== undefined && input.schemaVersion !== 0) {
    throw new BridgeConfigError(
      `unsupported bridge configuration schemaVersion ${String(input.schemaVersion)}`,
    );
  }
  rejectUnknownKeys(input, [
    "schemaVersion", "version", "maxFileSize", "maxIssues", "detectors", "includeModels",
  ], "configuration");

  const limits: Partial<BridgeAnalysisLimits> = {};
  if (input.maxFileSize !== undefined) {
    limits.maxSourceBytes = positiveInteger(input.maxFileSize, "maxFileSize");
  }
  if (input.maxIssues !== undefined) {
    limits.maxFindings = positiveInteger(input.maxIssues, "maxIssues");
  }
  const includeRules = input.detectors === undefined
    ? undefined
    : validateRules(input.detectors, "detectors");
  const migrated = input.version === 0 || input.maxFileSize !== undefined ||
    input.maxIssues !== undefined || input.detectors !== undefined;
  const diagnostics: BridgeDiagnostic[] = migrated ? [{
    code: "BRG_CONFIG_INVALID",
    severity: "info",
    message: "Migrated bridge configuration from legacy schema v0 to v1",
  }] : [];

  const config: BridgeAnalysisConfigV1 = {
    schemaVersion: BRIDGE_CONFIG_SCHEMA_VERSION,
    ...(Object.keys(limits).length ? { limits } : {}),
    ...(typeof input.includeModels === "boolean" ? { includeModels: input.includeModels } : {}),
    ...(includeRules ? { includeRules } : {}),
  };
  resolveBridgeLimits(config.limits);
  return { config, diagnostics };
}

export function validateBridgeConfig(
  input: BridgeAnalysisConfigInput,
): ValidatedBridgeConfig {
  return migrateBridgeConfig(input);
}

export function loadBridgeConfigFile(filePath: string): ValidatedBridgeConfig {
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    throw new BridgeConfigError(`configuration file could not be read (${errorCode(error)})`);
  }
  try {
    return validateBridgeConfig(JSON.parse(content) as BridgeAnalysisConfigInput);
  } catch (error) {
    if (error instanceof BridgeConfigError) throw error;
    throw new BridgeConfigError("configuration file contains invalid JSON");
  }
}

function validateV1(input: Record<string, unknown>): ValidatedBridgeConfig {
  rejectUnknownKeys(input, [
    "schemaVersion", "limits", "includeModels", "includeRules", "excludeRules",
  ], "configuration");
  if (input.includeModels !== undefined && typeof input.includeModels !== "boolean") {
    throw new BridgeConfigError("includeModels must be a boolean");
  }
  const limits = input.limits === undefined ? undefined : validateLimits(input.limits);
  const includeRules = input.includeRules === undefined
    ? undefined
    : validateRules(input.includeRules, "includeRules");
  const excludeRules = input.excludeRules === undefined
    ? undefined
    : validateRules(input.excludeRules, "excludeRules");
  if (includeRules && excludeRules) {
    const overlap = includeRules.filter((rule) => excludeRules.includes(rule));
    if (overlap.length) {
      throw new BridgeConfigError(`includeRules and excludeRules overlap: ${overlap.join(", ")}`);
    }
  }
  return {
    config: {
      schemaVersion: BRIDGE_CONFIG_SCHEMA_VERSION,
      ...(limits ? { limits } : {}),
      ...(typeof input.includeModels === "boolean" ? { includeModels: input.includeModels } : {}),
      ...(includeRules ? { includeRules } : {}),
      ...(excludeRules ? { excludeRules } : {}),
    },
    diagnostics: [],
  };
}

function validateLimits(value: unknown): Partial<BridgeAnalysisLimits> {
  if (!isRecord(value)) throw new BridgeConfigError("limits must be an object");
  rejectUnknownKeys(value, LIMIT_KEYS, "limits");
  const limits: Partial<BridgeAnalysisLimits> = {};
  for (const key of LIMIT_KEYS) {
    if (value[key] !== undefined) limits[key] = positiveInteger(value[key], key);
  }
  resolveBridgeLimits(limits);
  return limits;
}

function validateRules(value: unknown, field: string): BridgeRuleId[] {
  if (!Array.isArray(value)) throw new BridgeConfigError(`${field} must be an array`);
  const result = new Set<BridgeRuleId>();
  for (const rule of value) {
    if (typeof rule !== "string" || !RULE_IDS.has(rule)) {
      throw new BridgeConfigError(`${field} contains unknown rule ${String(rule)}`);
    }
    result.add(rule as BridgeRuleId);
  }
  return [...result].sort();
}

function positiveInteger(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new BridgeConfigError(`${field} must be a positive safe integer`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && /^[A-Z0-9_]+$/.test(code) ? code : "IO_ERROR";
}

function rejectUnknownKeys(
  value: Record<string, unknown>,
  allowed: readonly (string | number | symbol)[],
  field: string,
): void {
  const permitted = new Set(allowed.map(String));
  const unknown = Object.keys(value).filter((key) => !permitted.has(key)).sort();
  if (unknown.length) throw new BridgeConfigError(`${field} contains unknown field ${unknown[0]}`);
}
