import * as fs from "fs";
import {
  RETURNDATA_CONFIG_SCHEMA_VERSION,
  type ReturndataAnalysisConfigInput,
  type ReturndataAnalysisConfigV1,
  type ReturndataAnalysisLimits,
  type ReturndataDiagnostic,
  type ReturndataRuleId,
  type ValidatedReturndataConfig,
} from "./types";

export const DEFAULT_RETURNDATA_LIMITS: Readonly<ReturndataAnalysisLimits> = Object.freeze({
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
  `CP-RTD-${String(index + 1).padStart(3, "0")}`,
));

const LIMIT_KEYS: Array<keyof ReturndataAnalysisLimits> = [
  "maxSourceBytes",
  "maxFiles",
  "maxContracts",
  "maxFunctionsPerFile",
  "maxFunctionsPerContract",
  "maxOperationsPerFunction",
  "maxFindings",
  "maxEvidencePerFinding",
];

export class ReturndataConfigError extends Error {
  readonly code = "RTD_CONFIG_INVALID";

  constructor(message: string) {
    super(message);
    this.name = "ReturndataConfigError";
  }
}

export class ReturndataAnalysisCancelledError extends Error {
  readonly code = "RTD_CANCELLED";

  constructor() {
    super("Returndata safety analysis was cancelled");
    this.name = "ReturndataAnalysisCancelledError";
  }
}

export function resolveReturndataLimits(
  input?: Partial<ReturndataAnalysisLimits>,
): ReturndataAnalysisLimits {
  if (input !== undefined && !isRecord(input)) {
    throw new ReturndataConfigError("limits must be an object");
  }
  const result: ReturndataAnalysisLimits = { ...DEFAULT_RETURNDATA_LIMITS };
  for (const key of LIMIT_KEYS) {
    const value = input?.[key];
    if (value === undefined) continue;
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new ReturndataConfigError(`${key} must be a positive safe integer`);
    }
    result[key] = value;
  }
  return result;
}

export function migrateReturndataConfig(
  input: ReturndataAnalysisConfigInput,
): ValidatedReturndataConfig {
  if (!isRecord(input)) throw new ReturndataConfigError("configuration root must be an object");
  if (input.schemaVersion === RETURNDATA_CONFIG_SCHEMA_VERSION) return validateV1(input);
  if (input.schemaVersion !== undefined && input.schemaVersion !== 0) {
    throw new ReturndataConfigError(
      `unsupported returndata configuration schemaVersion ${String(input.schemaVersion)}`,
    );
  }
  rejectUnknownKeys(input, [
    "schemaVersion", "version", "maxFileSize", "maxIssues", "detectors", "includeModels",
  ], "configuration");

  const limits: Partial<ReturndataAnalysisLimits> = {};
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
  const diagnostics: ReturndataDiagnostic[] = migrated ? [{
    code: "RTD_CONFIG_INVALID",
    severity: "info",
    message: "Migrated returndata configuration from legacy schema v0 to v1",
  }] : [];

  const config: ReturndataAnalysisConfigV1 = {
    schemaVersion: RETURNDATA_CONFIG_SCHEMA_VERSION,
    ...(Object.keys(limits).length ? { limits } : {}),
    ...(typeof input.includeModels === "boolean" ? { includeModels: input.includeModels } : {}),
    ...(includeRules ? { includeRules } : {}),
  };
  resolveReturndataLimits(config.limits);
  return { config, diagnostics };
}

export function validateReturndataConfig(
  input: ReturndataAnalysisConfigInput,
): ValidatedReturndataConfig {
  return migrateReturndataConfig(input);
}

export function loadReturndataConfigFile(filePath: string): ValidatedReturndataConfig {
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    throw new ReturndataConfigError(`configuration file could not be read (${errorCode(error)})`);
  }
  try {
    return validateReturndataConfig(JSON.parse(content) as ReturndataAnalysisConfigInput);
  } catch (error) {
    if (error instanceof ReturndataConfigError) throw error;
    throw new ReturndataConfigError("configuration file contains invalid JSON");
  }
}

function validateV1(input: Record<string, unknown>): ValidatedReturndataConfig {
  rejectUnknownKeys(input, [
    "schemaVersion", "limits", "includeModels", "includeRules", "excludeRules",
  ], "configuration");
  if (input.includeModels !== undefined && typeof input.includeModels !== "boolean") {
    throw new ReturndataConfigError("includeModels must be a boolean");
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
      throw new ReturndataConfigError(`includeRules and excludeRules overlap: ${overlap.join(", ")}`);
    }
  }
  return {
    config: {
      schemaVersion: RETURNDATA_CONFIG_SCHEMA_VERSION,
      ...(limits ? { limits } : {}),
      ...(typeof input.includeModels === "boolean" ? { includeModels: input.includeModels } : {}),
      ...(includeRules ? { includeRules } : {}),
      ...(excludeRules ? { excludeRules } : {}),
    },
    diagnostics: [],
  };
}

function validateLimits(value: unknown): Partial<ReturndataAnalysisLimits> {
  if (!isRecord(value)) throw new ReturndataConfigError("limits must be an object");
  rejectUnknownKeys(value, LIMIT_KEYS, "limits");
  const limits: Partial<ReturndataAnalysisLimits> = {};
  for (const key of LIMIT_KEYS) {
    if (value[key] !== undefined) limits[key] = positiveInteger(value[key], key);
  }
  resolveReturndataLimits(limits);
  return limits;
}

function validateRules(value: unknown, field: string): ReturndataRuleId[] {
  if (!Array.isArray(value)) throw new ReturndataConfigError(`${field} must be an array`);
  const result = new Set<ReturndataRuleId>();
  for (const rule of value) {
    if (typeof rule !== "string" || !RULE_IDS.has(rule)) {
      throw new ReturndataConfigError(`${field} contains unknown rule ${String(rule)}`);
    }
    result.add(rule as ReturndataRuleId);
  }
  return [...result].sort();
}

function positiveInteger(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new ReturndataConfigError(`${field} must be a positive safe integer`);
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
  if (unknown.length) throw new ReturndataConfigError(`${field} contains unknown field ${unknown[0]}`);
}
