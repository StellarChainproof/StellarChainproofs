import * as fs from "fs";
import {
  DEFAULT_LENDING_LIMITS,
  LENDING_CONFIG_SCHEMA_VERSION,
  type LendingAnalysisConfigInput,
  type LendingAnalysisConfigV1,
  type LendingAnalysisLimits,
  type LendingDiagnostic,
  type LendingRuleId,
  type ValidatedLendingConfig,
} from "./types";

const RULE_IDS: ReadonlySet<string> = new Set([
  "CP-LND-001",
  "CP-LND-002",
  "CP-LND-003",
  "CP-LND-004",
  "CP-LND-005",
  "CP-LND-006",
  "CP-LND-007",
  "CP-LND-008",
  "CP-LND-009",
  "CP-LND-010",
  "CP-LND-011",
  "CP-LND-012",
  "CP-LND-013",
  "CP-LND-014",
  "CP-LND-015",
  "CP-LND-016",
  "CP-LND-017",
  "CP-LND-018",
  "CP-LND-019",
  "CP-LND-020",
]);

const LIMIT_KEYS: Array<keyof LendingAnalysisLimits> = [
  "maxSourceBytes",
  "maxFiles",
  "maxContracts",
  "maxFunctionsPerFile",
  "maxFunctionsPerContract",
  "maxOperationsPerFunction",
  "maxFindings",
  "maxEvidencePerFinding",
];

export class LendingConfigError extends Error {
  readonly code = "LND_CONFIG_INVALID";
  constructor(message: string) {
    super(message);
    this.name = "LendingConfigError";
  }
}

export class LendingAnalysisCancelledError extends Error {
  readonly code = "LND_CANCELLED";
  constructor() {
    super("Lending analysis was cancelled");
    this.name = "LendingAnalysisCancelledError";
  }
}

export function resolveLendingLimits(input?: Partial<LendingAnalysisLimits>): LendingAnalysisLimits {
  if (input !== undefined && !isRecord(input)) {
    throw new LendingConfigError("limits must be an object");
  }
  const result: LendingAnalysisLimits = { ...DEFAULT_LENDING_LIMITS };
  for (const key of LIMIT_KEYS) {
    const value = input?.[key];
    if (value === undefined) continue;
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new LendingConfigError(`${key} must be a positive safe integer`);
    }
    result[key] = value;
  }
  return result;
}

export function migrateLendingConfig(input: LendingAnalysisConfigInput): ValidatedLendingConfig {
  if (!isRecord(input)) {
    throw new LendingConfigError("configuration root must be an object");
  }
  if (input.schemaVersion === LENDING_CONFIG_SCHEMA_VERSION) {
    return validateV1(input);
  }
  if (input.schemaVersion !== undefined && input.schemaVersion !== 0) {
    throw new LendingConfigError(`unsupported lending configuration schemaVersion ${String(input.schemaVersion)}`);
  }
  const diagnostics: LendingDiagnostic[] = [];
  const limits: Partial<LendingAnalysisLimits> = {};
  if (input.maxFileSize !== undefined) limits.maxSourceBytes = asPositiveInteger(input.maxFileSize, "maxFileSize");
  if (input.maxIssues !== undefined) limits.maxFindings = asPositiveInteger(input.maxIssues, "maxIssues");
  const includeRules = input.rules === undefined ? undefined : validateRuleList(input.rules, "rules");
  if (input.version === 0 || input.maxFileSize !== undefined || input.maxIssues !== undefined || input.rules !== undefined) {
    diagnostics.push({
      code: "LND_CONFIG_INVALID",
      severity: "info",
      message: "Migrated lending configuration from legacy schema v0 to v1",
    });
  }
  const config: LendingAnalysisConfigV1 = {
    schemaVersion: LENDING_CONFIG_SCHEMA_VERSION,
    ...(Object.keys(limits).length > 0 ? { limits } : {}),
    ...(typeof input.includeModels === "boolean" ? { includeModels: input.includeModels } : {}),
    ...(includeRules ? { includeRules } : {}),
  };
  resolveLendingLimits(config.limits);
  return { config, diagnostics };
}

export function validateLendingConfig(input: LendingAnalysisConfigInput): ValidatedLendingConfig {
  return migrateLendingConfig(input);
}

export function loadLendingConfigFile(filePath: string): ValidatedLendingConfig {
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    throw new LendingConfigError(`configuration file could not be read (${errorCode(error)})`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new LendingConfigError("configuration file contains invalid JSON");
  }
  return validateLendingConfig(parsed as LendingAnalysisConfigInput);
}

function validateV1(input: Record<string, unknown>): ValidatedLendingConfig {
  if (input.includeModels !== undefined && typeof input.includeModels !== "boolean") {
    throw new LendingConfigError("includeModels must be a boolean");
  }
  const limits = input.limits === undefined ? undefined : validateLimitsObject(input.limits);
  const includeRules = input.includeRules === undefined ? undefined : validateRuleList(input.includeRules, "includeRules");
  const excludeRules = input.excludeRules === undefined ? undefined : validateRuleList(input.excludeRules, "excludeRules");
  if (includeRules && excludeRules) {
    const overlap = includeRules.filter((rule) => excludeRules.includes(rule));
    if (overlap.length > 0) {
      throw new LendingConfigError(`includeRules and excludeRules overlap: ${overlap.join(", ")}`);
    }
  }
  return {
    config: {
      schemaVersion: LENDING_CONFIG_SCHEMA_VERSION,
      ...(limits ? { limits } : {}),
      ...(typeof input.includeModels === "boolean" ? { includeModels: input.includeModels } : {}),
      ...(includeRules ? { includeRules } : {}),
      ...(excludeRules ? { excludeRules } : {}),
    },
    diagnostics: [],
  };
}

function validateLimitsObject(value: unknown): Partial<LendingAnalysisLimits> {
  if (!isRecord(value)) throw new LendingConfigError("limits must be an object");
  const result: Partial<LendingAnalysisLimits> = {};
  for (const key of LIMIT_KEYS) {
    if (value[key] !== undefined) {
      result[key] = asPositiveInteger(value[key], `limits.${key}`);
    }
  }
  return result;
}

function validateRuleList(value: unknown, field: string): LendingRuleId[] {
  if (!Array.isArray(value)) throw new LendingConfigError(`${field} must be an array`);
  const result: LendingRuleId[] = [];
  for (const item of value) {
    if (typeof item !== "string") throw new LendingConfigError(`${field} entries must be strings`);
    if (!RULE_IDS.has(item)) throw new LendingConfigError(`Unknown lending rule id: ${item}`);
    result.push(item as LendingRuleId);
  }
  return result;
}

function asPositiveInteger(value: unknown, field: string): number {
  if (!Number.isInteger(value) || Number(value) <= 0) {
    throw new LendingConfigError(`${field} must be a positive integer`);
  }
  return Number(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorCode(error: unknown): string {
  return error instanceof Error && "code" in error ? String((error as { code?: unknown }).code) : "unknown";
}
