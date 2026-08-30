import {
  AMM_CONFIG_SCHEMA_VERSION,
  type AmmAnalysisConfigInput,
  type AmmAnalysisConfigV1,
  type AmmAnalysisLimits,
  type AmmDiagnostic,
  type AmmRuleId,
  type ValidatedAmmConfig,
} from "./types";
import * as fs from "fs";

export const DEFAULT_AMM_LIMITS: Readonly<AmmAnalysisLimits> = Object.freeze({
  maxSourceBytes: 2 * 1024 * 1024,
  maxFiles: 128,
  maxContracts: 64,
  maxFunctionsPerFile: 256,
  maxFunctionsPerContract: 256,
  maxOperationsPerFunction: 1024,
  maxFindings: 512,
  maxEvidencePerFinding: 8,
});

const RULE_IDS: ReadonlySet<string> = new Set([
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
]);

const LIMIT_KEYS: Array<keyof AmmAnalysisLimits> = [
  "maxSourceBytes",
  "maxFiles",
  "maxContracts",
  "maxFunctionsPerFile",
  "maxFunctionsPerContract",
  "maxOperationsPerFunction",
  "maxFindings",
  "maxEvidencePerFinding",
];

export class AmmConfigError extends Error {
  readonly code = "AMM_CONFIG_INVALID";
  constructor(message: string) {
    super(message);
    this.name = "AmmConfigError";
  }
}

export class AmmAnalysisCancelledError extends Error {
  readonly code = "AMM_CANCELLED";
  constructor() {
    super("AMM analysis was cancelled");
    this.name = "AmmAnalysisCancelledError";
  }
}

export function resolveAmmLimits(input?: Partial<AmmAnalysisLimits>): AmmAnalysisLimits {
  if (input !== undefined && !isRecord(input)) {
    throw new AmmConfigError("limits must be an object");
  }

  const result: AmmAnalysisLimits = { ...DEFAULT_AMM_LIMITS };
  for (const key of LIMIT_KEYS) {
    const value = input?.[key];
    if (value === undefined) continue;
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new AmmConfigError(`${key} must be a positive safe integer`);
    }
    result[key] = value;
  }
  return result;
}

export function migrateAmmConfig(input: AmmAnalysisConfigInput): ValidatedAmmConfig {
  if (!isRecord(input)) {
    throw new AmmConfigError("configuration root must be an object");
  }

  if (input.schemaVersion === AMM_CONFIG_SCHEMA_VERSION) {
    return validateV1(input);
  }

  if (input.schemaVersion !== undefined && input.schemaVersion !== 0) {
    throw new AmmConfigError(`unsupported AMM configuration schemaVersion ${String(input.schemaVersion)}`);
  }

  const diagnostics: AmmDiagnostic[] = [];
  const limits: Partial<AmmAnalysisLimits> = {};
  if (input.maxFileSize !== undefined) {
    limits.maxSourceBytes = asPositiveInteger(input.maxFileSize, "maxFileSize");
  }
  if (input.maxIssues !== undefined) {
    limits.maxFindings = asPositiveInteger(input.maxIssues, "maxIssues");
  }

  const includeRules = input.rules === undefined ? undefined : validateRuleList(input.rules, "rules");
  if (input.version === 0 || input.maxFileSize !== undefined || input.maxIssues !== undefined || input.rules !== undefined) {
    diagnostics.push({
      code: "AMM_CONFIG_INVALID",
      severity: "info",
      message: "Migrated AMM configuration from legacy schema v0 to v1",
    });
  }

  const config: AmmAnalysisConfigV1 = {
    schemaVersion: AMM_CONFIG_SCHEMA_VERSION,
    ...(Object.keys(limits).length > 0 ? { limits } : {}),
    ...(typeof input.includeModels === "boolean" ? { includeModels: input.includeModels } : {}),
    ...(includeRules ? { includeRules } : {}),
  };
  resolveAmmLimits(config.limits);
  return { config, diagnostics };
}

export function validateAmmConfig(input: AmmAnalysisConfigInput): ValidatedAmmConfig {
  return migrateAmmConfig(input);
}

export function loadAmmConfigFile(filePath: string): ValidatedAmmConfig {
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    throw new AmmConfigError(`configuration file could not be read (${errorCode(error)})`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new AmmConfigError("configuration file contains invalid JSON");
  }

  return validateAmmConfig(parsed as AmmAnalysisConfigInput);
}

function validateV1(input: Record<string, unknown>): ValidatedAmmConfig {
  if (input.includeModels !== undefined && typeof input.includeModels !== "boolean") {
    throw new AmmConfigError("includeModels must be a boolean");
  }

  const limits = input.limits === undefined ? undefined : validateLimitsObject(input.limits);
  const includeRules = input.includeRules === undefined ? undefined : validateRuleList(input.includeRules, "includeRules");
  const excludeRules = input.excludeRules === undefined ? undefined : validateRuleList(input.excludeRules, "excludeRules");

  if (includeRules && excludeRules) {
    const overlap = includeRules.filter((rule) => excludeRules.includes(rule));
    if (overlap.length > 0) {
      throw new AmmConfigError(`includeRules and excludeRules overlap: ${overlap.join(", ")}`);
    }
  }

  return {
    config: {
      schemaVersion: AMM_CONFIG_SCHEMA_VERSION,
      ...(limits ? { limits } : {}),
      ...(typeof input.includeModels === "boolean" ? { includeModels: input.includeModels } : {}),
      ...(includeRules ? { includeRules } : {}),
      ...(excludeRules ? { excludeRules } : {}),
    },
    diagnostics: [],
  };
}

function validateLimitsObject(value: unknown): Partial<AmmAnalysisLimits> {
  if (!isRecord(value)) {
    throw new AmmConfigError("limits must be an object");
  }

  const result: Partial<AmmAnalysisLimits> = {};
  for (const key of LIMIT_KEYS) {
    const current = value[key];
    if (current !== undefined) {
      result[key] = asPositiveInteger(current, key);
    }
  }
  return result;
}

function validateRuleList(value: unknown, fieldName: string): AmmRuleId[] {
  if (!Array.isArray(value)) {
    throw new AmmConfigError(`${fieldName} must be an array of rule ids`);
  }

  const output: AmmRuleId[] = [];
  for (const item of value) {
    if (typeof item !== "string" || !RULE_IDS.has(item)) {
      throw new AmmConfigError(`${fieldName} contains an unsupported rule id: ${String(item)}`);
    }
    output.push(item as AmmRuleId);
  }
  return output;
}

function asPositiveInteger(value: unknown, fieldName: string): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new AmmConfigError(`${fieldName} must be a positive safe integer`);
  }
  return Number(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorCode(error: unknown): string {
  return error instanceof Error && error.message ? error.message : "unknown error";
}
