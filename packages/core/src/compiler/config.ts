/**
 * @packageDocumentation
 * @chainproof/core — Compiler Matrix Configuration, Validation & Migration
 */

import * as fs from "fs";
import type {
  CompilerMatrixConfigV0,
  CompilerMatrixConfigV1,
  ValidatedCompilerConfig,
  CompilerAnalysisLimits,
  CompilerRuleId,
} from "./types";
import { COMPILER_CONFIG_SCHEMA_VERSION } from "./types";
import { EVM_VERSIONS } from "./matrix";
import { parseSemVer } from "./semver";

export class CompilerConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CompilerConfigError";
  }
}

export const DEFAULT_COMPILER_LIMITS: CompilerAnalysisLimits = {
  maxFiles: 100,
  maxSourceBytes: 500_000,
  maxContracts: 50,
  maxVersionsToTest: 12,
  timeoutMs: 30_000,
  maxFindings: 500,
};

const VALID_RULES: Set<CompilerRuleId> = new Set([
  "CP-SOL-001",
  "CP-SOL-002",
  "CP-SOL-003",
  "CP-SOL-004",
  "CP-SOL-005",
  "CP-SOL-006",
  "CP-SOL-007",
  "CP-SOL-008",
  "CP-SOL-009",
  "CP-SOL-010",
]);

function assertPositiveInteger(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new CompilerConfigError(`Configuration field "${name}" must be a positive integer.`);
  }
  return value;
}

/**
 * Validates and normalizes raw configuration input.
 */
export function validateCompilerConfig(raw: unknown): ValidatedCompilerConfig {
  if (!raw || typeof raw !== "object") {
    throw new CompilerConfigError("Configuration must be a non-null object.");
  }

  const input = raw as Record<string, any>;

  // Check version
  const version = input.version !== undefined ? input.version : 1;
  if (version !== 1 && version !== 0) {
    throw new CompilerConfigError(
      `Unsupported configuration version: ${version}. Expected version ${COMPILER_CONFIG_SCHEMA_VERSION}.`,
    );
  }

  if (version === 0) {
    return migrateCompilerConfig(raw as CompilerMatrixConfigV0);
  }

  const v1 = input as CompilerMatrixConfigV1;

  // Validate EVM version
  const defaultEvmVersion = v1.defaultEvmVersion || "paris";
  if (v1.defaultEvmVersion && !EVM_VERSIONS.includes(v1.defaultEvmVersion as any)) {
    throw new CompilerConfigError(
      `Invalid defaultEvmVersion "${v1.defaultEvmVersion}". Supported EVM versions: ${EVM_VERSIONS.join(", ")}`,
    );
  }

  // Validate target versions
  const targetVersions: string[] = [];
  if (v1.targetVersions) {
    if (!Array.isArray(v1.targetVersions)) {
      throw new CompilerConfigError("targetVersions must be an array of version strings.");
    }
    for (const ver of v1.targetVersions) {
      if (typeof ver !== "string" || !parseSemVer(ver)) {
        throw new CompilerConfigError(`Invalid target compiler version "${ver}".`);
      }
      targetVersions.push(ver);
    }
  }

  // Validate compare versions
  let compareVersions: [string, string] | undefined;
  if (v1.compareVersions) {
    if (!Array.isArray(v1.compareVersions) || v1.compareVersions.length !== 2) {
      throw new CompilerConfigError("compareVersions must be a 2-element array [baseVersion, targetVersion].");
    }
    if (!parseSemVer(v1.compareVersions[0]) || !parseSemVer(v1.compareVersions[1])) {
      throw new CompilerConfigError("compareVersions contains invalid SemVer versions.");
    }
    compareVersions = [v1.compareVersions[0], v1.compareVersions[1]];
  }

  // Validate rules
  let includeRules: CompilerRuleId[] | undefined;
  if (v1.includeRules) {
    if (!Array.isArray(v1.includeRules)) {
      throw new CompilerConfigError("includeRules must be an array of rule IDs.");
    }
    for (const r of v1.includeRules) {
      if (!VALID_RULES.has(r)) {
        throw new CompilerConfigError(`Unknown rule ID in includeRules: "${r}".`);
      }
    }
    includeRules = [...v1.includeRules];
  }

  let excludeRules: CompilerRuleId[] | undefined;
  if (v1.excludeRules) {
    if (!Array.isArray(v1.excludeRules)) {
      throw new CompilerConfigError("excludeRules must be an array of rule IDs.");
    }
    for (const r of v1.excludeRules) {
      if (!VALID_RULES.has(r)) {
        throw new CompilerConfigError(`Unknown rule ID in excludeRules: "${r}".`);
      }
    }
    excludeRules = [...v1.excludeRules];
  }

  // Reject overlap between includeRules and excludeRules
  if (includeRules && excludeRules) {
    const overlap = includeRules.filter((r) => excludeRules!.includes(r));
    if (overlap.length > 0) {
      throw new CompilerConfigError(
        `includeRules and excludeRules cannot overlap. Overlapping rules: ${overlap.join(", ")}`,
      );
    }
  }

  // Validate limits
  const limits: CompilerAnalysisLimits = {
    maxFiles: v1.limits?.maxFiles !== undefined ? assertPositiveInteger(v1.limits.maxFiles, "limits.maxFiles") : DEFAULT_COMPILER_LIMITS.maxFiles,
    maxSourceBytes: v1.limits?.maxSourceBytes !== undefined ? assertPositiveInteger(v1.limits.maxSourceBytes, "limits.maxSourceBytes") : DEFAULT_COMPILER_LIMITS.maxSourceBytes,
    maxContracts: v1.limits?.maxContracts !== undefined ? assertPositiveInteger(v1.limits.maxContracts, "limits.maxContracts") : DEFAULT_COMPILER_LIMITS.maxContracts,
    maxVersionsToTest: v1.limits?.maxVersionsToTest !== undefined ? assertPositiveInteger(v1.limits.maxVersionsToTest, "limits.maxVersionsToTest") : DEFAULT_COMPILER_LIMITS.maxVersionsToTest,
    timeoutMs: v1.limits?.timeoutMs !== undefined ? assertPositiveInteger(v1.limits.timeoutMs, "limits.timeoutMs") : DEFAULT_COMPILER_LIMITS.timeoutMs,
    maxFindings: v1.limits?.maxFindings !== undefined ? assertPositiveInteger(v1.limits.maxFindings, "limits.maxFindings") : DEFAULT_COMPILER_LIMITS.maxFindings,
  };

  const optimizer = {
    enabled: v1.optimizer?.enabled ?? true,
    runs: v1.optimizer?.runs ? assertPositiveInteger(v1.optimizer.runs, "optimizer.runs") : 200,
    viaIR: v1.optimizer?.viaIR ?? false,
  };

  return {
    version: 1,
    defaultEvmVersion,
    targetVersions,
    compareVersions,
    optimizer,
    includeRules,
    excludeRules,
    allowedHazards: Array.isArray(v1.allowedHazards) ? v1.allowedHazards : [],
    limits,
    sandboxed: v1.sandboxed ?? true,
    compilerBinaryPath: v1.compilerBinaryPath,
    compilerCacheDir: v1.compilerCacheDir,
  };
}

/**
 * Migrates legacy v0 configuration to v1 schema.
 */
export function migrateCompilerConfig(v0: CompilerMatrixConfigV0): ValidatedCompilerConfig {
  const targetVersions = Array.isArray(v0.solcVersions) ? v0.solcVersions : [];
  const limits: CompilerAnalysisLimits = {
    ...DEFAULT_COMPILER_LIMITS,
    ...(v0.maxFiles ? { maxFiles: assertPositiveInteger(v0.maxFiles, "maxFiles") } : {}),
    ...(v0.maxSourceSize ? { maxSourceBytes: assertPositiveInteger(v0.maxSourceSize, "maxSourceSize") } : {}),
  };

  return {
    version: 1,
    defaultEvmVersion: v0.evmVersion || "paris",
    targetVersions,
    optimizer: {
      enabled: v0.optimizer ?? true,
      runs: v0.optimizerRuns ?? 200,
      viaIR: false,
    },
    allowedHazards: [],
    limits,
    sandboxed: true,
  };
}

/**
 * Loads and validates a JSON configuration file from disk.
 */
export function loadCompilerConfigFile(filePath: string): ValidatedCompilerConfig {
  if (!fs.existsSync(filePath)) {
    throw new CompilerConfigError(`Configuration file not found: ${filePath}`);
  }

  let rawContent: string;
  try {
    rawContent = fs.readFileSync(filePath, "utf-8");
  } catch (err) {
    throw new CompilerConfigError(`Failed to read configuration file: ${err instanceof Error ? err.message : String(err)}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawContent);
  } catch (err) {
    throw new CompilerConfigError(`Invalid JSON in configuration file: ${err instanceof Error ? err.message : String(err)}`);
  }

  return validateCompilerConfig(parsed);
}
