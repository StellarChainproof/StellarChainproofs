/**
 * @packageDocumentation
 * @chainproof/core — DoS & Unbounded Work Configuration, Validation & Migration
 */

import * as fs from "fs";
import type {
  DosConfigV0,
  DosConfigV1,
  ValidatedDosConfig,
  DosAnalysisLimits,
  DosRuleId,
  DosSeverity,
  DosConfidence,
} from "./types";
import { DOS_CONFIG_SCHEMA_VERSION } from "./types";

export class DosConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DosConfigError";
  }
}

export const ALL_DOS_RULES: DosRuleId[] = [
  "CP-DOS-001",
  "CP-DOS-002",
  "CP-DOS-003",
  "CP-DOS-004",
  "CP-DOS-005",
  "CP-DOS-006",
  "CP-DOS-007",
  "CP-DOS-008",
  "CP-DOS-009",
  "CP-DOS-010",
];

export const DEFAULT_DOS_LIMITS: DosAnalysisLimits = {
  maxFiles: 200,
  maxSourceBytes: 5 * 1024 * 1024, // 5MB
  maxContracts: 100,
  maxLoops: 500,
  maxFindings: 1000,
  timeoutMs: 30_000,
};

export function validateDosConfig(input: unknown): ValidatedDosConfig {
  if (!input || typeof input !== "object") {
    throw new DosConfigError("Configuration must be a non-null object.");
  }

  const raw = input as Record<string, any>;
  const version = raw.version ?? DOS_CONFIG_SCHEMA_VERSION;

  if (version === 0) {
    return migrateDosConfig(raw as DosConfigV0);
  }

  if (version !== 1) {
    throw new DosConfigError(`Unsupported DoS configuration schema version: ${version}`);
  }

  const v1 = input as DosConfigV1;

  // Validate includeRules
  const includeRules: DosRuleId[] = [];
  if (v1.includeRules) {
    if (!Array.isArray(v1.includeRules)) {
      throw new DosConfigError("includeRules must be an array of rule IDs.");
    }
    for (const r of v1.includeRules) {
      if (!ALL_DOS_RULES.includes(r as DosRuleId)) {
        throw new DosConfigError(`Invalid rule ID in includeRules: ${r}`);
      }
      includeRules.push(r as DosRuleId);
    }
  }

  // Validate excludeRules
  const excludeRules: DosRuleId[] = [];
  if (v1.excludeRules) {
    if (!Array.isArray(v1.excludeRules)) {
      throw new DosConfigError("excludeRules must be an array of rule IDs.");
    }
    for (const r of v1.excludeRules) {
      if (!ALL_DOS_RULES.includes(r as DosRuleId)) {
        throw new DosConfigError(`Invalid rule ID in excludeRules: ${r}`);
      }
      if (includeRules.includes(r as DosRuleId)) {
        throw new DosConfigError(`Rule ${r} cannot be in both includeRules and excludeRules.`);
      }
      excludeRules.push(r as DosRuleId);
    }
  }

  // Validate limits
  const limits: DosAnalysisLimits = { ...DEFAULT_DOS_LIMITS };
  if (v1.limits) {
    if (typeof v1.limits !== "object") {
      throw new DosConfigError("limits must be an object.");
    }
    if (v1.limits.maxFiles !== undefined) {
      if (typeof v1.limits.maxFiles !== "number" || v1.limits.maxFiles <= 0) {
        throw new DosConfigError("limits.maxFiles must be a positive integer.");
      }
      limits.maxFiles = v1.limits.maxFiles;
    }
    if (v1.limits.maxSourceBytes !== undefined) {
      if (typeof v1.limits.maxSourceBytes !== "number" || v1.limits.maxSourceBytes <= 0) {
        throw new DosConfigError("limits.maxSourceBytes must be a positive integer.");
      }
      limits.maxSourceBytes = v1.limits.maxSourceBytes;
    }
    if (v1.limits.maxContracts !== undefined) {
      if (typeof v1.limits.maxContracts !== "number" || v1.limits.maxContracts <= 0) {
        throw new DosConfigError("limits.maxContracts must be a positive integer.");
      }
      limits.maxContracts = v1.limits.maxContracts;
    }
    if (v1.limits.maxLoops !== undefined) {
      if (typeof v1.limits.maxLoops !== "number" || v1.limits.maxLoops <= 0) {
        throw new DosConfigError("limits.maxLoops must be a positive integer.");
      }
      limits.maxLoops = v1.limits.maxLoops;
    }
    if (v1.limits.maxFindings !== undefined) {
      if (typeof v1.limits.maxFindings !== "number" || v1.limits.maxFindings <= 0) {
        throw new DosConfigError("limits.maxFindings must be a positive integer.");
      }
      limits.maxFindings = v1.limits.maxFindings;
    }
    if (v1.limits.timeoutMs !== undefined) {
      if (typeof v1.limits.timeoutMs !== "number" || v1.limits.timeoutMs <= 0) {
        throw new DosConfigError("limits.timeoutMs must be a positive integer.");
      }
      limits.timeoutMs = v1.limits.timeoutMs;
    }
  }

  const minSeverity: DosSeverity = v1.minSeverity || "info";
  const minConfidence: DosConfidence = v1.minConfidence || "low";

  return {
    version: 1,
    includeRules,
    excludeRules,
    minSeverity,
    minConfidence,
    limits,
  };
}

export function migrateDosConfig(v0: DosConfigV0): ValidatedDosConfig {
  const includeRules: DosRuleId[] = (v0.includeRules || [])
    .filter((r) => ALL_DOS_RULES.includes(r as DosRuleId)) as DosRuleId[];
  const excludeRules: DosRuleId[] = (v0.excludeRules || [])
    .filter((r) => ALL_DOS_RULES.includes(r as DosRuleId)) as DosRuleId[];

  const limits: DosAnalysisLimits = {
    ...DEFAULT_DOS_LIMITS,
    ...(v0.maxFiles ? { maxFiles: v0.maxFiles } : {}),
    ...(v0.maxSourceSize ? { maxSourceBytes: v0.maxSourceSize } : {}),
  };

  return {
    version: 1,
    includeRules,
    excludeRules,
    minSeverity: "info",
    minConfidence: "low",
    limits,
  };
}

export function loadDosConfigFile(configPath: string): ValidatedDosConfig {
  if (!fs.existsSync(configPath)) {
    throw new DosConfigError(`Configuration file not found: ${configPath}`);
  }

  try {
    const content = fs.readFileSync(configPath, "utf-8");
    const parsed = JSON.parse(content);
    return validateDosConfig(parsed);
  } catch (err) {
    if (err instanceof DosConfigError) throw err;
    throw new DosConfigError(`Failed to load DoS config from ${configPath}: ${err instanceof Error ? err.message : String(err)}`);
  }
}
