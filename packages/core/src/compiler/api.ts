/**
 * @packageDocumentation
 * @chainproof/core — Public Compiler Compatibility & Diagnostic Matrix API
 */

import * as fs from "fs";
import * as path from "path";
import { parseSolidity } from "../ast/parser";
import type { Finding } from "../types";
import type {
  CompilerAnalysisOptions,
  CompilerAuditReport,
  CompilerAuditSummary,
  CompilerMatrixGrid,
  CompilerSourceInput,
  ProjectPragmaResolution,
  VersionComparisonResult,
  CompilerCancellationSignal,
} from "./types";
import {
  COMPILER_MATRIX_SCHEMA_VERSION,
} from "./types";
import { DEFAULT_COMPILER_LIMITS, CompilerConfigError } from "./config";
import { resolveProjectPragmas } from "./pragma";
import { evaluateCompilerMatrix } from "./matrix-analyzer";
import { getCompilerAdapter } from "./adapter";
import { compareContractVersions } from "./comparator";
import { detectCompilerCompatibility } from "./rules";
import { parseSemVer, sortSemVerList } from "./semver";

export class CompilerAnalysisCancelledError extends Error {
  constructor(message: string = "Compiler analysis was cancelled") {
    super(message);
    this.name = "CompilerAnalysisCancelledError";
  }
}

/**
 * Collects all `.sol` files from file paths or directories.
 */
export function collectCompilerSolidityFiles(targets: string[]): string[] {
  const files: string[] = [];
  for (const target of targets) {
    if (!fs.existsSync(target)) continue;
    const stat = fs.statSync(target);
    if (stat.isDirectory()) {
      const entries = fs.readdirSync(target, { recursive: true } as { recursive: boolean }) as string[];
      entries
        .filter((e) => e.endsWith(".sol"))
        .forEach((e) => files.push(path.resolve(path.join(target, e))));
    } else if (target.endsWith(".sol")) {
      files.push(path.resolve(target));
    }
  }
  return [...new Set(files)];
}

function loadSources(
  targets: string[] | CompilerSourceInput[],
  maxFiles: number = DEFAULT_COMPILER_LIMITS.maxFiles,
  maxSourceBytes: number = DEFAULT_COMPILER_LIMITS.maxSourceBytes,
  signal?: CompilerCancellationSignal,
): CompilerSourceInput[] {
  if (signal?.isCancelled()) {
    throw new CompilerAnalysisCancelledError();
  }

  if (targets.length === 0) return [];

  // Check if already provided as CompilerSourceInput
  if (typeof targets[0] !== "string") {
    const inputs = targets as CompilerSourceInput[];
    if (inputs.length > maxFiles) {
      throw new CompilerConfigError(`Source file count exceeds configured limit of ${maxFiles}`);
    }
    for (const inp of inputs) {
      if (Buffer.byteLength(inp.content, "utf-8") > maxSourceBytes) {
        throw new CompilerConfigError(`Source file "${inp.file}" exceeds size limit of ${maxSourceBytes} bytes`);
      }
    }
    return inputs;
  }

  const filePaths = collectCompilerSolidityFiles(targets as string[]);
  if (filePaths.length > maxFiles) {
    throw new CompilerConfigError(`Discovered ${filePaths.length} files, which exceeds limit of ${maxFiles}`);
  }

  const sources: CompilerSourceInput[] = [];
  for (const fp of filePaths) {
    if (signal?.isCancelled()) {
      throw new CompilerAnalysisCancelledError();
    }
    try {
      const content = fs.readFileSync(fp, "utf-8");
      if (Buffer.byteLength(content, "utf-8") > maxSourceBytes) {
        throw new CompilerConfigError(`Source file "${fp}" exceeds size limit of ${maxSourceBytes} bytes`);
      }
      sources.push({
        file: fp,
        content,
      });
    } catch (err) {
      if (err instanceof CompilerConfigError) throw err;
      // Skip unreadable files
    }
  }

  return sources;
}

/**
 * Inspects pragma directives and resolves compatibility constraints across files.
 */
export function inspectCompilerPragmas(
  targets: string[] | CompilerSourceInput[],
  options?: CompilerAnalysisOptions,
): ProjectPragmaResolution {
  const limits = { ...DEFAULT_COMPILER_LIMITS, ...options?.limits, ...options?.config?.limits };
  const sources = loadSources(targets, limits.maxFiles, limits.maxSourceBytes, options?.signal);
  return resolveProjectPragmas(sources);
}

/**
 * Builds a multi-compiler evaluation grid across supported/target compiler versions.
 */
export async function buildCompilerMatrix(
  targets: string[] | CompilerSourceInput[],
  options?: CompilerAnalysisOptions,
): Promise<CompilerMatrixGrid> {
  const limits = { ...DEFAULT_COMPILER_LIMITS, ...options?.limits, ...options?.config?.limits };
  const sources = loadSources(targets, limits.maxFiles, limits.maxSourceBytes, options?.signal);

  const targetVersions = options?.targetVersions || options?.config?.targetVersions;
  const settings = {
    optimizer: options?.optimizer || options?.config?.optimizer,
    evmVersion: options?.evmVersion || options?.config?.defaultEvmVersion,
  };

  const adapter = getCompilerAdapter({
    mode: options?.config?.sandboxed ? "simulated" : "auto",
    nativeBinaryPath: options?.config?.compilerBinaryPath,
    timeoutMs: limits.timeoutMs,
  });

  return evaluateCompilerMatrix(sources, {
    targetVersions,
    settings,
    adapter,
    signal: options?.signal,
    maxVersionsToTest: limits.maxVersionsToTest,
  });
}

/**
 * Compares two compiler versions side-by-side for contract artifacts.
 */
export async function compareCompilerVersions(
  targets: string[] | CompilerSourceInput[],
  versions: [string, string],
  options?: CompilerAnalysisOptions,
): Promise<VersionComparisonResult[]> {
  const limits = { ...DEFAULT_COMPILER_LIMITS, ...options?.limits, ...options?.config?.limits };
  const sources = loadSources(targets, limits.maxFiles, limits.maxSourceBytes, options?.signal);

  if (!versions || versions.length !== 2 || !parseSemVer(versions[0]) || !parseSemVer(versions[1])) {
    throw new CompilerConfigError("Two valid compiler versions must be specified for comparison.");
  }

  const [baseVer, targetVer] = versions;
  const adapter = getCompilerAdapter({
    mode: options?.config?.sandboxed ? "simulated" : "auto",
    nativeBinaryPath: options?.config?.compilerBinaryPath,
    timeoutMs: limits.timeoutMs,
  });

  const settings = {
    optimizer: options?.optimizer || options?.config?.optimizer,
    evmVersion: options?.evmVersion || options?.config?.defaultEvmVersion,
  };

  const baseResult = await adapter.compile(sources, settings, baseVer);
  const targetResult = await adapter.compile(sources, settings, targetVer);

  const contractNames = new Set([
    ...Object.keys(baseResult.contracts),
    ...Object.keys(targetResult.contracts),
  ]);

  const comparisons: VersionComparisonResult[] = [];
  for (const cName of contractNames) {
    if (options?.signal?.isCancelled()) throw new CompilerAnalysisCancelledError();
    const comp = compareContractVersions(cName, baseResult, targetResult);
    comparisons.push(comp);
  }

  return comparisons;
}

/**
 * Performs a complete multi-compiler compatibility and diagnostic audit.
 */
export async function auditCompilerCompatibility(
  targets: string[] | CompilerSourceInput[],
  options?: CompilerAnalysisOptions,
): Promise<CompilerAuditReport> {
  const limits = { ...DEFAULT_COMPILER_LIMITS, ...options?.limits, ...options?.config?.limits };
  const sources = loadSources(targets, limits.maxFiles, limits.maxSourceBytes, options?.signal);

  const pragmaResolution = resolveProjectPragmas(sources);
  const matrix = await buildCompilerMatrix(sources, options);

  let comparisons: VersionComparisonResult[] = [];
  const compareVersions = options?.compareVersions || options?.config?.compareVersions;
  if (compareVersions) {
    comparisons = await compareCompilerVersions(sources, compareVersions, options);
  } else if (matrix.targetVersions.length >= 2) {
    // Default compare lowest vs highest tested version
    const sorted = sortSemVerList(matrix.targetVersions, "asc");
    const lowest = sorted[0];
    const highest = sorted[sorted.length - 1];
    if (lowest !== highest) {
      comparisons = await compareCompilerVersions(sources, [lowest, highest], options);
    }
  }

  // Run compiler compatibility rules
  const allFindings: Finding[] = [];
  for (const src of sources) {
    if (options?.signal?.isCancelled()) throw new CompilerAnalysisCancelledError();
    const { ast } = parseSolidity(src.content, src.file);
    if (ast) {
      const findings = detectCompilerCompatibility(ast, src.content, src.file, {
        includeRules: options?.includeRules || options?.config?.includeRules,
        excludeRules: options?.excludeRules || options?.config?.excludeRules,
      });
      allFindings.push(...findings);
    }
  }

  // Cap findings
  const cappedFindings = allFindings.slice(0, limits.maxFindings);

  const findingsSummary = {
    critical: cappedFindings.filter((f) => f.severity === "critical").length,
    high: cappedFindings.filter((f) => f.severity === "high").length,
    medium: cappedFindings.filter((f) => f.severity === "medium").length,
    low: cappedFindings.filter((f) => f.severity === "low").length,
    info: cappedFindings.filter((f) => f.severity === "info").length,
    total: cappedFindings.length,
  };

  const breakingDrifts = comparisons.filter((c) => c.compatibilityStatus === "breaking_drift").length;
  const criticalHazards = matrix.summary.criticalHazardsFound;

  const passed =
    !pragmaResolution.unsatisfiable &&
    breakingDrifts === 0 &&
    criticalHazards === 0 &&
    findingsSummary.critical === 0 &&
    findingsSummary.high === 0;

  const summary: CompilerAuditSummary = {
    totalFiles: sources.length,
    totalContracts: matrix.summary.totalContracts,
    testedVersions: matrix.targetVersions,
    recommendedVersion: pragmaResolution.recommendedVersion || matrix.summary.recommendedVersion,
    compatibleVersionsCount: matrix.summary.fullyCompatibleVersions.length,
    criticalHazardsCount: criticalHazards,
    breakingDriftsCount: breakingDrifts,
    findingsSummary,
    passed,
  };

  return {
    version: "0.1.0",
    schemaVersion: COMPILER_MATRIX_SCHEMA_VERSION,
    summary,
    projectPragmas: pragmaResolution,
    matrix,
    comparisons,
    findings: cappedFindings,
    diagnostics: [],
  };
}
