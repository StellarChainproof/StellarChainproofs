/**
 * @packageDocumentation
 * @chainproof/core — Multi-Compiler Matrix Evaluation & Diagnostic Grid Generator
 */

import type {
  CompilerSourceInput,
  CompilerSettings,
  CompilerMatrixGrid,
  CompilerMatrixRow,
  MatrixCell,
  MatrixCellStatus,
  CompilerMatrixSummary,
  CompilerCancellationSignal,
} from "./types";
import {
  MILESTONE_COMPILER_VERSIONS,
  getHazardsForVersion,
  getRecommendedCompilerVersion,
} from "./matrix";
import { getCompilerAdapter, CompilerAdapter } from "./adapter";
import { resolveProjectPragmas } from "./pragma";
import { sortSemVerList } from "./semver";

export interface MatrixEvaluationOptions {
  targetVersions?: string[];
  settings?: Partial<CompilerSettings>;
  adapter?: CompilerAdapter;
  signal?: CompilerCancellationSignal;
  maxVersionsToTest?: number;
}

/**
 * Evaluates a set of Solidity sources across a matrix of compiler versions.
 */
export async function evaluateCompilerMatrix(
  sources: CompilerSourceInput[],
  options?: MatrixEvaluationOptions,
): Promise<CompilerMatrixGrid> {
  const adapter = options?.adapter || getCompilerAdapter();
  const pragmaResolution = resolveProjectPragmas(sources);

  let targetVersions = options?.targetVersions;
  if (!targetVersions || targetVersions.length === 0) {
    if (pragmaResolution.globalCompatibleVersions.length > 0) {
      // Pick representative milestone versions from the compatible set
      const compatibleSet = new Set(pragmaResolution.globalCompatibleVersions);
      const milestones = MILESTONE_COMPILER_VERSIONS.filter((v) => compatibleSet.has(v));
      targetVersions = milestones.length > 0 ? milestones : pragmaResolution.globalCompatibleVersions.slice(0, 8);
    } else {
      targetVersions = [...MILESTONE_COMPILER_VERSIONS];
    }
  }

  // Cap versions to max limit
  const maxVersions = options?.maxVersionsToTest ?? 12;
  targetVersions = sortSemVerList(targetVersions, "asc").slice(0, maxVersions);

  const rowMap = new Map<string, CompilerMatrixRow>();

  // Initialize rows for each contract
  for (const src of sources) {
    const defaultRowKey = `${src.file}:Main`;
    rowMap.set(defaultRowKey, {
      file: src.file,
      contract: "Main",
      cells: {},
    });
  }

  const fullyCompatible = new Set<string>();
  const partiallyCompatible = new Set<string>();
  const incompatible = new Set<string>();
  let totalCriticalHazards = 0;

  for (const version of targetVersions) {
    if (options?.signal?.isCancelled()) {
      break;
    }

    let compileRes;
    try {
      compileRes = await adapter.compile(sources, options?.settings, version);
    } catch (err) {
      compileRes = {
        version,
        success: false,
        contracts: {},
        diagnostics: [
          {
            severity: "error" as const,
            type: "CompilerExecutionError",
            message: String(err),
            formattedMessage: `Execution Error: ${String(err)}`,
          },
        ],
        durationMs: 0,
        evmVersion: "default",
        optimizer: { enabled: true, runs: 200 },
      };
    }

    const versionHazards = getHazardsForVersion(version);
    const criticalHazards = versionHazards.filter(
      (h) => h.severity === "critical" || h.severity === "high",
    );
    totalCriticalHazards += criticalHazards.length;

    // Process compiled contracts
    const contractNames = Object.keys(compileRes.contracts);
    if (contractNames.length > 0) {
      for (const [cName, cArtifact] of Object.entries(compileRes.contracts)) {
        const rowKey = `${cArtifact.sourcePath}:${cName}`;
        let row = rowMap.get(rowKey);
        if (!row) {
          row = {
            file: cArtifact.sourcePath,
            contract: cName,
            cells: {},
          };
          rowMap.set(rowKey, row);
        }

        const warnings = compileRes.diagnostics.filter((d) => d.severity === "warning");
        const errors = compileRes.diagnostics.filter((d) => d.severity === "error");

        let status: MatrixCellStatus = "compatible";
        const notes: string[] = [];

        if (errors.length > 0 || !compileRes.success) {
          status = "incompatible";
          notes.push(...errors.map((e) => e.message));
        } else if (criticalHazards.length > 0) {
          status = "hazard";
          notes.push(...criticalHazards.map((h) => `[${h.id}] ${h.name}`));
        } else if (warnings.length > 0) {
          status = "warning";
          notes.push(...warnings.map((w) => w.message));
        }

        const cell: MatrixCell = {
          version,
          status,
          compileSuccess: compileRes.success,
          warningsCount: warnings.length,
          errorsCount: errors.length,
          hazards: versionHazards.map((h) => h.id),
          bytecodeSize: cArtifact.bytecode.lengthBytes,
          storageLayoutHash: cArtifact.storageLayout.layoutHash,
          notes,
        };

        row.cells[version] = cell;
      }
    } else {
      // Record failed compilation across source files
      for (const src of sources) {
        const rowKey = `${src.file}:Main`;
        const row = rowMap.get(rowKey)!;
        row.cells[version] = {
          version,
          status: "incompatible",
          compileSuccess: false,
          warningsCount: 0,
          errorsCount: compileRes.diagnostics.length,
          hazards: versionHazards.map((h) => h.id),
          notes: compileRes.diagnostics.map((d) => d.message),
        };
      }
    }

    if (compileRes.success && criticalHazards.length === 0) {
      fullyCompatible.add(version);
    } else if (compileRes.success) {
      partiallyCompatible.add(version);
    } else {
      incompatible.add(version);
    }
  }

  // Clean up unused placeholder rows if specific contracts were found
  const rows = [...rowMap.values()].filter((r) => Object.keys(r.cells).length > 0);

  const summary: CompilerMatrixSummary = {
    testedVersions: targetVersions,
    supportedRange: pragmaResolution.globalRange,
    recommendedVersion:
      pragmaResolution.recommendedVersion || getRecommendedCompilerVersion(pragmaResolution.globalRange),
    totalContracts: rows.length,
    fullyCompatibleVersions: sortSemVerList([...fullyCompatible], "asc"),
    partiallyCompatibleVersions: sortSemVerList([...partiallyCompatible], "asc"),
    incompatibleVersions: sortSemVerList([...incompatible], "asc"),
    criticalHazardsFound: totalCriticalHazards,
  };

  return {
    targetVersions,
    rows,
    summary,
  };
}
