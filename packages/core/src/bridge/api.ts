import * as fs from "fs";
import * as path from "path";
import { analyzeBridgeModel } from "./analyzer";
import {
  BridgeAnalysisCancelledError,
  resolveBridgeLimits,
} from "./config";
import { buildBridgeModels } from "./model";
import type {
  BridgeAnalysisOptions,
  BridgeAnalysisReport,
  BridgeContractModel,
  BridgeDiagnostic,
  BridgeFileAnalysis,
  BridgeFinding,
  BridgeSourceInput,
} from "./types";

export const BRIDGE_ENGINE_VERSION = "0.1.0" as const;

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

/** Analyze a single in-memory Solidity source without filesystem or network access. */
export function analyzeBridgeSource(
  source: string,
  file = "<memory>.sol",
  options: BridgeAnalysisOptions = {},
): BridgeAnalysisReport {
  return analyzeBridgeSources([{ file, source }], options);
}

/** Analyze an explicitly supplied, deterministic set of Solidity sources. */
export function analyzeBridgeSources(
  inputs: BridgeSourceInput[],
  options: BridgeAnalysisOptions = {},
): BridgeAnalysisReport {
  const limits = resolveBridgeLimits(options.limits);
  checkCancelled(options);
  const ordered = [...inputs]
    .map((input) => ({ file: input.file, source: input.source }))
    .sort((left, right) => left.file.localeCompare(right.file));
  const files: BridgeFileAnalysis[] = [];
  let contractCount = 0;
  let findingsRemaining = limits.maxFindings;
  let truncated = ordered.length > limits.maxFiles;

  for (const input of ordered.slice(0, limits.maxFiles)) {
    checkCancelled(options);
    const built = buildBridgeModels(input.source, input.file, limits, options.signal);
    contractCount += built.models.length;
    const findings: BridgeFinding[] = [];
    for (const model of built.models) {
      checkCancelled(options);
      for (const finding of analyzeBridgeModel(model, options)) {
        if (findingsRemaining === 0) {
          truncated = true;
          break;
        }
        findings.push({
          ...finding,
          evidence: finding.evidence.slice(0, limits.maxEvidencePerFinding),
        });
        findingsRemaining -= 1;
      }
      if (findingsRemaining === 0) break;
    }
    const diagnostics = [...built.diagnostics];
    if (findingsRemaining === 0) {
      diagnostics.push(limitDiagnostic(input.file, limits.maxFindings));
    }
    files.push({
      file: input.file,
      findings: findings.sort(compareFindings),
      diagnostics: diagnostics.sort(compareDiagnostics),
      ...(options.includeModels ? { models: built.models.map(sortModel) } : {}),
    });
  }

  if (ordered.length > limits.maxFiles) {
    files.push({
      file: "<project>",
      findings: [],
      diagnostics: [{
        code: "BRG_SOURCE_LIMIT",
        severity: "warning",
        message: `Only the first ${limits.maxFiles} Solidity files were analyzed`,
      }],
    });
  }
  return report(files, truncated, contractCount);
}

/** Recursively collect Solidity files while avoiding symlink traversal. */
export function collectBridgeSolidityFiles(targets: string[]): string[] {
  const result = new Set<string>();
  const pending = [...targets].map((target) => path.resolve(target)).sort().reverse();
  while (pending.length) {
    const candidate = pending.pop() as string;
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(candidate);
    } catch {
      continue;
    }
    if (stat.isSymbolicLink()) continue;
    if (stat.isFile()) {
      if (candidate.endsWith(".sol")) result.add(candidate);
      continue;
    }
    if (!stat.isDirectory()) continue;
    let entries: string[];
    try {
      entries = fs.readdirSync(candidate).sort();
    } catch {
      continue;
    }
    for (let index = entries.length - 1; index >= 0; index -= 1) {
      pending.push(path.join(candidate, entries[index]));
    }
  }
  return [...result].sort();
}

/** Read and analyze Solidity files/directories with bounded IO and sanitized diagnostics. */
export function analyzeBridgeFiles(
  targets: string[],
  options: BridgeAnalysisOptions = {},
): BridgeAnalysisReport {
  const limits = resolveBridgeLimits(options.limits);
  checkCancelled(options);
  const discovered = collectBridgeSolidityFiles(targets);
  const inputs: BridgeSourceInput[] = [];
  const unreadable: BridgeFileAnalysis[] = [];
  for (const target of [...new Set(targets.map((item) => path.resolve(item)))].sort()) {
    try {
      fs.lstatSync(target);
    } catch (error) {
      unreadable.push(unreadableFile(target, error));
    }
  }
  for (const file of discovered.slice(0, limits.maxFiles)) {
    checkCancelled(options);
    try {
      inputs.push({ file, source: fs.readFileSync(file, "utf8") });
    } catch (error) {
      unreadable.push(unreadableFile(file, error));
    }
  }
  const analysis = analyzeBridgeSources(inputs, { ...options, limits });
  const files = [...analysis.files.filter((file) => file.file !== "<project>"), ...unreadable]
    .sort((left, right) => left.file.localeCompare(right.file));
  if (discovered.length > limits.maxFiles || analysis.files.some((file) => file.file === "<project>")) {
    files.push({
      file: "<project>",
      findings: [],
      diagnostics: [{
        code: "BRG_SOURCE_LIMIT",
        severity: "warning",
        message: `Only the first ${limits.maxFiles} Solidity files were analyzed`,
      }],
    });
  }
  return report(
    files,
    analysis.summary.truncated || discovered.length > limits.maxFiles,
    analysis.summary.contracts,
  );
}

function report(
  files: BridgeFileAnalysis[],
  truncated: boolean,
  contractCount: number,
): BridgeAnalysisReport {
  const summary = {
    files: files.filter((file) => file.file !== "<project>").length,
    contracts: contractCount,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0,
    truncated,
  };
  for (const file of files) {
    for (const finding of file.findings) {
      incrementSeverity(summary, finding.severity);
      summary.total += 1;
    }
    if (file.diagnostics.some((diagnostic) =>
      diagnostic.code === "BRG_FINDING_LIMIT" || diagnostic.code.endsWith("_LIMIT"))) {
      summary.truncated = true;
    }
  }
  return {
    schemaVersion: "1.0.0",
    engineVersion: BRIDGE_ENGINE_VERSION,
    files,
    summary,
  };
}

function sortModel(model: BridgeContractModel): BridgeContractModel {
  return {
    ...model,
    stateVariables: [...model.stateVariables].sort((left, right) =>
      left.location.line - right.location.line || left.name.localeCompare(right.name)),
    transitions: [...model.transitions].sort((left, right) =>
      left.location.line - right.location.line || left.name.localeCompare(right.name)),
    privilegedCalls: [...model.privilegedCalls].sort((left, right) => left.order - right.order),
    messageControlledCalls: [...model.messageControlledCalls].sort((left, right) => left.order - right.order),
  };
}

function incrementSeverity(
  summary: { critical: number; high: number; medium: number; low: number; info: number },
  severity: string,
): void {
  if (severity === "critical" || severity === "high" || severity === "medium" ||
    severity === "low" || severity === "info") {
    summary[severity] += 1;
  }
}

function limitDiagnostic(file: string, limit: number): BridgeDiagnostic {
  return {
    code: "BRG_FINDING_LIMIT",
    severity: "warning",
    message: `Finding output was limited to ${limit} records`,
    location: { file, line: 1, column: 1 },
  };
}

function compareFindings(left: BridgeFinding, right: BridgeFinding): number {
  return left.location.line - right.location.line || left.location.column - right.location.column ||
    left.ruleId.localeCompare(right.ruleId) || left.contract.localeCompare(right.contract);
}

function compareDiagnostics(left: BridgeDiagnostic, right: BridgeDiagnostic): number {
  return (left.location?.line ?? 0) - (right.location?.line ?? 0) ||
    left.code.localeCompare(right.code) || left.message.localeCompare(right.message);
}

function checkCancelled(options: BridgeAnalysisOptions): void {
  if (options.signal?.aborted) throw new BridgeAnalysisCancelledError();
}

function safeErrorCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && /^[A-Z0-9_]+$/.test(code) ? code : "IO_ERROR";
}

function unreadableFile(file: string, error: unknown): BridgeFileAnalysis {
  return {
    file,
    findings: [],
    diagnostics: [{
      code: "BRG_FILE_UNREADABLE",
      severity: "error",
      message: `Solidity target could not be read (${safeErrorCode(error)})`,
      location: { file, line: 1, column: 1 },
    }],
  };
}

export const BRIDGE_SEVERITY_ORDER = SEVERITIES;
