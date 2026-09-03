import * as fs from "fs";
import * as path from "path";
import { analyzeReturndataModel } from "./analyzer";
import {
  ReturndataAnalysisCancelledError,
  resolveReturndataLimits,
} from "./config";
import { buildReturndataModels } from "./model";
import type {
  ReturndataAnalysisOptions,
  ReturndataAnalysisReport,
  ReturndataContractModel,
  ReturndataDiagnostic,
  ReturndataFileAnalysis,
  ReturndataFinding,
  ReturndataSourceInput,
} from "./types";

export const RETURNDATA_ENGINE_VERSION = "0.1.0" as const;

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

/** Analyze a single in-memory Solidity source without filesystem or network access. */
export function analyzeReturndataSource(
  source: string,
  file = "<memory>.sol",
  options: ReturndataAnalysisOptions = {},
): ReturndataAnalysisReport {
  return analyzeReturndataSources([{ file, source }], options);
}

/** Analyze an explicitly supplied, deterministic set of Solidity sources. */
export function analyzeReturndataSources(
  inputs: ReturndataSourceInput[],
  options: ReturndataAnalysisOptions = {},
): ReturndataAnalysisReport {
  const limits = resolveReturndataLimits(options.limits);
  checkCancelled(options);
  const ordered = [...inputs]
    .map((input) => ({ file: input.file, source: input.source }))
    .sort((left, right) => left.file.localeCompare(right.file));
  const files: ReturndataFileAnalysis[] = [];
  let contractCount = 0;
  let findingsRemaining = limits.maxFindings;
  let truncated = ordered.length > limits.maxFiles;

  for (const input of ordered.slice(0, limits.maxFiles)) {
    checkCancelled(options);
    const built = buildReturndataModels(input.source, input.file, limits, options.signal);
    contractCount += built.models.length;
    const findings: ReturndataFinding[] = [];
    for (const model of built.models) {
      checkCancelled(options);
      for (const finding of analyzeReturndataModel(model, options)) {
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
        code: "RTD_SOURCE_LIMIT",
        severity: "warning",
        message: `Only the first ${limits.maxFiles} Solidity files were analyzed`,
      }],
    });
  }
  return report(files, truncated, contractCount);
}

/** Recursively collect Solidity files while avoiding symlink traversal. */
export function collectReturndataSolidityFiles(targets: string[]): string[] {
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
export function analyzeReturndataFiles(
  targets: string[],
  options: ReturndataAnalysisOptions = {},
): ReturndataAnalysisReport {
  const limits = resolveReturndataLimits(options.limits);
  checkCancelled(options);
  const discovered = collectReturndataSolidityFiles(targets);
  const inputs: ReturndataSourceInput[] = [];
  const unreadable: ReturndataFileAnalysis[] = [];
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
  const analysis = analyzeReturndataSources(inputs, { ...options, limits });
  const files = [...analysis.files.filter((file) => file.file !== "<project>"), ...unreadable]
    .sort((left, right) => left.file.localeCompare(right.file));
  if (discovered.length > limits.maxFiles || analysis.files.some((file) => file.file === "<project>")) {
    files.push({
      file: "<project>",
      findings: [],
      diagnostics: [{
        code: "RTD_SOURCE_LIMIT",
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
  files: ReturndataFileAnalysis[],
  truncated: boolean,
  contractCount: number,
): ReturndataAnalysisReport {
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
      diagnostic.code === "RTD_FINDING_LIMIT" || diagnostic.code.endsWith("_LIMIT"))) {
      summary.truncated = true;
    }
  }
  return {
    schemaVersion: "1.0.0",
    engineVersion: RETURNDATA_ENGINE_VERSION,
    files,
    summary,
  };
}

function sortModel(model: ReturndataContractModel): ReturndataContractModel {
  return {
    ...model,
    stateVariables: [...model.stateVariables].sort((left, right) =>
      left.location.line - right.location.line || left.name.localeCompare(right.name)),
    transitions: [...model.transitions].sort((left, right) =>
      left.location.line - right.location.line || left.name.localeCompare(right.name)),
    externalCalls: [...model.externalCalls].sort((left, right) => left.order - right.order),
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

function limitDiagnostic(file: string, limit: number): ReturndataDiagnostic {
  return {
    code: "RTD_FINDING_LIMIT",
    severity: "warning",
    message: `Finding output was limited to ${limit} records`,
    location: { file, line: 1, column: 1 },
  };
}

function compareFindings(left: ReturndataFinding, right: ReturndataFinding): number {
  return left.location.line - right.location.line || left.location.column - right.location.column ||
    left.ruleId.localeCompare(right.ruleId) || left.contract.localeCompare(right.contract);
}

function compareDiagnostics(left: ReturndataDiagnostic, right: ReturndataDiagnostic): number {
  return (left.location?.line ?? 0) - (right.location?.line ?? 0) ||
    left.code.localeCompare(right.code) || left.message.localeCompare(right.message);
}

function checkCancelled(options: ReturndataAnalysisOptions): void {
  if (options.signal?.aborted) throw new ReturndataAnalysisCancelledError();
}

function safeErrorCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && /^[A-Z0-9_]+$/.test(code) ? code : "IO_ERROR";
}

function unreadableFile(file: string, error: unknown): ReturndataFileAnalysis {
  return {
    file,
    findings: [],
    diagnostics: [{
      code: "RTD_FILE_UNREADABLE",
      severity: "error",
      message: `Solidity target could not be read (${safeErrorCode(error)})`,
      location: { file, line: 1, column: 1 },
    }],
  };
}

export const RETURNDATA_SEVERITY_ORDER = SEVERITIES;
