import * as fs from "fs";
import * as path from "path";
import { buildAmmModels } from "./model";
import { analyzeAmmModel } from "./analyzer";
import { resolveAmmLimits, AmmAnalysisCancelledError } from "./config";
import type {
  AmmAnalysisOptions,
  AmmAnalysisReport,
  AmmDiagnostic,
  AmmFileAnalysis,
  AmmFinding,
  AmmSourceInput,
} from "./types";

const ENGINE_VERSION = "0.1.0";

export function analyzeAmmSource(input: AmmSourceInput, options: AmmAnalysisOptions = {}): AmmAnalysisReport {
  return analyzeAmmSources([input], options);
}

export function analyzeAmmSources(inputs: AmmSourceInput[], options: AmmAnalysisOptions = {}): AmmAnalysisReport {
  const limits = resolveAmmLimits(options.limits);
  checkCancelled(options);

  const normalized = normalizeInputs(inputs);
  const limited = normalized.slice(0, limits.maxFiles);
  const files: AmmFileAnalysis[] = [];
  let contracts = 0;
  let truncated = normalized.length > limited.length;
  let findingBudget = limits.maxFindings;
  let contractBudget = limits.maxContracts;

  for (const input of limited) {
    checkCancelled(options);
    if (contractBudget === 0) {
      truncated = true;
      files.push({
        file: input.file,
        findings: [],
        diagnostics: [{
          code: "AMM_CONTRACT_LIMIT",
          severity: "warning",
          message: `The project-level ${limits.maxContracts}-contract limit was reached`,
          location: { file: input.file, line: 1, column: 1 },
        }],
      });
      continue;
    }

    const built = buildAmmModels(input.source, input.file, { ...limits, maxContracts: contractBudget }, options.signal);
    contracts += built.models.length;
    contractBudget -= built.models.length;
    if (built.diagnostics.some((diagnostic) => diagnostic.code.endsWith("_LIMIT"))) truncated = true;
    if (built.diagnostics.some((diagnostic) => diagnostic.code === "AMM_CONTRACT_LIMIT")) {
      truncated = true;
      contractBudget = 0;
    }

    const candidateFindings = built.models.flatMap((model) => analyzeAmmModel(model, options));
    const accepted = candidateFindings.slice(0, findingBudget).map((finding) => ({
      ...finding,
      evidence: finding.evidence.slice(0, limits.maxEvidencePerFinding),
    }));
    if (accepted.length < candidateFindings.length) truncated = true;
    findingBudget -= accepted.length;

    files.push({
      file: input.file,
      findings: accepted.sort(compareFindings),
      diagnostics: built.diagnostics.sort(compareDiagnostics),
      ...(options.includeModels ? { models: built.models } : {}),
    });
  }

  if (normalized.length > limited.length) {
    files.push({
      file: "<analysis>",
      findings: [],
      diagnostics: [{
        code: "AMM_SOURCE_LIMIT",
        severity: "warning",
        message: `Only the first ${limits.maxFiles} files were analyzed`,
      }],
    });
  }

  return buildReport(files, contracts, truncated);
}

export function analyzeAmmFiles(filePaths: string[], options: AmmAnalysisOptions = {}): AmmAnalysisReport {
  const limits = resolveAmmLimits(options.limits);
  const uniquePaths = [...new Set(filePaths)].sort((left, right) => left.localeCompare(right));
  const readable: AmmSourceInput[] = [];
  const failures: AmmFileAnalysis[] = [];

  for (const filePath of uniquePaths.slice(0, limits.maxFiles)) {
    checkCancelled(options);
    try {
      readable.push({ file: filePath, source: fs.readFileSync(filePath, "utf8") });
    } catch (error) {
      failures.push({
        file: filePath,
        findings: [],
        diagnostics: [{
          code: "AMM_FILE_UNREADABLE",
          severity: "error",
          message: `Solidity target could not be read (${errorCode(error)})`,
          location: { file: filePath, line: 1, column: 1 },
        }],
      });
    }
  }

  const report = analyzeAmmSources(readable, {
    ...options,
    limits: { ...limits, maxFiles: limits.maxFiles },
  });
  const files = [...report.files, ...failures].sort((left, right) => left.file.localeCompare(right.file));
  const skipped = uniquePaths.length > limits.maxFiles;
  if (skipped && !files.some((file) => file.file === "<analysis>")) {
    files.push({
      file: "<analysis>",
      findings: [],
      diagnostics: [{
        code: "AMM_SOURCE_LIMIT",
        severity: "warning",
        message: `Only the first ${limits.maxFiles} files were analyzed`,
      }],
    });
  }
  return buildReport(files, report.summary.contracts, report.summary.truncated || skipped);
}

export function collectAmmSolidityFiles(targets: string[], maxFiles: number = resolveAmmLimits().maxFiles): string[] {
  const found = new Set<string>();
  const queue = [...targets].map((target) => path.resolve(target)).sort().reverse();
  while (queue.length > 0 && found.size < maxFiles) {
    const target = queue.pop()!;
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(target);
    } catch {
      if (target.endsWith(".sol")) found.add(target);
      continue;
    }
    if (stat.isSymbolicLink()) continue;
    if (stat.isFile()) {
      if (target.endsWith(".sol")) found.add(target);
      continue;
    }
    if (!stat.isDirectory()) continue;
    const entries = fs.readdirSync(target, { withFileTypes: true })
      .filter((entry) => !entry.isSymbolicLink())
      .map((entry) => path.join(target, entry.name))
      .sort()
      .reverse();
    queue.push(...entries);
  }
  return [...found].sort();
}

export function analyzeAmmProject(targets: string[], options: AmmAnalysisOptions = {}): AmmAnalysisReport {
  const limits = resolveAmmLimits(options.limits);
  const files = collectAmmSolidityFiles(targets, limits.maxFiles + 1);
  return analyzeAmmFiles(files, options);
}

function buildReport(files: AmmFileAnalysis[], contracts: number, truncated: boolean): AmmAnalysisReport {
  const summary: AmmAnalysisReport["summary"] = {
    files: files.filter((file) => file.file !== "<analysis>").length,
    contracts,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0,
    truncated,
  };

  for (const file of files) {
    file.findings.sort(compareFindings);
    file.diagnostics.sort(compareDiagnostics);
    for (const finding of file.findings) {
      summary[finding.severity] += 1;
      summary.total += 1;
    }
  }

  return {
    schemaVersion: "1.0.0",
    engineVersion: ENGINE_VERSION,
    files,
    summary,
  };
}

function normalizeInputs(inputs: AmmSourceInput[]): AmmSourceInput[] {
  return [...new Map(inputs.map((input) => [input.file, input])).values()].sort((left, right) => left.file.localeCompare(right.file));
}

function checkCancelled(options: AmmAnalysisOptions): void {
  if (options.signal?.aborted) throw new AmmAnalysisCancelledError();
}

function compareFindings(left: AmmFinding, right: AmmFinding): number {
  return left.ruleId.localeCompare(right.ruleId) || left.location.line - right.location.line;
}

function compareDiagnostics(left: AmmDiagnostic, right: AmmDiagnostic): number {
  return left.code.localeCompare(right.code) || (left.location?.line ?? 0) - (right.location?.line ?? 0);
}

function errorCode(error: unknown): string {
  return error instanceof Error && error.message ? error.message : "unknown error";
}
