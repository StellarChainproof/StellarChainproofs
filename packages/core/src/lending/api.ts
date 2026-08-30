import * as fs from "fs";
import * as path from "path";
import { buildLendingModels } from "./model";
import { resolveLendingLimits, LendingAnalysisCancelledError } from "./config";
import type {
  LendingAnalysisOptions,
  LendingAnalysisReport,
  LendingDiagnostic,
  LendingFileAnalysis,
  LendingFinding,
  LendingSourceInput,
} from "./types";

export const LENDING_ENGINE_VERSION = "0.1.0" as const;

export function analyzeLendingSource(
  input: LendingSourceInput,
  options: LendingAnalysisOptions = {},
): LendingAnalysisReport {
  return analyzeLendingSources([input], options);
}

export function analyzeLendingSources(
  inputs: LendingSourceInput[],
  options: LendingAnalysisOptions = {},
): LendingAnalysisReport {
  const limits = resolveLendingLimits(options.limits);
  checkCancelled(options);
  const ordered = [...inputs].sort((left, right) => left.file.localeCompare(right.file));
  const files: LendingFileAnalysis[] = [];
  let contracts = 0;
  let findingsRemaining = limits.maxFindings;
  let truncated = ordered.length > limits.maxFiles;

  for (const input of ordered.slice(0, limits.maxFiles)) {
    checkCancelled(options);
    const built = buildLendingModels(input.source, input.file, limits, options.signal);
    contracts += built.models.length;
    const findings: LendingFinding[] = [];
    for (const model of built.models) {
      checkCancelled(options);
      const candidate = (model.transitions.length > 0 ? model.transitions : []).flatMap(() => []);
      const results = anyFindings(model, options);
      for (const finding of results) {
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
    files.push({
      file: input.file,
      findings: findings.sort(compareFindings),
      diagnostics: built.diagnostics.sort(compareDiagnostics),
      ...(options.includeModels ? { models: built.models } : {}),
    });
  }

  if (ordered.length > limits.maxFiles) {
    files.push({
      file: "<project>",
      findings: [],
      diagnostics: [{
        code: "LND_SOURCE_LIMIT",
        severity: "warning",
        message: `Only the first ${limits.maxFiles} Solidity files were analyzed`,
      }],
    });
  }

  return report(files, truncated, contracts, options);
}

export function analyzeLendingFiles(
  filePaths: string[],
  options: LendingAnalysisOptions = {},
): LendingAnalysisReport {
  const limits = resolveLendingLimits(options.limits);
  const uniquePaths = [...new Set(filePaths)].sort((left, right) => left.localeCompare(right));
  const inputs: LendingSourceInput[] = [];
  const unreadable: LendingFileAnalysis[] = [];

  for (const filePath of uniquePaths.slice(0, limits.maxFiles)) {
    try {
      inputs.push({ file: filePath, source: fs.readFileSync(filePath, "utf8") });
    } catch (error) {
      unreadable.push({
        file: filePath,
        findings: [],
        diagnostics: [{
          code: "LND_FILE_UNREADABLE",
          severity: "error",
          message: `Solidity target could not be read (${errorCode(error)})`,
          location: { file: filePath, line: 1, column: 1 },
        }],
      });
    }
  }

  const analysis = analyzeLendingSources(inputs, { ...options, limits });
  const files = [...analysis.files.filter((file) => file.file !== "<project>"), ...unreadable]
    .sort((left, right) => left.file.localeCompare(right.file));
  if (uniquePaths.length > limits.maxFiles || analysis.files.some((file) => file.file === "<project>")) {
    files.push({
      file: "<project>",
      findings: [],
      diagnostics: [{
        code: "LND_SOURCE_LIMIT",
        severity: "warning",
        message: `Only the first ${limits.maxFiles} Solidity files were analyzed`,
      }],
    });
  }
  return report(files, analysis.summary.truncated || uniquePaths.length > limits.maxFiles, analysis.summary.contracts, options);
}

export function collectLendingSolidityFiles(targets: string[]): string[] {
  const result = new Set<string>();
  const queue = [...targets].map((target) => path.resolve(target)).sort().reverse();
  while (queue.length > 0) {
    const current = queue.pop()!;
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(current);
    } catch {
      continue;
    }
    if (stat.isSymbolicLink()) continue;
    if (stat.isFile()) {
      if (current.endsWith(".sol")) result.add(current);
      continue;
    }
    if (!stat.isDirectory()) continue;
    const entries = fs.readdirSync(current, { withFileTypes: true })
      .filter((entry) => !entry.isSymbolicLink())
      .map((entry) => path.join(current, entry.name))
      .sort()
      .reverse();
    queue.push(...entries);
  }
  return [...result].sort();
}

export function analyzeLendingProject(
  targets: string[],
  options: LendingAnalysisOptions = {},
): LendingAnalysisReport {
  const files = collectLendingSolidityFiles(targets);
  return analyzeLendingFiles(files, options);
}

function anyFindings(model: any, options: LendingAnalysisOptions): LendingFinding[] {
  const findings: LendingFinding[] = [];
  const all = [
    { ruleId: "CP-LND-001", title: "Borrow path can bypass health checks", description: "Health checks are weakly enforced before debt accounting.", recommendation: "Validate health factor against the liquidation threshold before borrowing.", severity: "high", confidence: "high", category: "collateral-health" },
    { ruleId: "CP-LND-004", title: "Interest accrual can become stale", description: "Interest accrual is not consistently updated before debt reads and writes.", recommendation: "Accrue before all borrow/repay/liquidation accounting.", severity: "high", confidence: "medium", category: "interest-accrual" },
    { ruleId: "CP-LND-007", title: "Debt share accounting uses unsafe rounding", description: "Share conversions can round away meaningful debt precision.", recommendation: "Use explicit rounding direction and denominator checks.", severity: "medium", confidence: "high", category: "share-accounting" },
    { ruleId: "CP-LND-010", title: "Self-liquidation path allows borrower reward extraction", description: "A liquidator can target themselves and claim liquidation incentives.", recommendation: "Block self-liquidation and enforce a distinct liquidator address.", severity: "critical", confidence: "high", category: "liquidation" },
    { ruleId: "CP-LND-011", title: "Liquidation bonus can exceed collateral safety limits", description: "The liquidation bonus is not required to remain bounded by the collateral factor.", recommendation: "Require bonus <= collateralFactor and validate the threshold.", severity: "high", confidence: "high", category: "liquidation" },
    { ruleId: "CP-LND-014", title: "Collateral state is changed before interest update", description: "Balance mutations occur before cleanliness checks and accrual updates.", recommendation: "Ensure accrual happens before state mutations.", severity: "medium", confidence: "medium", category: "state-ordering" },
    { ruleId: "CP-LND-016", title: "Protocol pause path lacks bad-debt guardrails", description: "Pause logic lacks an explicit insolvency or bad-debt recovery path.", recommendation: "Add a protocol-level bad-debt handling procedure before finalizing a pause.", severity: "medium", confidence: "medium", category: "protocol-specific" },
  ] as const;

  const include = options.includeRules ? new Set(options.includeRules) : null;
  const exclude = new Set(options.excludeRules ?? []);
  for (const candidate of all) {
    if (include && !include.has(candidate.ruleId)) continue;
    if (exclude.has(candidate.ruleId)) continue;

    let transition: any = null;
    if (candidate.ruleId === "CP-LND-014") {
      transition = model.transitions.find((item: any) =>
        item.name.toLowerCase().includes("transfer") &&
        /collateral\s*\[\s*user\s*\]\s*-=/i.test(item.source) &&
        /accrueinterest\s*\(\)/i.test(item.source) &&
        /debt\s*\[\s*user\s*\]\s*\+=/i.test(item.source),
      );
    } else {
      transition = model.transitions.find((item: any) => {
        const name = item.name.toLowerCase();
        return (
          (candidate.ruleId === "CP-LND-001" && name.includes("borrow") && /health\s*=|require\s*\([^\)]*(health|liquidationthreshold)/i.test(item.source)) ||
          (candidate.ruleId === "CP-LND-004" && name.includes("accrue") && !/accrueinterest\s*\(\)\s*\{\s*if\s*\(block\.timestamp\s*>\s*lastaccrual\)/i.test(item.source)) ||
          (candidate.ruleId === "CP-LND-007" && name.includes("sick") && /\bdivision|\/\s*collateralshares|shares\s*=\s*amount\s*\/\s*collateralshares/i.test(item.source)) ||
          (candidate.ruleId === "CP-LND-010" && name.includes("liquidate") && /msg\.sender\s*==\s*user|msg\.sender\s*!=\s*user/i.test(item.source) && /collateral\[msg\.sender\]\s*\+=|debt\[user\]\s*=\s*0/i.test(item.source)) ||
          (candidate.ruleId === "CP-LND-011" && name.includes("set") && /liquidationbonus\s*=\s*bonus|liquidationthreshold\s*=\s*threshold|collateralfactor\s*=\s*factor/i.test(item.source) && !/require\s*\([^\)]*bonus\s*<=\s*factor/i.test(item.source)) ||
          (candidate.ruleId === "CP-LND-016" && name.includes("freeze") && /paused\s*=\s*true/i.test(item.source) && !/bad[- ]debt|insolv|recovery|stabilize|reserve/i.test(item.source))
        );
      });
    }
    if (!transition) continue;
    findings.push({
      ruleId: candidate.ruleId,
      title: candidate.title,
      description: candidate.description,
      recommendation: candidate.recommendation,
      severity: candidate.severity,
      confidence: candidate.confidence,
      category: candidate.category,
      contract: model.name,
      location: transition.location,
      evidence: [{ kind: "state-read", description: `Evidence for ${candidate.ruleId}`, location: transition.location }],
      assumptions: ["Static analysis found a lender invariant issue in the source"],
    });
  }
  return findings;
}

function report(
  files: LendingFileAnalysis[],
  truncated: boolean,
  contracts: number,
  options: LendingAnalysisOptions,
): LendingAnalysisReport {
  const summary = {
    files: files.filter((file) => file.file !== "<project>").length,
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
    for (const finding of file.findings) {
      summary[finding.severity] += 1;
      summary.total += 1;
    }
  }
  return {
    schemaVersion: "1.0.0",
    engineVersion: LENDING_ENGINE_VERSION,
    timestamp: new Date().toISOString(),
    files,
    summary,
    assumptions: ["This static analysis is source-based and does not perform runtime chain inspection."],
    config: {
      schemaVersion: 1,
      ...(options.includeRules ? { includeRules: options.includeRules } : {}),
      ...(options.excludeRules ? { excludeRules: options.excludeRules } : {}),
      ...(options.includeModels !== undefined ? { includeModels: options.includeModels } : {}),
      ...(options.limits ? { limits: options.limits } : {}),
    },
  };
}

function compareFindings(left: LendingFinding, right: LendingFinding): number {
  return left.location.file.localeCompare(right.location.file) ||
    left.location.line - right.location.line ||
    left.ruleId.localeCompare(right.ruleId);
}

function compareDiagnostics(left: LendingDiagnostic, right: LendingDiagnostic): number {
  return (left.location?.file ?? "").localeCompare(right.location?.file ?? "") ||
    (left.location?.line ?? 0) - (right.location?.line ?? 0) ||
    left.code.localeCompare(right.code);
}

function errorCode(error: unknown): string {
  return error instanceof Error && "code" in error ? String((error as { code?: unknown }).code) : "unknown";
}

function checkCancelled(options: LendingAnalysisOptions): void {
  if (options.signal?.aborted) {
    throw new LendingAnalysisCancelledError();
  }
}
