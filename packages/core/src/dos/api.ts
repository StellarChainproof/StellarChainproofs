/**
 * @packageDocumentation
 * @chainproof/core — Public High-Level DoS & Unbounded-Work Analysis API
 */

import * as fs from "fs";
import * as path from "path";
import { parseSolidity } from "../ast/parser";
import type {
  DosAnalysisOptions,
  DosAuditReport,
  DosAuditSummary,
  DosContractReport,
  DosFileReport,
  DosFinding,
  DosSourceInput,
  LoopBoundAnalysis,
  CallFanOutAnalysis,
  MitigationEvidence,
} from "./types";
import { DOS_ANALYSIS_SCHEMA_VERSION } from "./types";
import { DEFAULT_DOS_LIMITS, DosConfigError } from "./config";
import { extractLoopBounds } from "./loop-analyzer";
import { extractCallFanOuts } from "./call-fanout";
import { extractArrayGrowths } from "./growth-analyzer";
import { detectMitigations } from "./mitigation-detector";
import { detectDosVulnerabilities } from "./rules";

export class DosAnalysisCancelledError extends Error {
  constructor(message: string = "DoS and Unbounded-Work analysis was cancelled.") {
    super(message);
    this.name = "DosAnalysisCancelledError";
  }
}

export function collectDosSolidityFiles(
  targets: string[],
  limits: { maxFiles: number; maxSourceBytes: number } = DEFAULT_DOS_LIMITS,
): DosSourceInput[] {
  const result: DosSourceInput[] = [];

  function walk(currentPath: string): void {
    if (result.length >= limits.maxFiles) {
      throw new DosConfigError(`Maximum file limit of ${limits.maxFiles} exceeded during directory walk.`);
    }

    const stat = fs.statSync(currentPath);
    if (stat.isDirectory()) {
      const entries = fs.readdirSync(currentPath);
      for (const entry of entries) {
        if (entry === "node_modules" || entry === ".git" || entry === "dist" || entry === "artifacts") {
          continue;
        }
        walk(path.join(currentPath, entry));
      }
    } else if (stat.isFile() && currentPath.endsWith(".sol")) {
      if (stat.size > limits.maxSourceBytes) {
        throw new DosConfigError(
          `File "${currentPath}" size (${stat.size} bytes) exceeds maximum permitted limit (${limits.maxSourceBytes} bytes).`,
        );
      }
      const content = fs.readFileSync(currentPath, "utf-8");
      result.push({ file: currentPath, content });
    }
  }

  for (const t of targets) {
    if (fs.existsSync(t)) {
      walk(t);
    } else {
      throw new DosConfigError(`Target path not found: ${t}`);
    }
  }

  return result;
}

function resolveInputs(
  targets: string[] | DosSourceInput[],
  options?: DosAnalysisOptions,
): DosSourceInput[] {
  const limits = {
    maxFiles: options?.limits?.maxFiles ?? DEFAULT_DOS_LIMITS.maxFiles,
    maxSourceBytes: options?.limits?.maxSourceBytes ?? DEFAULT_DOS_LIMITS.maxSourceBytes,
  };

  if (targets.length === 0) {
    throw new DosConfigError("No targets provided for DoS analysis.");
  }

  if (typeof targets[0] === "string") {
    return collectDosSolidityFiles(targets as string[], limits);
  }

  const inputs = targets as DosSourceInput[];
  if (inputs.length > limits.maxFiles) {
    throw new DosConfigError(`Provided ${inputs.length} files exceeds maximum limit of ${limits.maxFiles}.`);
  }

  for (const inp of inputs) {
    if (inp.content && Buffer.byteLength(inp.content, "utf-8") > limits.maxSourceBytes) {
      throw new DosConfigError(`File "${inp.file}" exceeds maximum permitted size.`);
    }
  }

  return inputs;
}

export function inspectDosLoops(
  targets: string[] | DosSourceInput[],
  options?: DosAnalysisOptions,
): LoopBoundAnalysis[] {
  const inputs = resolveInputs(targets, options);
  const allLoops: LoopBoundAnalysis[] = [];

  for (const inp of inputs) {
    if (options?.signal?.isCancelled()) {
      throw new DosAnalysisCancelledError();
    }

    let ast = inp.ast;
    if (!ast) {
      const parsed = parseSolidity(inp.content, inp.file);
      ast = parsed.ast;
    }
    if (!ast) continue;

    for (const child of ast.children || []) {
      if (child.type === "ContractDefinition") {
        const contractName = child.name || "Contract";
        const loops = extractLoopBounds(child, contractName, inp.content, inp.file);
        allLoops.push(...loops);
      }
    }
  }

  return allLoops;
}

export function inspectDosCallFanOut(
  targets: string[] | DosSourceInput[],
  options?: DosAnalysisOptions,
): CallFanOutAnalysis[] {
  const inputs = resolveInputs(targets, options);
  const allCalls: CallFanOutAnalysis[] = [];

  for (const inp of inputs) {
    if (options?.signal?.isCancelled()) {
      throw new DosAnalysisCancelledError();
    }

    let ast = inp.ast;
    if (!ast) {
      const parsed = parseSolidity(inp.content, inp.file);
      ast = parsed.ast;
    }
    if (!ast) continue;

    for (const child of ast.children || []) {
      if (child.type === "ContractDefinition") {
        const contractName = child.name || "Contract";
        const calls = extractCallFanOuts(child, contractName, inp.content, inp.file);
        allCalls.push(...calls);
      }
    }
  }

  return allCalls;
}

export async function auditDosSafety(
  targets: string[] | DosSourceInput[],
  options?: DosAnalysisOptions,
): Promise<DosAuditReport> {
  const inputs = resolveInputs(targets, options);
  const fileReports: DosFileReport[] = [];
  const allFindings: DosFinding[] = [];
  const allMitigations: MitigationEvidence[] = [];

  let totalContracts = 0;
  let totalLoopsAnalyzed = 0;
  let unboundedLoopsFound = 0;
  let pushPaymentsFound = 0;
  let returnBombRisksFound = 0;
  let callFanOutsFound = 0;
  let storageClearingFound = 0;
  let arrayGrowthPointsFound = 0;

  for (const inp of inputs) {
    if (options?.signal?.isCancelled()) {
      throw new DosAnalysisCancelledError();
    }

    let ast = inp.ast;
    if (!ast) {
      const parsed = parseSolidity(inp.content, inp.file);
      ast = parsed.ast;
    }

    const contractReports: DosContractReport[] = [];
    let fileFindings: DosFinding[] = [];

    if (ast) {
      fileFindings = detectDosVulnerabilities(ast, inp.content, inp.file, options);
      allFindings.push(...fileFindings);

      for (const child of ast.children || []) {
        if (child.type === "ContractDefinition") {
          totalContracts++;
          const cName = child.name || "Contract";
          const loops = extractLoopBounds(child, cName, inp.content, inp.file);
          const calls = extractCallFanOuts(child, cName, inp.content, inp.file);
          const growths = extractArrayGrowths(child, cName, inp.content, inp.file);
          const mitigations = detectMitigations(child, cName, inp.content, inp.file);

          totalLoopsAnalyzed += loops.length;
          unboundedLoopsFound += loops.filter((l) => l.boundType === "storage_array_bounded" || l.boundType === "unbounded").length;
          pushPaymentsFound += calls.filter((c) => c.isPushPayment && c.isInsideLoop).length;
          returnBombRisksFound += calls.filter((c) => c.callType === "low_level_call" && !c.hasReturndataSizeCheck).length;
          callFanOutsFound += calls.filter((c) => c.isInsideLoop).length;
          storageClearingFound += loops.filter((l) => l.hasStorageDeletions).length;
          arrayGrowthPointsFound += growths.length;

          allMitigations.push(...mitigations);

          const cFindings = fileFindings.filter((f) => f.file === inp.file);

          contractReports.push({
            contractName: cName,
            file: inp.file,
            totalLoops: loops.length,
            unboundedLoops: loops.filter((l) => l.boundType === "storage_array_bounded" || l.boundType === "unbounded").length,
            externalCallsInLoops: calls.filter((c) => c.isInsideLoop).length,
            pushPaymentPatterns: calls.filter((c) => c.isPushPayment && c.isInsideLoop).length,
            returnBombRisks: calls.filter((c) => c.callType === "low_level_call" && !c.hasReturndataSizeCheck).length,
            growthEndpoints: growths.length,
            loops,
            callFanOuts: calls,
            arrayGrowths: growths,
            mitigations,
            findings: cFindings,
          });
        }
      }
    }

    fileReports.push({
      file: inp.file,
      contracts: contractReports,
      findings: fileFindings,
    });
  }

  const severityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    gas: 0,
  };

  for (const f of allFindings) {
    if (f.severity in severityCounts) {
      severityCounts[f.severity as keyof typeof severityCounts]++;
    }
  }

  const passed = severityCounts.critical === 0 && severityCounts.high === 0;

  const summary: DosAuditSummary = {
    totalFiles: inputs.length,
    totalContracts,
    totalLoopsAnalyzed,
    unboundedLoopsFound,
    pushPaymentsFound,
    returnBombRisksFound,
    callFanOutsFound,
    storageClearingFound,
    arrayGrowthPointsFound,
    mitigationsRecognized: allMitigations.length,
    findingsCount: severityCounts,
    passed,
  };

  return {
    schemaVersion: DOS_ANALYSIS_SCHEMA_VERSION,
    createdAt: new Date().toISOString(),
    summary,
    files: fileReports,
    findings: allFindings,
    mitigations: allMitigations,
  };
}
