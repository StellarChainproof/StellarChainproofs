import * as fs from "fs";
import * as path from "path";
import { parseSolidity } from "./ast/parser";
import { runSlither, isSlitherAvailable } from "./ast/slither";
import { detectReentrancy } from "./rules/swc107-reentrancy";
import { detectTxOrigin } from "./rules/swc115-tx-origin";
import { detectIntegerOverflow, detectUncheckedReturn } from "./rules/swc101-overflow";
import { detectGasIssues } from "./rules/gas-optimizer";
import { enhanceFindingsWithLLM } from "./llm/enhancer";
import type {
  ScanConfig,
  ScanResult,
  FileScanResult,
  Finding,
  Severity,
} from "./types";

const VERSION = "0.1.0";

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  gas: 0,
};

function collectSolFiles(targets: string[]): string[] {
  const files: string[] = [];
  for (const target of targets) {
    if (!fs.existsSync(target)) continue;
    const stat = fs.statSync(target);
    if (stat.isDirectory()) {
      const entries = fs.readdirSync(target, { recursive: true } as { recursive: boolean }) as string[];
      entries
        .filter((e) => e.endsWith(".sol"))
        .forEach((e) => files.push(path.join(target, e)));
    } else if (target.endsWith(".sol")) {
      files.push(target);
    }
  }
  return [...new Set(files)];
}

async function scanFile(
  filePath: string,
  config: ScanConfig
): Promise<FileScanResult> {
  let source: string;
  try {
    source = fs.readFileSync(filePath, "utf-8");
  } catch (e) {
    return {
      file: filePath,
      findings: [],
      gasHints: [],
      slitherRan: false,
      parseError: `Could not read file: ${e}`,
    };
  }

  const { ast, error } = parseSolidity(source, filePath);

  if (!ast) {
    return {
      file: filePath,
      findings: [],
      gasHints: [],
      slitherRan: false,
      parseError: error,
    };
  }

  // ── AST-based rules ────────────────────────────────────────────────────────
  let findings: Finding[] = [
    ...detectReentrancy(ast, source, filePath),
    ...detectTxOrigin(ast, source, filePath),
    ...detectIntegerOverflow(ast, source, filePath),
    ...detectUncheckedReturn(ast, source, filePath),
  ];

  const gasHints = detectGasIssues(ast, source, filePath);

  // ── Slither (if available + enabled) ──────────────────────────────────────
  const slitherRan = config.useSlither && isSlitherAvailable();
  if (slitherRan) {
    const slitherFindings = runSlither(filePath);
    // Deduplicate by line + title
    const existingKeys = new Set(findings.map((f) => `${f.line}-${f.title}`));
    for (const sf of slitherFindings) {
      if (!existingKeys.has(`${sf.line}-${sf.title}`)) {
        findings.push(sf);
      }
    }
  }

  // ── Filter by minSeverity ──────────────────────────────────────────────────
  if (config.minSeverity) {
    const minRank = SEVERITY_RANK[config.minSeverity];
    findings = findings.filter((f) => SEVERITY_RANK[f.severity] >= minRank);
  }

  // ── LLM enhancement ────────────────────────────────────────────────────────
  if (config.useLLM && findings.length > 0) {
    findings = await enhanceFindingsWithLLM(findings, source, config);
  }


  return { file: filePath, findings, gasHints, slitherRan };
}

export async function scan(config: ScanConfig): Promise<ScanResult> {
  const files = collectSolFiles(config.targets);

  const fileResults = await Promise.all(
    files.map((f) => scanFile(f, config))
  );

  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    gas: 0,
    total: 0,
  };

  for (const r of fileResults) {
    for (const f of r.findings) {
      summary[f.severity]++;
      summary.total++;
    }
    summary.gas += r.gasHints.length;
    summary.total += r.gasHints.length;
  }

  return {
    version: VERSION,
    timestamp: new Date().toISOString(),
    files: fileResults,
    summary,
  };
}
