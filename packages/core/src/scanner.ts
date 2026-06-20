import * as fs from "fs";
import * as path from "path";
import { parseSolidity } from "./ast/parser";
import {
  buildImportGraph,
  buildMergedContractViews,
  hasImportDirectives,
} from "./ast/import-graph";
import { runSlither, isSlitherAvailable } from "./ast/slither";
import { detectReentrancy } from "./rules/swc107-reentrancy";
import { detectTxOrigin } from "./rules/swc115-tx-origin";
import { detectUnprotectedUpgrade } from "./rules/swc116-unprotected-upgrade";
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

/**
 * Expand the file list to include locally resolvable imports.
 */
function expandWithImports(initialFiles: string[]): string[] {
  const discovered = new Set(initialFiles.map((f) => path.resolve(f)));
  const queue = [...discovered];

  while (queue.length > 0) {
    const absolutePath = queue.shift()!;
    if (!fs.existsSync(absolutePath)) continue;

    let source: string;
    try {
      source = fs.readFileSync(absolutePath, "utf-8");
    } catch {
      continue;
    }

    const { ast } = parseSolidity(source, absolutePath);
    if (!ast) continue;

    const partialGraph = buildImportGraph([absolutePath]);
    for (const imported of partialGraph.edges.get(absolutePath) ?? []) {
      if (!discovered.has(imported) && fs.existsSync(imported)) {
        discovered.add(imported);
        queue.push(imported);
      }
    }
  }

  return [...discovered];
}

function runRulesOnView(
  view: ReturnType<typeof buildMergedContractViews>[number],
  config: ScanConfig
): Finding[] {
  const ruleOptions = { contractView: view };
  return [
    ...detectReentrancy(view.node, view.source, view.file, ruleOptions),
    ...detectTxOrigin(view.node, view.source, view.file, ruleOptions),
    ...detectUnprotectedUpgrade(view.node, view.source, view.file, ruleOptions),
  ];
}

function runRulesOnFile(
  ast: NonNullable<ReturnType<typeof parseSolidity>["ast"]>,
  source: string,
  filePath: string
): Finding[] {
  return [
    ...detectReentrancy(ast, source, filePath),
    ...detectTxOrigin(ast, source, filePath),
    ...detectUnprotectedUpgrade(ast, source, filePath),
    ...detectIntegerOverflow(ast, source, filePath),
    ...detectUncheckedReturn(ast, source, filePath),
  ];
}

async function scanFileLegacy(
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

  let findings = runRulesOnFile(ast, source, filePath);
  const gasHints = detectGasIssues(ast, source, filePath);

  const slitherRan = config.useSlither && isSlitherAvailable();
  if (slitherRan) {
    const slitherFindings = runSlither(filePath);
    const existingKeys = new Set(findings.map((f) => `${f.line}-${f.title}`));
    for (const sf of slitherFindings) {
      if (!existingKeys.has(`${sf.line}-${sf.title}`)) {
        findings.push(sf);
      }
    }
  }

  if (config.minSeverity) {
    const minRank = SEVERITY_RANK[config.minSeverity];
    findings = findings.filter((f) => SEVERITY_RANK[f.severity] >= minRank);
  }

  if (config.useLLM && config.apiKey && findings.length > 0) {
    findings = await enhanceFindingsWithLLM(findings, source, config.apiKey);
  }


  return { file: filePath, findings, gasHints, slitherRan };
}

async function scanWithImportGraph(
  files: string[],
  config: ScanConfig
): Promise<FileScanResult[]> {
  const graph = buildImportGraph(files);
  const views = buildMergedContractViews(graph);
  const findingsByFile = new Map<string, Finding[]>();
  const gasByFile = new Map<string, ReturnType<typeof detectGasIssues>>();
  const slitherByFile = new Map<string, boolean>();
  const parseErrors = new Map<string, string>();

  for (const filePath of files) {
    findingsByFile.set(path.resolve(filePath), []);
    gasByFile.set(path.resolve(filePath), []);
    slitherByFile.set(path.resolve(filePath), false);
  }

  for (const warning of graph.warnings) {
    console.warn(`[ChainProof] ${warning}`);
  }

  for (const parsed of graph.files.values()) {
    let findings = [
      ...detectIntegerOverflow(parsed.ast, parsed.source, parsed.absolutePath),
      ...detectUncheckedReturn(parsed.ast, parsed.source, parsed.absolutePath),
    ];

    for (const view of views.filter((v) => v.file === parsed.absolutePath)) {
      findings.push(...runRulesOnView(view, config));
    }

    findings = dedupeFindings(findings);

    const slitherRan = config.useSlither && isSlitherAvailable();
    if (slitherRan) {
      const slitherFindings = runSlither(parsed.filePath);
      const existingKeys = new Set(findings.map((f) => findingKey(f)));
      for (const sf of slitherFindings) {
        if (!existingKeys.has(findingKey(sf))) {
          findings.push(sf);
        }
      }
    }
    slitherByFile.set(parsed.absolutePath, slitherRan);

    if (config.minSeverity) {
      const minRank = SEVERITY_RANK[config.minSeverity];
      findings = findings.filter((f) => SEVERITY_RANK[f.severity] >= minRank);
    }

    if (config.useLLM && config.apiKey && findings.length > 0) {
      findings = await enhanceFindingsWithLLM(findings, parsed.source, config.apiKey);
    }

    findingsByFile.set(parsed.absolutePath, findings);
    gasByFile.set(parsed.absolutePath, detectGasIssues(parsed.ast, parsed.source, parsed.absolutePath));
  }

  for (const filePath of files) {
    const absolutePath = path.resolve(filePath);
    if (!graph.files.has(absolutePath) && !parseErrors.has(absolutePath)) {
      parseErrors.set(absolutePath, `Could not parse or read file: ${filePath}`);
    }
  }

  return files.map((filePath) => {
    const absolutePath = path.resolve(filePath);
    return {
      file: filePath,
      findings: findingsByFile.get(absolutePath) ?? [],
      gasHints: gasByFile.get(absolutePath) ?? [],
      slitherRan: slitherByFile.get(absolutePath) ?? false,
      parseError: parseErrors.get(absolutePath),
    };
  });
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];
  for (const finding of findings) {
    const key = findingKey(finding);
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(finding);
  }
  return result;
}

function findingKey(finding: Finding): string {
  return `${finding.id}-${finding.file}-${finding.definedIn ?? ""}-${finding.line}-${finding.title}`;
}

export async function scan(config: ScanConfig): Promise<ScanResult> {
  const initialFiles = collectSolFiles(config.targets);
  const files = initialFiles.length > 0 ? expandWithImports(initialFiles) : initialFiles;

  let fileResults: FileScanResult[];

  if (files.length === 0) {
    fileResults = [];
  } else if (files.length === 1) {
    const graph = buildImportGraph(files);
    if (hasImportDirectives(graph)) {
      fileResults = await scanWithImportGraph(files, config);
    } else {
      fileResults = [await scanFileLegacy(files[0], config)];
    }
  } else {
    const graph = buildImportGraph(files);
    if (hasImportDirectives(graph)) {
      fileResults = await scanWithImportGraph(files, config);
    } else {
      fileResults = await Promise.all(files.map((f) => scanFileLegacy(f, config)));
    }
  }

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
