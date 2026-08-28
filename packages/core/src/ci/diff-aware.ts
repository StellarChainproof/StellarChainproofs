import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import type { Finding, ScanResult, ScanConfig, Severity } from "../types";
import type { CIDiffConfig, CIBaseline, CIIntegrationConfig } from "./types";
import { computeFingerprint } from "../diff";
import { scan } from "../scanner";

// ─── Git Diff Parsing ────────────────────────────────────────────────────────

/**
 * Result of parsing a git diff between two refs.
 */
export interface GitDiffResult {
  /** Files added in the new ref */
  added: string[];
  /** Files modified between refs */
  modified: string[];
  /** Files deleted in the new ref */
  deleted: string[];
  /** Files renamed from old to new path (old -> new) */
  renamed: Array<{ from: string; to: string }>;
  /** All changed file paths (union of added + modified) */
  allChanged: string[];
  /** Base commit SHA */
  baseSha: string;
  /** Head commit SHA */
  headSha: string;
}

/**
 * Parses the output of `git diff --name-status` to extract changed files.
 *
 * @param baseRef - Base branch/ref to diff against
 * @param headRef - Head branch/ref (defaults to HEAD)
 * @param includeExtensions - File extensions to include (default: [".sol"])
 * @returns Parsed diff result
 * @throws If git diff command fails
 */
export function parseGitDiff(
  baseRef: string,
  headRef: string = "HEAD",
  includeExtensions: string[] = [".sol"],
): GitDiffResult {
  const baseSha = execSync(`git rev-parse ${baseRef}`, {
    encoding: "utf-8",
  }).trim();

  const headSha = execSync(`git rev-parse ${headRef}`, {
    encoding: "utf-8",
  }).trim();

  // Get raw diff output
  const rawDiff = execSync(
    `git diff --name-status ${baseRef}...${headRef}`,
    { encoding: "utf-8" }
  ).trim();

  const added: string[] = [];
  const modified: string[] = [];
  const deleted: string[] = [];
  const renamed: Array<{ from: string; to: string }> = [];

  for (const line of rawDiff.split("\n")) {
    if (!line.trim()) continue;
    const parts = line.split("\t");
    const status = parts[0];

    switch (status) {
      case "A": {
        const file = parts[1];
        if (matchesExtensions(file, includeExtensions)) {
          added.push(file);
        }
        break;
      }
      case "M": {
        const file = parts[1];
        if (matchesExtensions(file, includeExtensions)) {
          modified.push(file);
        }
        break;
      }
      case "D": {
        const file = parts[1];
        if (matchesExtensions(file, includeExtensions)) {
          deleted.push(file);
        }
        break;
      }
      case "R100":
      case "R": {
        // Rename: status\toldPath\tnewPath
        const from = parts[1];
        const to = parts[2];
        if (matchesExtensions(to, includeExtensions)) {
          renamed.push({ from, to });
        }
        break;
      }
      default:
        break;
    }
  }

  // Handle renamed files as both added (new path) for scanning
  const renamedNew = renamed.map((r) => r.to);

  const allChanged = [...new Set([...added, ...modified, ...renamedNew])];

  return {
    added,
    modified,
    deleted,
    renamed,
    allChanged,
    baseSha,
    headSha,
  };
}

/**
 * Checks if a file path matches any of the given extensions.
 */
function matchesExtensions(filePath: string, extensions: string[]): boolean {
  return extensions.some((ext) => filePath.endsWith(ext));
}

// ─── Diff-Aware Scanning ─────────────────────────────────────────────────────

/**
 * Performs a diff-aware scan, only scanning files that changed between
 * the base and head refs. Falls back to full scan if diff computation fails.
 *
 * @param config - CI integration configuration with diff settings
 * @returns An object with the current scan result and optional diff information
 */
export async function diffAwareScan(
  config: CIIntegrationConfig,
): Promise<{
  result: ScanResult;
  diff?: { introduced: Finding[]; resolved: Finding[]; persisted: Finding[] };
  gitDiff?: GitDiffResult;
}> {
  const diffConfig = config.diff;
  const useDiff = diffConfig?.enabled && diffConfig?.baseRef;

  if (!useDiff) {
    // Full scan mode
    const result = await scan(config.scanConfig);
    return { result };
  }

  try {
    // Parse the git diff to find changed files
    const includeExtensions = diffConfig!.includeExtensions || [".sol"];
    const gitDiff = parseGitDiff(
      diffConfig!.baseRef!,
      diffConfig!.headSha || "HEAD",
      includeExtensions
    );

    if (gitDiff.allChanged.length === 0) {
      // No Solidity files changed — return empty scan
      return {
        result: {
          version: "0.1.0",
          timestamp: new Date().toISOString(),
          files: [],
          summary: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            gas: 0,
            total: 0,
          },
        },
        diff: { introduced: [], resolved: [], persisted: [] },
        gitDiff,
      };
    }

    // Filter scan targets to only changed files
    const changedFiles = gitDiff.allChanged.filter((f) => {
      // Check exclusion patterns
      if (diffConfig?.excludePatterns) {
        const isExcluded = diffConfig.excludePatterns.some((pattern) =>
          matchGlob(f, pattern)
        );
        if (isExcluded) return false;
      }
      // Check file exists (renamed files may not exist at old path)
      return fs.existsSync(f);
    });

    if (changedFiles.length === 0) {
      return {
        result: {
          version: "0.1.0",
          timestamp: new Date().toISOString(),
          files: [],
          summary: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            gas: 0,
            total: 0,
          },
        },
        diff: { introduced: [], resolved: [], persisted: [] },
        gitDiff,
      };
    }

    // Scan only changed files
    const diffScanConfig: ScanConfig = {
      ...config.scanConfig,
      targets: changedFiles,
    };
    const currentResult = await scan(diffScanConfig);

    // Also scan the baseline to compute diff
    let baselineResult: ScanResult | null = null;

    try {
      // Check if a baseline artifact exists
      const baselinePath = path.join(
        process.cwd(),
        "chainproof-reports",
        "baseline.json"
      );

      if (fs.existsSync(baselinePath)) {
        const baselineData = fs.readFileSync(baselinePath, "utf-8");
        const baseline: CIBaseline = JSON.parse(baselineData);
        baselineResult = baseline.scanResult;
      } else {
        // Scan the base ref to create baseline
        const baseScanConfig: ScanConfig = {
          ...config.scanConfig,
          targets: changedFiles,
        };

        // Stash and checkout base ref for scanning
        const isDirty =
          execSync("git status --porcelain", { encoding: "utf-8" }).trim()
            .length > 0;
        let currentRef = "";
        try {
          currentRef = execSync("git symbolic-ref --short -q HEAD", {
            encoding: "utf-8",
          }).trim();
          if (!currentRef) {
            currentRef = execSync("git rev-parse HEAD", {
              encoding: "utf-8",
            }).trim();
          }
        } catch {
          currentRef = execSync("git rev-parse HEAD", {
            encoding: "utf-8",
          }).trim();
        }

        let stashed = false;
        if (isDirty) {
          execSync("git stash push -m 'chainproof-diff-tmp'", {
            stdio: "ignore",
          });
          stashed = true;
        }

        try {
          execSync(`git checkout ${diffConfig!.baseRef!}`, {
            stdio: "ignore",
          });
          baselineResult = await scan(baseScanConfig);
        } finally {
          execSync(`git checkout ${currentRef}`, { stdio: "ignore" });
          if (stashed) {
            execSync("git stash pop", { stdio: "ignore" });
          }
        }
      }
    } catch {
      // Baseline scan failed — fall back to full diff if configured
      if (diffConfig?.fallbackToFullScan) {
        const fullResult = await scan(config.scanConfig);
        return { result: fullResult, gitDiff };
      }
    }

    // Compute diff between baseline and current
    if (baselineResult) {
      const diff = computeDiff(baselineResult, currentResult);
      return { result: currentResult, diff, gitDiff };
    }

    return { result: currentResult, gitDiff };
  } catch (err) {
    // Diff computation failed
    if (diffConfig?.fallbackToFullScan) {
      const result = await scan(config.scanConfig);
      return { result };
    }
    throw err;
  }
}

// ─── Diff Computation ────────────────────────────────────────────────────────

/**
 * Computes introduced, resolved, and persisted findings between two scan results.
 * Uses fingerprint-based matching with line tolerance for stable identification.
 */
export function computeDiff(
  baseline: ScanResult,
  current: ScanResult,
): { introduced: Finding[]; resolved: Finding[]; persisted: Finding[] } {
  const baselineFindings = baseline.files.flatMap((f) => f.findings);
  const currentFindings = current.files.flatMap((f) => f.findings);

  const baselineMatched = new Set<number>();
  const currentMatched = new Set<number>();

  // Exact fingerprint matching
  const baselineFPMap = new Map<string, number[]>();
  baselineFindings.forEach((f, idx) => {
    const fp = computeFingerprint(f);
    if (!baselineFPMap.has(fp)) baselineFPMap.set(fp, []);
    baselineFPMap.get(fp)!.push(idx);
  });

  currentFindings.forEach((cf, currentIdx) => {
    const fp = computeFingerprint(cf);
    const indices = baselineFPMap.get(fp);
    if (indices && indices.length > 0) {
      const baselineIdx = indices.shift()!;
      baselineMatched.add(baselineIdx);
      currentMatched.add(currentIdx);
    }
  });

  // Fuzzy line tolerance matching (±3 lines)
  currentFindings.forEach((cf, currentIdx) => {
    if (currentMatched.has(currentIdx)) return;
    const normFile = cf.file.replace(/\\/g, "/");
    const snippetHash = hashSnippet(cf.snippet);

    for (let baselineIdx = 0; baselineIdx < baselineFindings.length; baselineIdx++) {
      if (baselineMatched.has(baselineIdx)) continue;
      const bf = baselineFindings[baselineIdx];

      if (bf.id === cf.id && bf.file.replace(/\\/g, "/") === normFile) {
        const lineDiff = Math.abs(cf.line - bf.line);
        const baseSnippetHash = hashSnippet(bf.snippet);

        if (lineDiff <= 3 && (snippetHash === baseSnippetHash || !cf.snippet || !bf.snippet)) {
          baselineMatched.add(baselineIdx);
          currentMatched.add(currentIdx);
          break;
        }
      }
    }
  });

  const introduced = currentFindings.filter((_, idx) => !currentMatched.has(idx));
  const resolved = baselineFindings.filter((_, idx) => !baselineMatched.has(idx));
  const persisted = currentFindings.filter((_, idx) => currentMatched.has(idx));

  return { introduced, resolved, persisted };
}

function hashSnippet(snippet?: string): string {
  if (!snippet) return "";
  const { createHash } = require("crypto");
  return createHash("sha256").update(snippet.trim()).digest("hex");
}

// ─── Artifact Management ─────────────────────────────────────────────────────

/**
 * Saves the current scan result as a baseline artifact for future diff comparisons.
 */
export function saveBaselineArtifact(
  result: ScanResult,
  branch: string,
  commitSha: string,
  outputDir?: string,
): string {
  const dir = outputDir || path.join(process.cwd(), "chainproof-reports");
  fs.mkdirSync(dir, { recursive: true });

  const baseline: CIBaseline = {
    scanResult: result,
    branch,
    commitSha,
    capturedAt: new Date().toISOString(),
    schemaVersion: "1.0.0",
  };

  const filePath = path.join(dir, "baseline.json");
  fs.writeFileSync(filePath, JSON.stringify(baseline, null, 2), "utf-8");
  return filePath;
}

/**
 * Loads a baseline artifact from disk.
 */
export function loadBaselineArtifact(
  baselinePath?: string,
): CIBaseline | null {
  const filePath =
    baselinePath ||
    path.join(process.cwd(), "chainproof-reports", "baseline.json");

  if (!fs.existsSync(filePath)) return null;

  try {
    const content = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(content);
  } catch {
    return null;
  }
}

// ─── Changed File Extraction Helpers ─────────────────────────────────────────

/**
 * Extracts only the files that exist on the filesystem from a list of paths.
 * Filters out deleted files and files matching exclusion patterns.
 */
export function filterExistingFiles(
  filePaths: string[],
  excludePatterns?: string[],
): string[] {
  return filePaths.filter((f) => {
    if (!fs.existsSync(f)) return false;
    if (excludePatterns) {
      return !excludePatterns.some((pattern) => matchGlob(f, pattern));
    }
    return true;
  });
}

/**
 * Resolves relative file paths to absolute paths.
 */
export function resolveFilePaths(
  filePaths: string[],
  basePath?: string,
): string[] {
  const base = basePath || process.cwd();
  return filePaths.map((f) => {
    if (path.isAbsolute(f)) return f;
    return path.resolve(base, f);
  });
}

/**
 * Extracts Solidity file paths from a git diff command output string.
 */
export function extractSolFilesFromDiffOutput(diffOutput: string): string[] {
  const files: string[] = [];
  for (const line of diffOutput.split("\n")) {
    if (!line.trim()) continue;
    const parts = line.split("\t");
    const file = parts[parts.length - 1];
    if (file && file.endsWith(".sol")) {
      files.push(file);
    }
  }
  return [...new Set(files)];
}

// ─── Suppression Policy Application ──────────────────────────────────────────

/**
 * Applies a suppression policy to filter out suppressed findings from a scan result.
 */
export function applySuppressionPolicy(
  findings: Finding[],
  policy: {
    suppressedRuleIds?: string[];
    suppressedSeverities?: Severity[];
    suppressedFiles?: string[];
    expiresAt?: string;
  },
): Finding[] {
  // Check if suppression has expired
  if (policy.expiresAt && new Date(policy.expiresAt) > new Date()) {
    return findings; // Suppression is active — filter out suppressed items
  }

  return findings.filter((f) => {
    if (policy.suppressedRuleIds?.includes(f.id)) return false;
    if (policy.suppressedSeverities?.includes(f.severity)) return false;
    if (
      policy.suppressedFiles?.some((pattern) => matchGlob(f.file, pattern))
    ) {
      return false;
    }
    return true;
  });
}

// ─── Fork Safety Checks ──────────────────────────────────────────────────────

/**
 * Detects whether the current CI run is from a forked repository.
 * Checks common environment variables for both GitLab and Bitbucket.
 */
export function detectFork(): { isFork: boolean; provider: "gitlab" | "bitbucket" | "unknown" } {
  // GitLab: CI_MERGE_REQUEST_SOURCE_BRANCH_NAME vs CI_MERGE_REQUEST_TARGET_BRANCH_NAME
  // Fork indicator: CI_PROJECT_NAMESPACE differs from CI_PROJECT_ROOT_NAMESPACE
  const glRootNs = process.env.CI_PROJECT_ROOT_NAMESPACE;
  const glProjectNs = process.env.CI_PROJECT_NAMESPACE;

  if (glRootNs && glProjectNs && glRootNs !== glProjectNs) {
    return { isFork: true, provider: "gitlab" };
  }

  // GitLab: CI_PIPELINE_SOURCE == "merge_request_event" + fork info
  const glFork = process.env.CI_MERGE_REQUEST_SOURCE_PROJECT_ID;
  const glProject = process.env.CI_PROJECT_ID;
  if (glFork && glProject && glFork !== glProject) {
    return { isFork: true, provider: "gitlab" };
  }

  // Bitbucket: BB_PR_FROM_COMMIT or PR-based pipeline from fork
  const bbFork = process.env.BB_PR_FROM_COMMIT;
  if (bbFork) {
    return { isFork: false, provider: "bitbucket" }; // Need more signals
  }

  // GitHub Actions: github.event.pull_request.head.repo.full_name != github.repository
  const ghHeadRepo = process.env.GITHUB_HEAD_REPOSITORY;
  const ghRepo = process.env.GITHUB_REPOSITORY;
  if (ghHeadRepo && ghRepo && ghHeadRepo !== ghRepo) {
    return { isFork: true, provider: "unknown" };
  }

  return { isFork: false, provider: "unknown" };
}

// ─── Glob Helper ─────────────────────────────────────────────────────────────

/**
 * Simple glob pattern matcher supporting * and ** wildcards.
 */
function matchGlob(filePath: string, pattern: string): boolean {
  const normalizedFile = filePath.replace(/\\/g, "/");
  const normalizedPattern = pattern.replace(/\\/g, "/");

  const regexStr = normalizedPattern
    .replace(/\./g, "\\.")
    .replace(/\*\*/g, "{{GLOBSTAR}}")
    .replace(/\*/g, "[^/]*")
    .replace(/\{\{GLOBSTAR\}\}/g, ".*");

  const regex = new RegExp(`^${regexStr}$`);
  return regex.test(normalizedFile);
}
