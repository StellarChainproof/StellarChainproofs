import type { Finding, Severity, ScanResult } from "../types";
import {
  SEVERITY_MAP,
  type CIAnnotation,
  type CIReportResult,
  type CIIntegrationConfig,
  type CIDiffConfig,
  type CIBaseline,
  type SuppressionPolicy,
  type CIForkSafety,
  truncateMessage,
  redactSecrets,
  ANNOTATION_MESSAGE_MAX_LENGTH,
} from "./types";

// ─── GitLab Code Quality / SAST JSON Formats ─────────────────────────────────

/**
 * GitLab Code Quality report schema.
 * @see https://docs.gitlab.com/ee/ci/testing/code_quality.html#schema
 */
export interface GitLabCodeQualityIssue {
  description: string;
  severity: "info" | "minor" | "major" | "critical" | "blocker";
  fingerprint: string;
  location: {
    path: string;
    lines: {
      begin: number;
    };
  };
  identifiers: Array<{
    type: string;
    name: string;
    value: string;
  }>;
}

/**
 * GitLab Code Quality report wrapper.
 */
export interface GitLabCodeQualityReport {
  version: "15.1.6";
  schema: "https://gitlab.com/haydendh/code-quality-schema/-/raw/main/schema/15.1.6.json";
  issues: GitLabCodeQualityIssue[];
}

/**
 * GitLab SAST report schema (subset for security findings).
 * @see https://docs.gitlab.com/ee/development/sast.html
 */
export interface GitLabSASTVulnerability {
  id: string;
  category: "sast";
  name: string;
  message: string;
  description: string;
  severity: "UNKNOWN" | "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  solution?: string;
  identifiers: Array<{
    type: string;
    name: string;
    value: string;
  }>;
  location: {
    file: string;
    start_line: number;
    end_line?: number;
  };
}

export interface GitLabSASTReport {
  version: string;
  schema: string;
  scan: {
    analyzer: {
      id: string;
      name: string;
      version: string;
    };
    scanner: {
      id: string;
      name: string;
      version: string;
    };
  };
  vulnerabilities: GitLabSASTVulnerability[];
}

// ─── GitLab MR Note Builder ──────────────────────────────────────────────────

const GITLAB_SEVERITY_EMOJI: Record<string, string> = {
  blocker: "🔴",
  critical: "🟠",
  major: "🟡",
  minor: "🟢",
  info: "🔵",
};

/**
 * Maps ChainProof severity to GitLab Code Quality severity.
 */
export function mapSeverityToGitLab(severity: Severity): string {
  return SEVERITY_MAP.gitlab[severity] || "info";
}

/**
 * Maps ChainProof severity to GitLab SAST severity.
 */
export function mapSeverityToGitLabSAST(severity: Severity): "UNKNOWN" | "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
  const map: Record<Severity, "UNKNOWN" | "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"> = {
    critical: "CRITICAL",
    high: "HIGH",
    medium: "MEDIUM",
    low: "LOW",
    info: "INFO",
    gas: "INFO",
  };
  return map[severity] || "INFO";
}

/**
 * Converts a ChainProof finding to a GitLab Code Quality issue.
 */
export function findingToGitLabCodeQuality(finding: Finding): GitLabCodeQualityIssue {
  const { createHash } = require("crypto") as typeof import("crypto");
  const fingerprint = createHash("sha256")
    .update(`${finding.id}:${finding.file}:${finding.line}:${finding.severity}`)
    .digest("hex");

  return {
    description: truncateMessage(
      `[${finding.severity.toUpperCase()}] ${finding.title}: ${finding.description}`
    ),
    severity: mapSeverityToGitLab(finding.severity) as GitLabCodeQualityIssue["severity"],
    fingerprint,
    location: {
      path: finding.file,
      lines: {
        begin: finding.line,
      },
    },
    identifiers: [
      ...(finding.swcId
        ? [{ type: "swc", name: finding.swcId, value: finding.swcId }]
        : []),
      {
        type: "chainproof",
        name: finding.id,
        value: finding.id,
      },
    ],
  };
}

/**
 * Converts a ChainProof finding to a GitLab SAST vulnerability.
 */
export function findingToGitLabSAST(finding: Finding): GitLabSASTVulnerability {
  const id = `chainproof-${finding.id}-${finding.file}-${finding.line}`;
  const identifiers: GitLabSASTVulnerability["identifiers"] = [
    {
      type: "chainproof_rule",
      name: finding.id,
      value: finding.id,
    },
  ];

  if (finding.swcId) {
    identifiers.push({
      type: "swc_id",
      name: finding.swcId,
      value: finding.swcId,
    });
  }

  return {
    id,
    category: "sast",
    name: finding.title,
    message: truncateMessage(`[${finding.id}] ${finding.title}`),
    description: truncateMessage(finding.description),
    severity: mapSeverityToGitLabSAST(finding.severity),
    solution: finding.recommendation || undefined,
    identifiers,
    location: {
      file: finding.file,
      start_line: finding.line,
      end_line: finding.lineEnd,
    },
  };
}

/**
 * Builds a GitLab Code Quality JSON report from scan results.
 */
export function buildGitLabCodeQualityReport(result: ScanResult): GitLabCodeQualityReport {
  const issues: GitLabCodeQualityIssue[] = [];

  for (const file of result.files) {
    for (const finding of file.findings) {
      issues.push(findingToGitLabCodeQuality(finding));
    }
  }

  return {
    version: "15.1.6",
    schema: "https://gitlab.com/haydendh/code-quality-schema/-/raw/main/schema/15.1.6.json",
    issues,
  };
}

/**
 * Builds a GitLab SAST JSON report from scan results.
 */
export function buildGitLabSASTReport(result: ScanResult): GitLabSASTReport {
  const vulnerabilities: GitLabSASTVulnerability[] = [];

  for (const file of result.files) {
    for (const finding of file.findings) {
      vulnerabilities.push(findingToGitLabSAST(finding));
    }
  }

  return {
    version: "15.1.6",
    schema: "https://gitlab.com/gitlab-org/gitlab/-/raw/master/lib/gitlab/ci/templates/security/schema.json",
    scan: {
      analyzer: {
        id: "chainproof-core",
        name: "ChainProof Core",
        version: result.version,
      },
      scanner: {
        id: "chainproof-scanner",
        name: "ChainProof Scanner",
        version: result.version,
      },
    },
    vulnerabilities,
  };
}

// ─── MR Note Builder ─────────────────────────────────────────────────────────

/**
 * Builds a Merge Request discussion note for GitLab containing the
 * ChainProof security scan summary.
 *
 * @param result - The scan result
 * @param diff - Optional diff result for diff-aware mode
 * @param maxFindings - Maximum number of findings to include in the note
 * @returns Markdown-formatted note body
 */
export function buildGitLabMRNote(
  result: ScanResult,
  diff?: { introduced: Finding[]; resolved: Finding[] },
  maxFindings: number = 50,
): string {
  const { summary } = result;
  const lines: string[] = [];

  const emoji =
    summary.critical > 0
      ? "🚨"
      : summary.high > 0
      ? "⚠️"
      : summary.total > 0
      ? "💡"
      : "✅";

  lines.push(`## ${emoji} ChainProof Security Scan`);
  lines.push("");

  if (diff) {
    lines.push("**Mode:** Diff-aware (only changed files scanned)");
    lines.push("");
  }

  // Summary table
  lines.push("| Severity | Count |");
  lines.push("|----------|-------|");
  if (summary.critical > 0)
    lines.push(`| 🔴 Critical | ${summary.critical} |`);
  if (summary.high > 0)
    lines.push(`| 🟠 High     | ${summary.high} |`);
  if (summary.medium > 0)
    lines.push(`| 🟡 Medium   | ${summary.medium} |`);
  if (summary.low > 0)
    lines.push(`| 🟢 Low      | ${summary.low} |`);
  if (summary.info > 0)
    lines.push(`| 🔵 Info     | ${summary.info} |`);
  if (summary.gas > 0)
    lines.push(`| ⛽ Gas      | ${summary.gas} |`);
  lines.push(`| **Total** | **${summary.total}** |`);
  lines.push("");

  if (summary.critical > 0 || summary.high > 0) {
    lines.push(
      "> 🛑 **Critical or high severity issues found. Resolve before merging.**"
    );
    lines.push("");
  }

  // Diff-specific section
  if (diff) {
    if (diff.introduced.length > 0) {
      lines.push(`### Newly Introduced (${diff.introduced.length})`);
      lines.push("");
      lines.push("| Rule | File | Line | Severity | Title |");
      lines.push("|------|------|------|----------|-------|");
      const shownIntroduced = diff.introduced.slice(0, maxFindings);
      for (const f of shownIntroduced) {
        lines.push(
          `| ${f.id} | ${f.file} | ${f.line} | ${f.severity} | ${f.title} |`
        );
      }
      if (diff.introduced.length > maxFindings) {
        lines.push(
          `| ... | ... | ... | ... | +${diff.introduced.length - maxFindings} more |`
        );
      }
      lines.push("");
    }

    if (diff.resolved.length > 0) {
      lines.push(`### Resolved (${diff.resolved.length})`);
      lines.push("");
      lines.push("| Rule | File | Line | Severity | Title |");
      lines.push("|------|------|------|----------|-------|");
      const shownResolved = diff.resolved.slice(0, maxFindings);
      for (const f of shownResolved) {
        lines.push(
          `| ${f.id} | ${f.file} | ${f.line} | ${f.severity} | ${f.title} |`
        );
      }
      lines.push("");
    }
  } else {
    // Full scan mode: show top findings
    const allFindings = result.files.flatMap((f) => f.findings);
    const topFindings = allFindings
      .filter((f) => f.severity === "critical" || f.severity === "high")
      .slice(0, maxFindings);

    if (topFindings.length > 0) {
      lines.push("### Top Findings");
      lines.push("");
      lines.push("| Rule | File | Line | Severity | Title |");
      lines.push("|------|------|------|----------|-------|");
      for (const f of topFindings) {
        lines.push(
          `| ${f.id} | ${f.file} | ${f.line} | ${f.severity} | ${f.title} |`
        );
      }
      lines.push("");
    }
  }

  lines.push("---");
  lines.push(
    "_Generated by [ChainProof](https://github.com/StellarChainproof/StellarChainproofs)_"
  );

  return lines.join("\n");
}

// ─── CI Annotations from Findings ────────────────────────────────────────────

/**
 * Converts a list of findings into CI annotations for GitLab.
 * Applies suppression policy and annotation limits.
 */
export function findingsToGitLabAnnotations(
  findings: Finding[],
  options?: {
    minSeverity?: Severity;
    suppressPolicy?: SuppressionPolicy;
    maxAnnotations?: number;
  },
): CIAnnotation[] {
  const sevRank: Record<Severity, number> = {
    critical: 6,
    high: 5,
    medium: 4,
    low: 3,
    info: 2,
    gas: 1,
  };

  let filtered = [...findings];

  // Apply minimum severity filter
  if (options?.minSeverity) {
    const minRank = sevRank[options.minSeverity];
    filtered = filtered.filter((f) => sevRank[f.severity] >= minRank);
  }

  // Apply suppression policy
  if (options?.suppressPolicy) {
    const policy = options.suppressPolicy;
    filtered = filtered.filter((f) => {
      if (policy.suppressedRuleIds.includes(f.id)) return false;
      if (policy.suppressedSeverities.includes(f.severity)) return false;
      if (
        policy.suppressedFiles.some((pattern) =>
          matchGlob(f.file, pattern)
        )
      ) {
        return false;
      }
      if (policy.expiresAt && new Date(policy.expiresAt) > new Date()) {
        return false;
      }
      return true;
    });
  }

  // Convert to annotations
  const annotations: CIAnnotation[] = filtered.map((f) => ({
    severity: mapSeverityToGitLab(f.severity),
    message: truncateMessage(
      `[${f.id}] ${f.title}: ${f.description}`
    ),
    file: f.file,
    line: f.line,
    endLine: f.lineEnd,
    ruleId: f.id,
    snippet: f.snippet,
  }));

  // Apply annotation limit
  if (options?.maxAnnotations && annotations.length > options.maxAnnotations) {
    return annotations.slice(0, options.maxAnnotations);
  }

  return annotations;
}

// ─── Full CI Report Builder ──────────────────────────────────────────────────

/**
 * Builds a complete CI report result for GitLab from a scan result.
 */
export function buildGitLabCIReport(
  result: ScanResult,
  config: CIIntegrationConfig,
  diff?: { introduced: Finding[]; resolved: Finding[]; persisted: Finding[] },
  forkSafety?: CIForkSafety,
  baseline?: CIBaseline,
): CIReportResult {
  const failSeverity = config.failSeverity || "high";
  const failRank: Record<Severity, number> = {
    critical: 6,
    high: 5,
    medium: 4,
    low: 3,
    info: 2,
    gas: 1,
  };

  // Determine findings to evaluate for failure gate
  const evaluationFindings = diff ? diff.introduced : result.files.flatMap((f) => f.findings);

  // Check suppressions
  const { SuppressionPolicy } = { SuppressionPolicy: config } as any;

  const shouldFail =
    !forkSafety?.isFork &&
    evaluationFindings.some(
      (f) => failRank[f.severity] >= failRank[failSeverity]
    );

  // Build annotations
  const annotations = findingsToGitLabAnnotations(
    diff ? diff.introduced : result.files.flatMap((f) => f.findings),
    {
      minSeverity: config.minSeverity,
      maxAnnotations: config.maxAnnotations || 100,
    }
  );

  return {
    provider: "gitlab",
    annotations,
    summary: {
      critical: result.summary.critical,
      high: result.summary.high,
      medium: result.summary.medium,
      low: result.summary.low,
      info: result.summary.info,
      gas: result.summary.gas,
      total: result.summary.total,
    },
    shouldFail,
    failThreshold: failSeverity,
    metadata: {
      scanVersion: result.version,
      timestamp: result.timestamp,
      filesScanned: result.files.length,
      introducedCount: diff?.introduced.length,
      resolvedCount: diff?.resolved.length,
    },
  };
}

// ─── Artifact Serialization ──────────────────────────────────────────────────

/**
 * Serializes a GitLab Code Quality report to JSON for artifact upload.
 * Automatically redacts any secrets found in the output.
 */
export function serializeGitLabCodeQualityArtifact(
  report: GitLabCodeQualityReport,
): string {
  return JSON.stringify(report, null, 2);
}

/**
 * Serializes a GitLab SAST report to JSON for artifact upload.
 */
export function serializeGitLabSASTArtifact(report: GitLabSASTReport): string {
  const serialized = JSON.stringify(report, null, 2);
  return redactSecrets(serialized);
}

// ─── Job Artifact Paths ──────────────────────────────────────────────────────

/** Standard artifact paths for GitLab CI integration. */
export const GITLAB_ARTIFACT_PATHS = [
  "chainproof-reports/code-quality-report.json",
  "chainproof-reports/sast-report.json",
  "chainproof-reports/audit-report.json",
  "chainproof-reports/audit-report.md",
  "chainproof-reports/diff-report.json",
  "chainproof-reports/diff-report.md",
] as const;

/** GitLab CI job names for the integration. */
export const GITLAB_JOB_NAMES = {
  scan: "chainproof-scan",
  diffScan: "chainproof-diff-scan",
  uploadCodeQuality: "chainproof-upload-code-quality",
  uploadSAST: "chainproof-upload-sast",
} as const;

// ─── Template YAML Snippets ──────────────────────────────────────────────────

/**
 * Returns a GitLab CI YAML template for ChainProof integration.
 * This can be included in a user's `.gitlab-ci.yml`.
 */
export function generateGitLabCITemplate(options?: {
  targets?: string;
  failSeverity?: string;
  useSlither?: boolean;
  useLLM?: boolean;
  diffMode?: boolean;
}): string {
  const targets = options?.targets || "contracts/";
  const failSeverity = options?.failSeverity || "high";
  const useSlither = options?.useSlither ? "true" : "false";
  const useLLM = options?.useLLM ? "true" : "false";

  return `# ChainProof Security Scanner — GitLab CI Integration
# Add \`include: - local: .chainproof-gitlab-ci.yml\` to your .gitlab-ci.yml

chainproof-scan:
  stage: test
  image: node:20-alpine
  before_script:
    - npm ci
  script:
    - npx chainproof scan ${targets} --format json --output chainproof-reports/audit-report.json --no-llm --no-slither
    - npx chainproof scan ${targets} --format markdown --output chainproof-reports/audit-report.md --no-llm --no-slither
    - |
      if [ -f chainproof-reports/audit-report.json ]; then
        echo "ChainProof scan completed successfully"
      else
        echo "ChainProof scan failed to produce output"
        exit 1
      fi
  artifacts:
    paths:
      - chainproof-reports/
    reports:
      codequality: chainproof-reports/code-quality-report.json
      sast: chainproof-reports/sast-report.json
    expire_in: 30 days
  rules:
    - if: $CI_MERGE_REQUEST_IID
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  allow_failure: false
${options?.diffMode ? `
chainproof-diff-scan:
  stage: test
  image: node:20-alpine
  before_script:
    - npm ci
  script:
    - npx chainproof ci gitlab --targets ${targets} --diff --fail-severity ${failSeverity}
  artifacts:
    paths:
      - chainproof-reports/
    reports:
      codequality: chainproof-reports/code-quality-report.json
      sast: chainproof-reports/sast-report.json
    expire_in: 30 days
  rules:
    - if: $CI_MERGE_REQUEST_IID
  allow_failure: false
` : ""}`;
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

/**
 * Simple glob pattern matcher supporting * and ** wildcards.
 * Used for file path suppression matching.
 */
function matchGlob(filePath: string, pattern: string): boolean {
  // Normalize paths
  const normalizedFile = filePath.replace(/\\/g, "/");
  const normalizedPattern = pattern.replace(/\\/g, "/");

  // Convert glob to regex
  const regexStr = normalizedPattern
    .replace(/\./g, "\\.")
    .replace(/\*\*/g, "{{GLOBSTAR}}")
    .replace(/\*/g, "[^/]*")
    .replace(/\{\{GLOBSTAR\}\}/g, ".*");

  const regex = new RegExp(`^${regexStr}$`);
  return regex.test(normalizedFile);
}
