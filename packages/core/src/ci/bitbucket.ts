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
} from "./types";

// ─── Bitbucket Code Insights Report Schema ───────────────────────────────────

/**
 * Bitbucket Code Insights report annotation.
 * @see https://developer.atlassian.com/cloud/bitbucket/rest/api-group-pipelines/#api-repositories-workspace-repo-slug-pipelines-config-variables-key-get
 */
export interface BitbucketAnnotation {
  external_id: string;
  annotation_type: "VULNERABILITY" | "SECURITY" | "BUG" | "CODE_SMELL" | "ISSUE";
  summary: string;
  details: string;
  severity: "BLOCKER" | "CRITICAL" | "MAJOR" | "MINOR" | "INFO";
  path: string;
  line?: number;
  link?: string;
  rule?: {
    type: string;
    name: string;
  };
}

/**
 * Bitbucket Code Insights report.
 */
export interface BitbucketCodeInsightsReport {
  reporter: string;
  title: string;
  details: string;
  annotations: BitbucketAnnotation[];
  result: "PASS" | "FAIL";
  data: {
    type: string;
    properties: Record<string, unknown>;
  };
}

/**
 * Bitbucket pipeline status update payload.
 */
export interface BitbucketPipelineStatus {
  state: "SUCCESSFUL" | "FAILED" | "INPROGRESS" | "STOPPED";
  key: string;
  name: string;
  description: string;
  url?: string;
  refname?: string;
  commit?: string;
  build_number?: number;
}

// ─── Severity Mapping ────────────────────────────────────────────────────────

/**
 * Maps ChainProof severity to Bitbucket Code Insights severity.
 */
export function mapSeverityToBitbucket(severity: Severity): string {
  return SEVERITY_MAP.bitbucket[severity] || "INFO";
}

/**
 * Maps ChainProof severity to a Bitbucket annotation type.
 */
export function mapFindingTypeToBitbucket(
  severity: Severity
): BitbucketAnnotation["annotation_type"] {
  if (severity === "critical" || severity === "high") return "VULNERABILITY";
  if (severity === "medium") return "SECURITY";
  if (severity === "low") return "CODE_SMELL";
  return "ISSUE";
}

// ─── Finding Conversion ──────────────────────────────────────────────────────

/**
 * Converts a ChainProof finding to a Bitbucket Code Insights annotation.
 */
export function findingToBitbucketAnnotation(
  finding: Finding
): BitbucketAnnotation {
  return {
    external_id: `chainproof-${finding.id}-${finding.file}-${finding.line}`,
    annotation_type: mapFindingTypeToBitbucket(finding.severity),
    summary: truncateMessage(
      `[${finding.id}] ${finding.title}`
    ),
    details: truncateMessage(finding.description),
    severity: mapSeverityToBitbucket(finding.severity) as BitbucketAnnotation["severity"],
    path: finding.file,
    line: finding.line,
    rule: {
      type: "chainproof",
      name: finding.id,
    },
  };
}

// ─── Report Builder ──────────────────────────────────────────────────────────

/**
 * Builds a Bitbucket Code Insights report from ChainProof scan results.
 *
 * @param result - Scan result from `@chainproof/core`
 * @param options - Report options including fail threshold and max annotations
 * @returns Complete Code Insights report payload
 */
export function buildBitbucketCodeInsightsReport(
  result: ScanResult,
  options?: {
    failSeverity?: Severity;
    maxAnnotations?: number;
    title?: string;
    details?: string;
  }
): BitbucketCodeInsightsReport {
  const failSeverity = options?.failSeverity || "high";
  const failRank: Record<string, number> = {
    blocker: 5,
    critical: 5,
    major: 4,
    minor: 3,
    info: 2,
  };

  const allFindings = result.files.flatMap((f) => f.findings);
  const allAnnotations = allFindings.map(findingToBitbucketAnnotation);

  // Determine result based on severity threshold
  const minFailRank = failRank[mapSeverityToBitbucket(failSeverity)] ?? 4;
  const shouldFail = allAnnotations.some(
    (a) => (failRank[a.severity] ?? 0) >= minFailRank
  );

  // Apply max annotation limit
  const annotations =
    options?.maxAnnotations && allAnnotations.length > options.maxAnnotations
      ? allAnnotations.slice(0, options.maxAnnotations)
      : allAnnotations;

  // Build summary details
  const { summary } = result;
  const summaryLines: string[] = [];
  summaryLines.push(`Files scanned: ${result.files.length}`);
  if (summary.critical > 0) summaryLines.push(`Critical: ${summary.critical}`);
  if (summary.high > 0) summaryLines.push(`High: ${summary.high}`);
  if (summary.medium > 0) summaryLines.push(`Medium: ${summary.medium}`);
  if (summary.low > 0) summaryLines.push(`Low: ${summary.low}`);
  if (summary.info > 0) summaryLines.push(`Info: ${summary.info}`);
  summaryLines.push(`Total: ${summary.total}`);

  return {
    reporter: "chainproof",
    title: options?.title || "ChainProof Security Scan",
    details:
      options?.details ||
      summaryLines.join(" | "),
    annotations,
    result: shouldFail ? "FAIL" : "PASS",
    data: {
      type: "pipeline",
      properties: {
        scanVersion: result.version,
        timestamp: result.timestamp,
        filesScanned: result.files.length,
        severity: failSeverity,
        criticalCount: summary.critical,
        highCount: summary.high,
        mediumCount: summary.medium,
        lowCount: summary.low,
        infoCount: summary.info,
        gasCount: summary.gas,
      },
    },
  };
}

// ─── Diff-Aware Report Builder ───────────────────────────────────────────────

/**
 * Builds a Bitbucket Code Insights report for diff-aware mode,
 * only including newly introduced findings.
 */
export function buildBitbucketDiffReport(
  result: ScanResult,
  diff: { introduced: Finding[]; resolved: Finding[]; persisted: Finding[] },
  options?: {
    failSeverity?: Severity;
    maxAnnotations?: number;
  }
): BitbucketCodeInsightsReport {
  const failSeverity = options?.failSeverity || "high";
  const failRank: Record<string, number> = {
    blocker: 5,
    critical: 5,
    major: 4,
    minor: 3,
    info: 2,
  };

  const annotations = diff.introduced.map(findingToBitbucketAnnotation);

  const minFailRank = failRank[mapSeverityToBitbucket(failSeverity)] ?? 4;
  const shouldFail = annotations.some(
    (a) => (failRank[a.severity] ?? 0) >= minFailRank
  );

  const limitedAnnotations =
    options?.maxAnnotations && annotations.length > options.maxAnnotations
      ? annotations.slice(0, options.maxAnnotations)
      : annotations;

  const summaryLines: string[] = [];
  summaryLines.push(`Introduced: ${diff.introduced.length}`);
  summaryLines.push(`Resolved: ${diff.resolved.length}`);
  summaryLines.push(`Persisted: ${diff.persisted.length}`);

  return {
    reporter: "chainproof",
    title: "ChainProof Diff Security Scan",
    details: summaryLines.join(" | "),
    annotations: limitedAnnotations,
    result: shouldFail ? "FAIL" : "PASS",
    data: {
      type: "pipeline",
      properties: {
        scanVersion: result.version,
        timestamp: result.timestamp,
        introducedCount: diff.introduced.length,
        resolvedCount: diff.resolved.length,
        persistedCount: diff.persisted.length,
      },
    },
  };
}

// ─── MR/Pipeline Note Builder ────────────────────────────────────────────────

/**
 * Builds a Bitbucket pull request summary for the ChainProof scan.
 */
export function buildBitbucketPRSummary(
  result: ScanResult,
  diff?: { introduced: Finding[]; resolved: Finding[] }
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

  // Diff section
  if (diff) {
    if (diff.introduced.length > 0) {
      lines.push("### Newly Introduced Findings");
      lines.push("");
      for (const f of diff.introduced.slice(0, 20)) {
        const sev =
          f.severity === "critical"
            ? "🔴"
            : f.severity === "high"
            ? "🟠"
            : "🟡";
        lines.push(
          `- ${sev} **${f.title}** — \`${f.file}:${f.line}\` (${f.id})`
        );
      }
      if (diff.introduced.length > 20) {
        lines.push(`- _...and ${diff.introduced.length - 20} more_`);
      }
      lines.push("");
    }

    if (diff.resolved.length > 0) {
      lines.push(`### Resolved (${diff.resolved.length})`);
      lines.push("");
      for (const f of diff.resolved.slice(0, 10)) {
        lines.push(
          `- ✅ **${f.title}** — \`${f.file}:${f.line}\` (${f.id})`
        );
      }
      lines.push("");
    }
  } else {
    // Full scan: show top findings
    const allFindings = result.files.flatMap((f) => f.findings);
    const topFindings = allFindings
      .filter((f) => f.severity === "critical" || f.severity === "high")
      .slice(0, 10);

    if (topFindings.length > 0) {
      lines.push("### Top Findings");
      lines.push("");
      for (const f of topFindings) {
        const sev =
          f.severity === "critical" ? "🔴" : "🟠";
        lines.push(
          `- ${sev} **${f.title}** — \`${f.file}:${f.line}\` (${f.id})`
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
 * Converts findings into Bitbucket CI annotations with filtering.
 */
export function findingsToBitbucketAnnotations(
  findings: Finding[],
  options?: {
    minSeverity?: Severity;
    suppressPolicy?: SuppressionPolicy;
    maxAnnotations?: number;
  }
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
    severity: mapSeverityToBitbucket(f.severity),
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
 * Builds a complete CI report result for Bitbucket from a scan result.
 */
export function buildBitbucketCIReport(
  result: ScanResult,
  config: CIIntegrationConfig,
  diff?: { introduced: Finding[]; resolved: Finding[]; persisted: Finding[] },
  forkSafety?: CIForkSafety,
): CIReportResult {
  const failSeverity = config.failSeverity || "high";
  const failRank: Record<string, number> = {
    blocker: 5,
    critical: 5,
    major: 4,
    minor: 3,
    info: 2,
  };

  const evaluationFindings = diff ? diff.introduced : result.files.flatMap((f) => f.findings);

  const shouldFail =
    !forkSafety?.isFork &&
    evaluationFindings.some(
      (f) =>
        (failRank[mapSeverityToBitbucket(f.severity)] ?? 0) >=
        (failRank[mapSeverityToBitbucket(failSeverity)] ?? 4)
    );

  const annotations = findingsToBitbucketAnnotations(
    diff ? diff.introduced : result.files.flatMap((f) => f.findings),
    {
      minSeverity: config.minSeverity,
      maxAnnotations: config.maxAnnotations || 100,
    }
  );

  return {
    provider: "bitbucket",
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
 * Serializes a Bitbucket Code Insights report to JSON for pipeline upload.
 */
export function serializeBitbucketCodeInsightsArtifact(
  report: BitbucketCodeInsightsReport
): string {
  const serialized = JSON.stringify(report, null, 2);
  return redactSecrets(serialized);
}

// ─── Job Artifact Paths ──────────────────────────────────────────────────────

/** Standard artifact paths for Bitbucket Pipelines integration. */
export const BITBUCKET_ARTIFACT_PATHS = [
  "chainproof-reports/code-insights-report.json",
  "chainproof-reports/audit-report.json",
  "chainproof-reports/audit-report.md",
  "chainproof-reports/diff-report.json",
  "chainproof-reports/diff-report.md",
] as const;

// ─── Template YAML Snippet ───────────────────────────────────────────────────

/**
 * Returns a Bitbucket Pipelines YAML template for ChainProof integration.
 */
export function generateBitbucketPipelineTemplate(options?: {
  targets?: string;
  failSeverity?: string;
  diffMode?: boolean;
}): string {
  const targets = options?.targets || "contracts/";
  const failSeverity = options?.failSeverity || "high";

  return `# ChainProof Security Scanner — Bitbucket Pipelines Integration
# Add to your bitbucket-pipelines.yml

pipelines:
  pull-requests:
    "**":
      - step:
          name: ChainProof Security Scan
          image: node:20-alpine
          script:
            - npm ci
            - npx chainproof ci bitbucket --targets ${targets} --fail-severity ${failSeverity}
          after-script:
            - |
              if [ -f chainproof-reports/code-insights-report.json ]; then
                echo "Uploading Code Insights report..."
              fi
          artifacts:
            - chainproof-reports/**
          caches:
            - node

  branches:
    main:
      - step:
          name: ChainProof Security Scan (main)
          image: node:20-alpine
          script:
            - npm ci
            - npx chainproof ci bitbucket --targets ${targets} --fail-severity ${failSeverity}
          after-script:
            - |
              if [ -f chainproof-reports/code-insights-report.json ]; then
                echo "Uploading Code Insights report..."
              fi
          artifacts:
            - chainproof-reports/**
          caches:
            - node
`;
}

// ─── Pipeline Status Builder ─────────────────────────────────────────────────

/**
 * Builds a pipeline status update payload for the Bitbucket API.
 */
export function buildBitbucketPipelineStatus(
  result: ScanResult,
  options?: {
    commitSha?: string;
    branch?: string;
    pipelineUrl?: string;
  }
): BitbucketPipelineStatus {
  const hasBlocking =
    result.summary.critical > 0 || result.summary.high > 0;

  return {
    state: hasBlocking ? "FAILED" : "SUCCESSFUL",
    key: "chainproof-security-scan",
    name: "ChainProof Security Scan",
    description: hasBlocking
      ? `${result.summary.critical} critical, ${result.summary.high} high severity issues found`
      : `Scanned ${result.files.length} files — ${result.summary.total} total findings (none critical/high)`,
    url: options?.pipelineUrl,
    refname: options?.branch,
    commit: options?.commitSha,
  };
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

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
