import type { Finding, Severity, ScanResult, ScanConfig } from "../types";

// ─── CI Provider Identifiers ─────────────────────────────────────────────────

/** Supported CI providers for native integration. */
export type CIProvider = "gitlab" | "bitbucket" | "github";

// ─── Severity Mapping ────────────────────────────────────────────────────────

/**
 * Maps ChainProof severity levels to provider-specific severity labels.
 */
export const SEVERITY_MAP: Record<CIProvider, Record<Severity, string>> = {
  gitlab: {
    critical: "blocker",
    high: "critical",
    medium: "major",
    low: "minor",
    info: "info",
    gas: "info",
  },
  bitbucket: {
    critical: "BLOCKER",
    high: "CRITICAL",
    medium: "MAJOR",
    low: "MINOR",
    info: "INFO",
    gas: "INFO",
  },
  github: {
    critical: "error",
    high: "error",
    medium: "warning",
    low: "notice",
    info: "notice",
    gas: "notice",
  },
};

// ─── Annotation ──────────────────────────────────────────────────────────────

/**
 * A single code-level annotation tied to a source location.
 * Used to create inline review notes on merge/pull requests.
 */
export interface CIAnnotation {
  /** Severity level mapped for the target provider */
  severity: string;
  /** Human-readable message */
  message: string;
  /** Source file path relative to repo root */
  file: string;
  /** 1-indexed start line */
  line: number;
  /** 1-indexed end line (optional, for multi-line annotations) */
  endLine?: number;
  /** Rule/check ID (e.g. "CP-107", "SWC-107") */
  ruleId?: string;
  /** Optional snippet of the vulnerable code */
  snippet?: string;
}

// ─── CI Report Result ────────────────────────────────────────────────────────

/**
 * Provider-agnostic CI report containing findings formatted for a specific provider.
 * Supports multiple output targets: MR/Pipeline notes, Code Insights, artifacts, etc.
 */
export interface CIReportResult {
  /** Target provider */
  provider: CIProvider;
  /** CI-specific formatted annotations */
  annotations: CIAnnotation[];
  /** Summary counts */
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    gas: number;
    total: number;
  };
  /** Whether the report should fail the CI pipeline */
  shouldFail: boolean;
  /** Minimum severity threshold used for the fail gate */
  failThreshold: Severity;
  /** Metadata about the scan */
  metadata: {
    scanVersion: string;
    timestamp: string;
    filesScanned: number;
    /** Branch or ref being scanned */
    branch?: string;
    /** Commit SHA */
    commitSha?: string;
    /** Diff-aware: number of introduced findings (vs baseline) */
    introducedCount?: number;
    /** Diff-aware: number of resolved findings (vs baseline) */
    resolvedCount?: number;
  };
}

// ─── Diff-Aware CI Configuration ─────────────────────────────────────────────

/**
 * Configuration for diff-aware scanning in CI environments.
 * Limits scanning to files changed in a merge/pull request.
 */
export interface CIDiffConfig {
  /** Enable diff-aware scanning (only scan changed files) */
  enabled: boolean;
  /** Base branch/ref to diff against (e.g. "main", "origin/main") */
  baseRef?: string;
  /** Commit SHA of the base for diff computation */
  baseSha?: string;
  /** Commit SHA of the current head for diff computation */
  headSha?: string;
  /** File extensions to include in diff (default: [".sol"]) */
  includeExtensions?: string[];
  /** Glob patterns to exclude from diff */
  excludePatterns?: string[];
  /** Fallback: scan all files if diff computation fails */
  fallbackToFullScan?: boolean;
}

// ─── CI Integration Configuration ────────────────────────────────────────────

/**
 * Full configuration for a CI provider integration.
 * Combines scan settings with CI-specific behavior.
 */
export interface CIIntegrationConfig {
  /** Target CI provider */
  provider: CIProvider;
  /** ChainProof scan configuration */
  scanConfig: ScanConfig;
  /** Diff-aware scanning settings */
  diff?: CIDiffConfig;
  /** Minimum severity to report as annotations */
  minSeverity?: Severity;
  /** Minimum severity to cause a CI failure gate */
  failSeverity?: Severity;
  /** Whether to post MR/Pipeline notes */
  postNotes?: boolean;
  /** Whether to create Code Insights annotations */
  createAnnotations?: boolean;
  /** Whether to upload artifacts */
  uploadArtifacts?: boolean;
  /** Whether to update existing notes (idempotent) */
  updateExisting?: boolean;
  /** Maximum number of annotations to post (provider limit) */
  maxAnnotations?: number;
  /** Whether to suppress duplicate findings */
  suppressDuplicates?: boolean;
}

// ─── Baseline / Suppression Policy ───────────────────────────────────────────

/**
 * A suppressed finding rule. Suppressed rules are excluded from
 * CI failure gates and annotation posting.
 */
export interface SuppressionPolicy {
  /** Rule IDs to suppress */
  suppressedRuleIds: string[];
  /** Severity levels to suppress entirely */
  suppressedSeverities: Severity[];
  /** Files to suppress (glob patterns) */
  suppressedFiles: string[];
  /** Expiration timestamp for temporary suppressions (ISO 8601) */
  expiresAt?: string;
  /** Reason for the suppression */
  reason?: string;
}

/**
 * Baseline scan result for diff-aware CI scans.
 * Stored as a CI artifact and compared against on subsequent runs.
 */
export interface CIBaseline {
  /** Scan result used as baseline */
  scanResult: ScanResult;
  /** Branch the baseline was captured from */
  branch: string;
  /** Commit SHA the baseline was captured at */
  commitSha: string;
  /** Timestamp of baseline capture */
  capturedAt: string;
  /** Version of the baseline schema */
  schemaVersion: string;
}

// ─── Rate Limit / Retry Configuration ────────────────────────────────────────

/**
 * Configuration for API retry and rate-limit behavior.
 */
export interface CIRetryConfig {
  /** Maximum number of retry attempts for transient errors */
  maxRetries: number;
  /** Base delay in milliseconds between retries */
  baseDelayMs: number;
  /** Maximum delay in milliseconds (for exponential backoff) */
  maxDelayMs: number;
  /** HTTP status codes considered retryable */
  retryableStatusCodes: number[];
}

/** Default retry configuration for CI API calls. */
export const DEFAULT_RETRY_CONFIG: CIRetryConfig = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
  retryableStatusCodes: [429, 500, 502, 503, 504],
};

// ─── Fork Safety ─────────────────────────────────────────────────────────────

/**
 * Fork safety configuration.
 * When scanning from a forked repository, certain API calls (posting notes,
 * updating status) may require elevated permissions not available to fork PRs.
 */
export interface CIForkSafety {
  /** Whether the current run is from a forked repository */
  isFork: boolean;
  /** Whether to skip posting annotations when running from a fork */
  skipPosting?: boolean;
  /** Whether to skip pipeline status updates when running from a fork */
  skipStatus?: boolean;
  /** Whether to upload artifacts when running from a fork */
  uploadArtifacts?: boolean;
}

// ─── Token Safety ────────────────────────────────────────────────────────────

/** List of environment variable names that may contain secrets. */
const SECRET_ENV_PATTERNS = [
  "TOKEN",
  "SECRET",
  "KEY",
  "PASSWORD",
  "CREDENTIAL",
  "AUTH",
];

/**
 * Redacts sensitive values from strings before logging or artifact storage.
 * Replaces matched values with `[REDACTED]`.
 */
export function redactSecrets(text: string, envVars?: Record<string, string>): string {
  let redacted = text;

  if (envVars) {
    for (const [key, value] of Object.entries(envVars)) {
      if (!value) continue;
      const isSecret = SECRET_ENV_PATTERNS.some((p) =>
        key.toUpperCase().includes(p)
      );
      if (isSecret && value.length > 0) {
        redacted = redacted.split(value).join("[REDACTED]");
      }
    }
  }

  // Also redact common token patterns (Bearer, Basic, etc.)
  redacted = redacted.replace(
    /((?:Bearer|Basic|Token)\s+)[A-Za-z0-9._\-]{20,}/g,
    "$1[REDACTED]"
  );

  // Redact high-entropy hex strings that look like private keys or API keys
  redacted = redacted.replace(
    /\b(0x)?[a-fA-F0-9]{64}\b/g,
    "[REDACTED]"
  );

  return redacted;
}

/**
 * Validates that a token string looks like a valid CI provider token
 * (non-empty, no surrounding whitespace, not obviously a placeholder).
 */
export function validateCIToken(token: string | undefined, provider: CIProvider): boolean {
  if (!token || token.trim().length === 0) return false;

  const trimmed = token.trim();

  // Reject obvious placeholders
  const placeholders = [
    "your-token-here",
    "CHANGE_ME",
    "REPLACE_ME",
    "xxx",
    "todo",
    "placeholder",
  ];
  if (placeholders.some((p) => trimmed.toLowerCase().includes(p.toLowerCase()))) {
    return false;
  }

  // Provider-specific minimum length checks
  switch (provider) {
    case "gitlab":
      // GitLab tokens are typically 20+ characters (PAT) or glpat- prefix
      return trimmed.length >= 20;
    case "bitbucket":
      // Bitbucket App passwords are at least 20 chars
      return trimmed.length >= 20;
    case "github":
      // GitHub tokens are 40+ chars or ghp_/gho_ prefix
      return trimmed.length >= 40 || trimmed.startsWith("ghp_") || trimmed.startsWith("gho_");
    default:
      return trimmed.length >= 20;
  }
}

// ─── Pagination Helpers ──────────────────────────────────────────────────────

/** Result of a paginated API fetch. */
export interface PaginatedResult<T> {
  items: T[];
  total: number;
  page: number;
  perPage: number;
  hasMore: boolean;
}

// ─── ID Generation ───────────────────────────────────────────────────────────

/** Maximum length for annotation message strings (provider-imposed). */
export const ANNOTATION_MESSAGE_MAX_LENGTH = 1024;

/**
 * Truncates a message to the maximum allowed length,
 * appending an ellipsis if truncated.
 */
export function truncateMessage(message: string): string {
  if (message.length <= ANNOTATION_MESSAGE_MAX_LENGTH) return message;
  return message.slice(0, ANNOTATION_MESSAGE_MAX_LENGTH - 3) + "...";
}
