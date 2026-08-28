/**
 * @packageDocumentation
 * CI Provider Integrations
 *
 * Provider-neutral interfaces, GitLab SAST/Code Quality, Bitbucket Code Insights,
 * diff-aware scanning, suppression policies, fork safety, and CI artifact handling.
 */

// ─── Shared Types ────────────────────────────────────────────────────────────
export {
  type CIProvider,
  type CIAnnotation,
  type CIReportResult,
  type CIDiffConfig,
  type CIIntegrationConfig,
  type SuppressionPolicy,
  type CIBaseline,
  type CIRetryConfig,
  type CIForkSafety,
  type PaginatedResult,
  SEVERITY_MAP,
  DEFAULT_RETRY_CONFIG,
  ANNOTATION_MESSAGE_MAX_LENGTH,
  redactSecrets,
  validateCIToken,
  truncateMessage,
} from "./types";

// ─── GitLab Integration ──────────────────────────────────────────────────────
export {
  type GitLabCodeQualityIssue,
  type GitLabCodeQualityReport,
  type GitLabSASTVulnerability,
  type GitLabSASTReport,
  mapSeverityToGitLab,
  mapSeverityToGitLabSAST,
  findingToGitLabCodeQuality,
  findingToGitLabSAST,
  buildGitLabCodeQualityReport,
  buildGitLabSASTReport,
  buildGitLabMRNote,
  findingsToGitLabAnnotations,
  buildGitLabCIReport,
  serializeGitLabCodeQualityArtifact,
  serializeGitLabSASTArtifact,
  generateGitLabCITemplate,
  GITLAB_ARTIFACT_PATHS,
  GITLAB_JOB_NAMES,
} from "./gitlab";

// ─── Bitbucket Integration ───────────────────────────────────────────────────
export {
  type BitbucketAnnotation,
  type BitbucketCodeInsightsReport,
  type BitbucketPipelineStatus,
  mapSeverityToBitbucket,
  mapFindingTypeToBitbucket,
  findingToBitbucketAnnotation,
  buildBitbucketCodeInsightsReport,
  buildBitbucketDiffReport,
  buildBitbucketPRSummary,
  findingsToBitbucketAnnotations,
  buildBitbucketCIReport,
  serializeBitbucketCodeInsightsArtifact,
  buildBitbucketPipelineStatus,
  generateBitbucketPipelineTemplate,
  BITBUCKET_ARTIFACT_PATHS,
} from "./bitbucket";

// ─── Diff-Aware Scanning ────────────────────────────────────────────────────
export {
  type GitDiffResult,
  parseGitDiff,
  diffAwareScan,
  computeDiff,
  saveBaselineArtifact,
  loadBaselineArtifact,
  filterExistingFiles,
  resolveFilePaths,
  extractSolFilesFromDiffOutput,
  applySuppressionPolicy,
  detectFork,
} from "./diff-aware";
