// ─── Severity Levels ──────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "gas";

// ─── A single detected issue ──────────────────────────────────────────────────

export interface Finding {
  /** Unique rule ID e.g. "SWC-107" */
  id: string;
  /** Short human-readable title */
  title: string;
  /** Full explanation of the vulnerability */
  description: string;
  /** Suggested fix */
  recommendation: string;
  severity: Severity;
  /** Source file path */
  file: string;
  /** 1-indexed line numbers */
  line: number;
  lineEnd?: number;
  /** The raw source snippet */
  snippet?: string;
  /** SWC registry reference if applicable */
  swcId?: string;
  /** Whether this was enhanced/explained by LLM */
  llmEnhanced?: boolean;
  /** File where the vulnerable code is defined */
  definedIn?: string;
  /** File of the contract that inherits the issue */
  inheritedBy?: string;
  /** Resolved import chain from inheriting file to definition file */
  importPath?: string[];
}

// ─── Gas optimization hint ────────────────────────────────────────────────────

export interface GasHint {
  file: string;
  line: number;
  description: string;
  estimatedSaving: string;
  snippet?: string;
}

// ─── Scan result for a single file ───────────────────────────────────────────

export interface FileScanResult {
  file: string;
  findings: Finding[];
  gasHints: GasHint[];
  /** true if Slither was available and ran */
  slitherRan: boolean;
  parseError?: string;
}

// ─── Full scan result for a project ──────────────────────────────────────────

export interface ScanResult {
  version: string;
  timestamp: string;
  files: FileScanResult[];
  /** Aggregated counts */
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    gas: number;
    total: number;
  };
}

// ─── Scanner config ───────────────────────────────────────────────────────────

export interface ScanConfig {
  /** Paths to .sol files or directories */
  targets: string[];
  /** Run Slither if installed */
  useSlither: boolean;
  /** Send findings to LLM for explanation */
  useLLM: boolean;

  /**
   * Provider API key.
   *
   * Backward compatible with prior Anthropic-only implementation.
   */
  apiKey?: string;

  /**
   * Select LLM provider (e.g. "anthropic", "openai"). Defaults to "anthropic".
   */
  llmProvider?: string;
  /** Provider/model identifier (provider-specific). */
  llmModel?: string;
  /** Provider API key (alternative to apiKey). */
  llmApiKey?: string;

  /** Minimum severity to report */
  minSeverity?: Severity;
  /** Output format */
  outputFormat?: "json" | "markdown" | "table";
}

