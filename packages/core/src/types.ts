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
  /** Call path showing the vulnerable execution trace (e.g., ["withdraw", "_updateBalance"]) */
  callPath?: string[];
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

// ─── Complexity / Maintainability Metrics ──────────────────────────────────────

export interface HighComplexityFunction {
  name: string;
  cc: number;
}

export interface ContractMetrics {
  contract: string;
  file: string;
  linesOfCode: number;
  functionCount: number;
  inheritanceDepth: number;
  avgCyclomaticComplexity: number;
  highComplexityFunctions: Array<{ name: string; cc: number }>;
  externalCallsPerFunction: Record<string, number>;
  stateVariableCount: number;
  visibilityDistribution: Record<string, number>;
  riskScore: number; // 0-100 composite
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
  /** Complexity and maintainability metrics per contract */
  metrics?: ContractMetrics[];
}

// ─── Plugin API ──────────────────────────────────────────────────────────────

export type ASTNode = any; // From @solidity-parser/parser

export interface PluginRule {
  /** Unique rule ID e.g. "MYTEAM-001" */
  id: string;
  /** Short human-readable title */
  title: string;
  severity: Severity;
  /** Full explanation of the vulnerability */
  description: string;
  /** Suggested fix */
  recommendation?: string;
  /** Detection function */
  detect: (ast: ASTNode, source: string, filePath: string) => Finding[];
}

export interface ChainProofPlugin {
  name: string;
  version: string;
  rules: PluginRule[];
}

// ─── Scanner config ───────────────────────────────────────────────────────────

export interface ScanConfig {
  /** Paths to .sol files or directories */
  targets: string[];
  /** Run Slither if installed */
  useSlither: boolean;
  /** Send findings to LLM for explanation */
  useLLM: boolean;
  /** Compute complexity metrics */
  useMetrics: boolean;
  /** Anthropic API key */
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
  /** Array of plugins to load */
  plugins?: ChainProofPlugin[];
}

