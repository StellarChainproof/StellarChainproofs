import type { Finding, GasHint, ScanConfig, ASTNode } from "../types";
import type { ThreatModel } from "../threat-model";
import type { Range, Diagnostic as LspDiagnostic, DiagnosticSeverity as LspDiagnosticSeverity } from "vscode-languageserver";

export type TransportType = "stdio" | "ipc" | "tcp";

export interface LspDaemonOptions {
  /** Transport protocol: stdio, IPC socket, or TCP socket */
  transport?: TransportType;
  /** Path for IPC domain socket (used when transport === 'ipc') */
  socketPath?: string;
  /** Port for TCP server (used when transport === 'tcp') */
  port?: number;
  /** Secret bearer token required for socket authentication */
  authToken?: string;
  /** Maximum pending requests in the queue before shedding load */
  maxQueueDepth?: number;
  /** Maximum concurrent analysis tasks */
  maxConcurrent?: number;
  /** Debounce delay for document changes in milliseconds */
  debounceMs?: number;
  /** Base scan configuration overrides */
  scanConfig?: Partial<ScanConfig>;
  /** Optional logger function */
  logger?: (level: "info" | "warn" | "error" | "debug", message: string) => void;
}

export interface DiagnosticData {
  findingId?: string;
  swcId?: string;
  ruleId?: string;
  recommendation?: string;
  evidencePath?: Array<{ file: string; line: number; description: string }>;
  confidence?: "high" | "medium" | "low";
  assumptions?: string[];
  isGasHint?: boolean;
}

export interface ExtendedLspDiagnostic extends LspDiagnostic {
  data?: DiagnosticData;
}

export interface LspStatus {
  openDocumentsCount: number;
  queueDepth: number;
  activeAnalyses: number;
  cacheStats: {
    hits: number;
    misses: number;
    entries: number;
  };
  uptimeSeconds: number;
  workspaceFolders: string[];
}

export interface ThreatModelRequestParams {
  uri?: string;
  workspacePath?: string;
  assumptionsPath?: string;
  minSeverity?: "critical" | "high" | "medium" | "low";
}

export interface ScanReportRequestParams {
  uri?: string;
  workspacePath?: string;
  format?: "markdown" | "json" | "table";
  minSeverity?: "critical" | "high" | "medium" | "low" | "info";
}

export interface ScanReportResponse {
  format: "markdown" | "json" | "table";
  content: string;
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

export interface ClearCacheResponse {
  cleared: boolean;
  message: string;
}

/** Custom JSON-RPC method strings for ChainProof protocol extensions */
export const ChainProofLspMethods = {
  ThreatModel: "chainproof/threatModel",
  ScanReport: "chainproof/scanReport",
  ClearCache: "chainproof/clearCache",
  Status: "chainproof/status",
} as const;
