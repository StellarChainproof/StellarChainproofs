export interface IsolationLimits {
  maxTotalSizeBytes: number;
  maxSingleFileSizeBytes: number;
  maxFileCount: number;
  maxCompressionRatio: number;
  maxDepth: number;
}

export interface TenantPolicy {
  tenantId: string;
  allowLLM: boolean;
  allowSlither: boolean;
  maxFilesPerScan: number;
  maxFileSize: number;
  allowedImports?: string[];
  customLimits?: Partial<IsolationLimits>;
}

export interface SandboxConfig {
  tenantId: string;
  jobId: string;
  baseDir?: string;
  limits?: Partial<IsolationLimits>;
}

export interface ArchiveExtractResult {
  files: Array<{ path: string; content: string }>;
  totalSizeBytes: number;
  fileCount: number;
}
