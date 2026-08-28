export interface TenantQuotaLimits {
  tenantId: string;
  maxConcurrentJobs: number;
  maxJobsPerWindow: number;
  windowDurationMs: number;
  maxStorageBytes: number;
  maxComputeTimeMsPerWindow: number;
}

export interface TenantQuotaUsage {
  tenantId: string;
  concurrentJobs: number;
  jobsInWindow: number;
  storageBytes: number;
  computeTimeMsInWindow: number;
  windowResetAt: number;
}

export interface StructuredQuotaErrorPayload {
  error: string;
  code: string;
  tenantId: string;
  metric: "concurrency" | "rate_limit" | "storage" | "compute_time";
  limit: number;
  current: number;
  retryAfterSeconds?: number;
}
