import { StructuredQuotaErrorPayload, TenantQuotaLimits, TenantQuotaUsage } from "./types";
import { JobQueueManager } from "../queue/job-queue";

export const DEFAULT_TENANT_LIMITS: Omit<TenantQuotaLimits, "tenantId"> = {
  maxConcurrentJobs: 2,
  maxJobsPerWindow: 100,
  windowDurationMs: 3600000,
  maxStorageBytes: 500 * 1024 * 1024,
  maxComputeTimeMsPerWindow: 300000,
};

export class StructuredQuotaError extends Error {
  public payload: StructuredQuotaErrorPayload;

  constructor(payload: StructuredQuotaErrorPayload) {
    super(payload.error);
    this.name = "StructuredQuotaError";
    this.payload = payload;
  }
}

export class QuotaManager {
  private tenantLimits: Map<string, TenantQuotaLimits> = new Map();
  private tenantUsage: Map<string, TenantQuotaUsage> = new Map();

  public setTenantLimits(tenantId: string, limits: Partial<TenantQuotaLimits>): TenantQuotaLimits {
    const fullLimits: TenantQuotaLimits = {
      tenantId,
      ...DEFAULT_TENANT_LIMITS,
      ...limits,
    };
    this.tenantLimits.set(tenantId, fullLimits);
    return fullLimits;
  }

  public getTenantLimits(tenantId: string): TenantQuotaLimits {
    return (
      this.tenantLimits.get(tenantId) ?? {
        tenantId,
        ...DEFAULT_TENANT_LIMITS,
      }
    );
  }

  public getTenantUsage(tenantId: string, queueManager?: JobQueueManager): TenantQuotaUsage {
    const limits = this.getTenantLimits(tenantId);
    const now = Date.now();

    let usage = this.tenantUsage.get(tenantId);

    if (!usage || now >= usage.windowResetAt) {
      usage = {
        tenantId,
        concurrentJobs: 0,
        jobsInWindow: 0,
        storageBytes: 0,
        computeTimeMsInWindow: 0,
        windowResetAt: now + limits.windowDurationMs,
      };
      this.tenantUsage.set(tenantId, usage);
    }

    if (queueManager) {
      const activeJobs = queueManager
        .getStore()
        .values()
        .filter((j) => j.tenantId === tenantId && (j.status === "queued" || j.status === "running"));
      usage.concurrentJobs = activeJobs.length;

      const completedJobs = queueManager
        .getStore()
        .values()
        .filter((j) => j.tenantId === tenantId && j.result);

      let totalStorage = 0;
      for (const job of completedJobs) {
        totalStorage += JSON.stringify(job.result).length;
      }
      usage.storageBytes = totalStorage;
    }

    return usage;
  }

  public checkAndRecordJobSubmission(tenantId: string, queueManager?: JobQueueManager): void {
    const limits = this.getTenantLimits(tenantId);
    const usage = this.getTenantUsage(tenantId, queueManager);

    if (usage.concurrentJobs >= limits.maxConcurrentJobs) {
      throw new StructuredQuotaError({
        error: `Tenant '${tenantId}' has reached maximum concurrent job limit (${usage.concurrentJobs}/${limits.maxConcurrentJobs})`,
        code: "QUOTA_EXCEEDED_CONCURRENCY",
        tenantId,
        metric: "concurrency",
        limit: limits.maxConcurrentJobs,
        current: usage.concurrentJobs,
        retryAfterSeconds: 15,
      });
    }

    if (usage.jobsInWindow >= limits.maxJobsPerWindow) {
      const retryAfterSeconds = Math.max(1, Math.ceil((usage.windowResetAt - Date.now()) / 1000));
      throw new StructuredQuotaError({
        error: `Tenant '${tenantId}' exceeded job submission rate limit (${usage.jobsInWindow}/${limits.maxJobsPerWindow} per window)`,
        code: "QUOTA_EXCEEDED_RATE_LIMIT",
        tenantId,
        metric: "rate_limit",
        limit: limits.maxJobsPerWindow,
        current: usage.jobsInWindow,
        retryAfterSeconds,
      });
    }

    if (usage.storageBytes >= limits.maxStorageBytes) {
      throw new StructuredQuotaError({
        error: `Tenant '${tenantId}' exceeded storage quota limit (${(usage.storageBytes / 1024 / 1024).toFixed(1)}MB/${(limits.maxStorageBytes / 1024 / 1024).toFixed(1)}MB)`,
        code: "QUOTA_EXCEEDED_STORAGE",
        tenantId,
        metric: "storage",
        limit: limits.maxStorageBytes,
        current: usage.storageBytes,
      });
    }

    usage.jobsInWindow++;
  }

  public recordComputeTime(tenantId: string, computeTimeMs: number): void {
    const limits = this.getTenantLimits(tenantId);
    const usage = this.getTenantUsage(tenantId);
    usage.computeTimeMsInWindow += computeTimeMs;

    if (usage.computeTimeMsInWindow > limits.maxComputeTimeMsPerWindow) {
      console.warn(
        `[QuotaManager] Tenant '${tenantId}' exceeded compute time quota window limit (${usage.computeTimeMsInWindow}ms > ${limits.maxComputeTimeMsPerWindow}ms)`
      );
    }
  }
}
