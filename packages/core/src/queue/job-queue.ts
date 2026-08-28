import * as crypto from "crypto";
import { DurableJobStore } from "./persistence";
import { JobFilter, JobPriority, QueueStats, ScanJob, SubmitJobOptions } from "./types";

export interface JobQueueManagerOptions {
  store?: DurableJobStore;
  defaultTimeoutMs?: number;
  defaultMaxRetries?: number;
  retentionPeriodMs?: number;
}

export class JobQueueManager {
  private store: DurableJobStore;
  private defaultTimeoutMs: number;
  private defaultMaxRetries: number;
  private retentionPeriodMs: number;

  constructor(options: JobQueueManagerOptions = {}) {
    this.store = options.store ?? new DurableJobStore();
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 60000;
    this.defaultMaxRetries = options.defaultMaxRetries ?? 2;
    this.retentionPeriodMs = options.retentionPeriodMs ?? 86400000 * 7;
  }

  public getStore(): DurableJobStore {
    return this.store;
  }

  public submitJob(options: SubmitJobOptions): { job: ScanJob; deduplicated: boolean } {
    const now = Date.now();

    if (options.idempotencyKey) {
      const existing = this.store
        .values()
        .find(
          (j) =>
            j.tenantId === options.tenantId &&
            j.idempotencyKey === options.idempotencyKey &&
            j.status !== "cancelled" &&
            now - j.createdAt < this.retentionPeriodMs
        );

      if (existing) {
        return { job: existing, deduplicated: true };
      }
    }

    const jobId = `job_${crypto.randomBytes(10).toString("hex")}`;
    const priority: JobPriority = options.priority ?? 2;

    const job: ScanJob = {
      id: jobId,
      tenantId: options.tenantId,
      projectId: options.projectId,
      principalId: options.principalId,
      priority,
      idempotencyKey: options.idempotencyKey,
      files: options.files,
      config: options.config ?? {},
      status: "queued",
      progress: {
        percentage: 0,
        step: "queued",
        message: "Job queued for processing",
        timestamp: now,
      },
      attempts: 0,
      maxRetries: options.maxRetries ?? this.defaultMaxRetries,
      timeoutMs: options.timeoutMs ?? this.defaultTimeoutMs,
      cancelRequested: false,
      createdAt: now,
      updatedAt: now,
      tags: options.tags,
    };

    this.store.set(job);
    return { job, deduplicated: false };
  }

  public getJob(jobId: string): ScanJob | undefined {
    return this.store.get(jobId);
  }

  public dequeueNextJob(): ScanJob | undefined {
    const queuedJobs = this.store
      .values()
      .filter((j) => j.status === "queued" && !j.cancelRequested);

    if (queuedJobs.length === 0) return undefined;

    queuedJobs.sort((a, b) => {
      if (a.priority !== b.priority) {
        return a.priority - b.priority;
      }
      return a.createdAt - b.createdAt;
    });

    return queuedJobs[0];
  }

  public cancelJob(jobId: string, tenantId?: string): { success: boolean; job?: ScanJob; error?: string } {
    const job = this.store.get(jobId);
    if (!job) {
      return { success: false, error: "Job not found" };
    }

    if (tenantId && job.tenantId !== tenantId) {
      return { success: false, error: "Access denied to job" };
    }

    if (job.status === "completed" || job.status === "failed" || job.status === "cancelled") {
      return { success: false, error: `Cannot cancel job in terminal status '${job.status}'`, job };
    }

    job.cancelRequested = true;
    job.updatedAt = Date.now();

    if (job.status === "queued") {
      job.status = "cancelled";
      job.progress = {
        percentage: 100,
        step: "cancelled",
        message: "Job cancelled before execution",
        timestamp: Date.now(),
      };
      job.completedAt = Date.now();
    }

    this.store.set(job);
    return { success: true, job };
  }

  public deleteJob(jobId: string, tenantId?: string): { success: boolean; error?: string } {
    const job = this.store.get(jobId);
    if (!job) {
      return { success: false, error: "Job not found" };
    }

    if (tenantId && job.tenantId !== tenantId) {
      return { success: false, error: "Access denied to job" };
    }

    this.store.delete(jobId);
    return { success: true };
  }

  public listJobs(filter: JobFilter = {}): { jobs: ScanJob[]; total: number; offset: number; limit: number } {
    let allJobs = this.store.values();

    if (filter.tenantId) {
      allJobs = allJobs.filter((j) => j.tenantId === filter.tenantId);
    }

    if (filter.projectId) {
      allJobs = allJobs.filter((j) => j.projectId === filter.projectId);
    }

    if (filter.status) {
      const statuses = Array.isArray(filter.status) ? filter.status : [filter.status];
      allJobs = allJobs.filter((j) => statuses.includes(j.status));
    }

    if (filter.search) {
      const q = filter.search.toLowerCase();
      allJobs = allJobs.filter(
        (j) => j.id.toLowerCase().includes(q) || j.files.some((f) => f.path.toLowerCase().includes(q))
      );
    }

    allJobs.sort((a, b) => b.createdAt - a.createdAt);

    const total = allJobs.length;
    const offset = filter.offset ?? 0;
    const limit = filter.limit ?? 50;
    const page = allJobs.slice(offset, offset + limit);

    return { jobs: page, total, offset, limit };
  }

  public getStats(tenantId?: string): QueueStats {
    let jobs = this.store.values();
    if (tenantId) {
      jobs = jobs.filter((j) => j.tenantId === tenantId);
    }

    let totalDurationMs = 0;
    let completedCount = 0;
    const activeTenants = new Set<string>();

    let queued = 0;
    let running = 0;
    let completed = 0;
    let failed = 0;
    let cancelled = 0;
    let timedOut = 0;

    for (const job of jobs) {
      activeTenants.add(job.tenantId);
      switch (job.status) {
        case "queued":
          queued++;
          break;
        case "running":
          running++;
          break;
        case "completed":
          completed++;
          if (job.startedAt && job.completedAt) {
            totalDurationMs += job.completedAt - job.startedAt;
            completedCount++;
          }
          break;
        case "failed":
          failed++;
          break;
        case "cancelled":
          cancelled++;
          break;
        case "timed_out":
          timedOut++;
          break;
      }
    }

    return {
      totalJobs: jobs.length,
      queued,
      running,
      completed,
      failed,
      cancelled,
      timedOut,
      activeTenants: activeTenants.size,
      avgDurationMs: completedCount > 0 ? Math.round(totalDurationMs / completedCount) : 0,
    };
  }

  public purgeExpiredJobs(maxAgeMs?: number): number {
    const ageCutoff = Date.now() - (maxAgeMs ?? this.retentionPeriodMs);
    let purgedCount = 0;

    for (const job of this.store.values()) {
      if (
        (job.status === "completed" || job.status === "failed" || job.status === "cancelled" || job.status === "timed_out") &&
        job.createdAt < ageCutoff
      ) {
        this.store.delete(job.id);
        purgedCount++;
      }
    }

    return purgedCount;
  }
}
