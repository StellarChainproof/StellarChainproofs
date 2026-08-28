import { scan } from "../scanner";
import { ScanConfig, ScanResult } from "../types";
import { JobQueueManager } from "./job-queue";
import { LeaseManager } from "./lease-manager";
import { JobProgress, ScanJob, StreamEvent } from "./types";
import { TenantSandbox } from "../isolation/sandbox";
import { ErrorSanitizer } from "../isolation/sanitizer";
import { TenantPolicyEnforcer } from "../isolation/llm-policy";

export type EventCallback = (event: StreamEvent) => void;

export interface QueueWorkerOptions {
  queueManager: JobQueueManager;
  leaseManager?: LeaseManager;
  concurrency?: number;
  pollIntervalMs?: number;
  heartbeatIntervalMs?: number;
  sweepIntervalMs?: number;
}

export class QueueWorker {
  private queueManager: JobQueueManager;
  private leaseManager: LeaseManager;
  private concurrency: number;
  private pollIntervalMs: number;
  private heartbeatIntervalMs: number;
  private sweepIntervalMs: number;

  private activeJobsCount = 0;
  private running = false;
  private pollTimer?: NodeJS.Timeout;
  private sweepTimer?: NodeJS.Timeout;

  private listeners: Map<string, Set<EventCallback>> = new Map();
  private globalListeners: Set<EventCallback> = new Set();
  private abortControllers: Map<string, AbortController> = new Map();

  constructor(options: QueueWorkerOptions) {
    this.queueManager = options.queueManager;
    this.leaseManager = options.leaseManager ?? new LeaseManager();
    this.concurrency = options.concurrency ?? 2;
    this.pollIntervalMs = options.pollIntervalMs ?? 500;
    this.heartbeatIntervalMs = options.heartbeatIntervalMs ?? 5000;
    this.sweepIntervalMs = options.sweepIntervalMs ?? 10000;
  }

  public start(): void {
    if (this.running) return;
    this.running = true;

    this.pollTimer = setInterval(() => {
      this.pollAndProcess();
    }, this.pollIntervalMs);

    this.sweepTimer = setInterval(() => {
      this.sweepStaleLeases();
    }, this.sweepIntervalMs);
  }

  public stop(): void {
    this.running = false;
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.sweepTimer) clearInterval(this.sweepTimer);

    for (const controller of this.abortControllers.values()) {
      controller.abort();
    }
    this.abortControllers.clear();
  }

  public subscribe(jobId: string, callback: EventCallback): () => void {
    if (!this.listeners.has(jobId)) {
      this.listeners.set(jobId, new Set());
    }
    this.listeners.get(jobId)!.add(callback);

    return () => {
      const set = this.listeners.get(jobId);
      if (set) {
        set.delete(callback);
        if (set.size === 0) this.listeners.delete(jobId);
      }
    };
  }

  public subscribeAll(callback: EventCallback): () => void {
    this.globalListeners.add(callback);
    return () => {
      this.globalListeners.delete(callback);
    };
  }

  private emitEvent(event: StreamEvent): void {
    const set = this.listeners.get(event.jobId);
    if (set) {
      for (const callback of set) {
        try {
          callback(event);
        } catch {
          // ignore
        }
      }
    }

    for (const callback of this.globalListeners) {
      try {
        callback(event);
      } catch {
        // ignore
      }
    }
  }

  private async pollAndProcess(): Promise<void> {
    if (!this.running || this.activeJobsCount >= this.concurrency) return;

    const job = this.queueManager.dequeueNextJob();
    if (!job) return;

    this.activeJobsCount++;
    this.processJob(job).finally(() => {
      this.activeJobsCount--;
    });
  }

  public async processJob(job: ScanJob): Promise<void> {
    const leaseId = this.leaseManager.grantLease(job);
    this.queueManager.getStore().set(job);

    const abortController = new AbortController();
    this.abortControllers.set(job.id, abortController);

    const heartbeatTimer = setInterval(() => {
      const ok = this.leaseManager.heartbeat(job, leaseId);
      if (!ok) {
        abortController.abort();
      } else {
        this.queueManager.getStore().set(job);
        this.emitEvent({
          type: "heartbeat",
          jobId: job.id,
          status: job.status,
          progress: job.progress,
          timestamp: Date.now(),
        });
      }
    }, this.heartbeatIntervalMs);

    const timeoutTimer = setTimeout(() => {
      job.status = "timed_out";
      job.error = `Job exceeded maximum allowed execution time of ${job.timeoutMs}ms`;
      abortController.abort();
    }, job.timeoutMs);

    let sandbox: TenantSandbox | undefined;

    try {
      this.updateProgress(job, 10, "preparing", "Creating tenant isolation sandbox...");

      sandbox = new TenantSandbox({
        tenantId: job.tenantId,
        jobId: job.id,
      });

      const sandboxPaths = sandbox.writeFiles(job.files);

      this.updateProgress(job, 30, "scanning", "Executing ChainProof contract analyzer...");

      let scanConfig: ScanConfig = {
        targets: sandboxPaths,
        useSlither: job.config.useSlither ?? false,
        useLLM: job.config.useLLM ?? false,
        useMetrics: job.config.useMetrics ?? true,
        minSeverity: job.config.minSeverity ?? "low",
        apiKey: job.config.apiKey,
        llmProvider: job.config.llmProvider,
        llmModel: job.config.llmModel,
      };

      const policyEnforcer = new TenantPolicyEnforcer({ tenantId: job.tenantId });
      scanConfig = policyEnforcer.enforceScanConfig(scanConfig);

      if (job.cancelRequested || abortController.signal.aborted) {
        throw new Error("Job execution cancelled");
      }

      const rawResult = await scan(scanConfig);

      if (job.cancelRequested || abortController.signal.aborted) {
        throw new Error("Job execution cancelled");
      }

      this.updateProgress(job, 90, "remapping", "Remapping file paths and formatting result...");

      const sandboxDir = sandbox.getSandboxDir();

      const remappedResult: ScanResult = {
        ...rawResult,
        files: rawResult.files.map((fileResult) => {
          const idx = sandboxPaths.findIndex((p) => p === fileResult.file);
          const originalPath = idx !== -1 ? job.files[idx].path : fileResult.file;

          return {
            ...fileResult,
            file: originalPath,
            findings: fileResult.findings.map((finding) => ({
              ...finding,
              file: originalPath,
              evidence: finding.evidence?.map((ev) => ({
                ...ev,
                file: ev.file ? ErrorSanitizer.sanitizePath(ev.file, sandboxDir) : originalPath,
              })),
            })),
            gasHints: fileResult.gasHints.map((hint) => ({
              ...hint,
              file: originalPath,
            })),
          };
        }),
      };

      job.result = remappedResult;
      job.status = "completed";
      job.completedAt = Date.now();
      this.updateProgress(job, 100, "completed", "Scan completed successfully");

      this.emitEvent({
        type: "complete",
        jobId: job.id,
        status: job.status,
        progress: job.progress,
        data: remappedResult,
        timestamp: Date.now(),
      });
    } catch (err) {
      const sandboxDir = sandbox?.getSandboxDir();
      const sanitizedErr = ErrorSanitizer.sanitizeError(err, sandboxDir);
      const errMessage = sanitizedErr.message;

      if (job.cancelRequested || errMessage.includes("cancelled")) {
        job.status = "cancelled";
        job.error = "Job was cancelled by user";
        this.updateProgress(job, 100, "cancelled", job.error);
      } else if (job.status === "timed_out") {
        this.updateProgress(job, 100, "timed_out", job.error ?? "Execution timed out");
      } else {
        job.attempts++;
        if (job.attempts < job.maxRetries) {
          job.status = "queued";
          this.updateProgress(
            job,
            0,
            "queued",
            `Scan attempt ${job.attempts} failed (${errMessage}). Requeued for retry.`
          );
        } else {
          job.status = "failed";
          job.error = errMessage;
          job.completedAt = Date.now();
          this.updateProgress(job, 100, "failed", `Scan failed after ${job.attempts} attempt(s): ${errMessage}`);
        }
      }

      this.emitEvent({
        type: "error",
        jobId: job.id,
        status: job.status,
        progress: job.progress,
        data: { error: job.error },
        timestamp: Date.now(),
      });
    } finally {
      clearInterval(heartbeatTimer);
      clearTimeout(timeoutTimer);
      this.leaseManager.releaseLease(job);
      this.abortControllers.delete(job.id);
      this.queueManager.getStore().set(job);

      if (sandbox) {
        sandbox.cleanup();
      }
    }
  }

  private updateProgress(job: ScanJob, percentage: number, step: string, message?: string): void {
    const progress: JobProgress = {
      percentage,
      step,
      message,
      timestamp: Date.now(),
    };
    job.progress = progress;
    job.updatedAt = Date.now();
    this.queueManager.getStore().set(job);

    this.emitEvent({
      type: "progress",
      jobId: job.id,
      status: job.status,
      progress,
      timestamp: Date.now(),
    });
  }

  public sweepStaleLeases(): number {
    const allJobs = this.queueManager.getStore().values();
    const staleJobs = this.leaseManager.findStaleJobs(allJobs);

    let recovered = 0;
    for (const job of staleJobs) {
      this.leaseManager.releaseLease(job);
      job.attempts++;

      if (job.attempts < job.maxRetries) {
        job.status = "queued";
        job.progress = {
          percentage: 0,
          step: "queued",
          message: "Stale worker lease detected. Job requeued automatically.",
          timestamp: Date.now(),
        };
      } else {
        job.status = "failed";
        job.error = "Worker crash / stale lease timeout exceeded max retries";
        job.completedAt = Date.now();
      }

      this.queueManager.getStore().set(job);
      recovered++;
    }

    return recovered;
  }
}
