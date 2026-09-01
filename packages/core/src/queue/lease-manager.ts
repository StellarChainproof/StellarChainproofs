import * as crypto from "crypto";
import { ScanJob } from "./types";

export interface LeaseManagerOptions {
  leaseDurationMs?: number;
  heartbeatTimeoutMs?: number;
}

export class LeaseManager {
  private leaseDurationMs: number;
  private heartbeatTimeoutMs: number;

  constructor(options: LeaseManagerOptions = {}) {
    this.leaseDurationMs = options.leaseDurationMs ?? 30000;
    this.heartbeatTimeoutMs = options.heartbeatTimeoutMs ?? 15000;
  }

  public grantLease(job: ScanJob): string {
    const leaseId = `lease_${crypto.randomBytes(8).toString("hex")}`;
    const now = Date.now();

    job.leaseId = leaseId;
    job.leaseExpiresAt = now + this.leaseDurationMs;
    job.heartbeatAt = now;
    job.status = "running";
    job.startedAt = job.startedAt ?? now;

    return leaseId;
  }

  public heartbeat(job: ScanJob, leaseId: string): boolean {
    if (job.leaseId !== leaseId) {
      return false;
    }

    const now = Date.now();
    job.leaseExpiresAt = now + this.leaseDurationMs;
    job.heartbeatAt = now;
    return true;
  }

  public releaseLease(job: ScanJob): void {
    job.leaseId = undefined;
    job.leaseExpiresAt = undefined;
    job.heartbeatAt = undefined;
  }

  public isLeaseExpired(job: ScanJob): boolean {
    if (job.status !== "running") return false;
    if (!job.leaseExpiresAt || !job.heartbeatAt) return true;

    const now = Date.now();
    if (now > job.leaseExpiresAt) return true;
    if (now - job.heartbeatAt > this.heartbeatTimeoutMs) return true;

    return false;
  }

  public findStaleJobs(jobs: ScanJob[]): ScanJob[] {
    return jobs.filter((job) => this.isLeaseExpired(job));
  }
}
