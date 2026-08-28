import { ScanConfig, ScanResult } from "../types";

export type JobStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "timed_out";

export type JobPriority = 0 | 1 | 2 | 3;

export interface JobProgress {
  percentage: number;
  step: string;
  message?: string;
  timestamp: number;
}

export interface JobInputFile {
  path: string;
  content: string;
}

export interface ScanJob {
  id: string;
  tenantId: string;
  projectId?: string;
  principalId: string;
  priority: JobPriority;
  idempotencyKey?: string;

  files: JobInputFile[];
  config: Partial<ScanConfig>;

  status: JobStatus;
  progress: JobProgress;

  leaseId?: string;
  leaseExpiresAt?: number;
  heartbeatAt?: number;

  attempts: number;
  maxRetries: number;
  timeoutMs: number;
  cancelRequested: boolean;

  result?: ScanResult;
  error?: string;

  createdAt: number;
  updatedAt: number;
  startedAt?: number;
  completedAt?: number;

  tags?: Record<string, string>;
}

export interface SubmitJobOptions {
  tenantId: string;
  projectId?: string;
  principalId: string;
  priority?: JobPriority;
  idempotencyKey?: string;
  files: JobInputFile[];
  config?: Partial<ScanConfig>;
  timeoutMs?: number;
  maxRetries?: number;
  tags?: Record<string, string>;
}

export interface JobFilter {
  tenantId?: string;
  projectId?: string;
  status?: JobStatus | JobStatus[];
  limit?: number;
  offset?: number;
  search?: string;
}

export interface QueueStats {
  totalJobs: number;
  queued: number;
  running: number;
  completed: number;
  failed: number;
  cancelled: number;
  timedOut: number;
  activeTenants: number;
  avgDurationMs: number;
}

export interface StreamEvent {
  type: "progress" | "status" | "error" | "complete" | "heartbeat";
  jobId: string;
  status: JobStatus;
  progress: JobProgress;
  data?: unknown;
  timestamp: number;
}
