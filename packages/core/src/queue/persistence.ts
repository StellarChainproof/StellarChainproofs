import * as fs from "fs";
import * as path from "path";
import { ScanJob } from "./types";

export interface DurableJobStoreOptions {
  storageDir?: string;
  autoSave?: boolean;
}

export class DurableJobStore {
  private jobs: Map<string, ScanJob> = new Map();
  private storageDir?: string;
  private autoSave: boolean;

  constructor(options: DurableJobStoreOptions = {}) {
    this.storageDir = options.storageDir;
    this.autoSave = options.autoSave ?? true;

    if (this.storageDir) {
      if (!fs.existsSync(this.storageDir)) {
        fs.mkdirSync(this.storageDir, { recursive: true });
      }
      this.loadFromDisk();
    }
  }

  public get(jobId: string): ScanJob | undefined {
    return this.jobs.get(jobId);
  }

  public set(job: ScanJob): void {
    job.updatedAt = Date.now();
    this.jobs.set(job.id, job);
    if (this.autoSave) {
      this.saveJobToDisk(job);
    }
  }

  public delete(jobId: string): boolean {
    const deleted = this.jobs.delete(jobId);
    if (this.storageDir) {
      const filePath = path.join(this.storageDir, `${jobId}.json`);
      if (fs.existsSync(filePath)) {
        try {
          fs.unlinkSync(filePath);
        } catch {
          // ignore
        }
      }
    }
    return deleted;
  }

  public values(): ScanJob[] {
    return Array.from(this.jobs.values());
  }

  public clear(): void {
    this.jobs.clear();
    if (this.storageDir && fs.existsSync(this.storageDir)) {
      const files = fs.readdirSync(this.storageDir);
      for (const file of files) {
        if (file.endsWith(".json")) {
          try {
            fs.unlinkSync(path.join(this.storageDir, file));
          } catch {
            // ignore
          }
        }
      }
    }
  }

  private saveJobToDisk(job: ScanJob): void {
    if (!this.storageDir) return;
    try {
      const filePath = path.join(this.storageDir, `${job.id}.json`);
      const tmpPath = `${filePath}.tmp`;
      fs.writeFileSync(tmpPath, JSON.stringify(job, null, 2), "utf-8");
      fs.renameSync(tmpPath, filePath);
    } catch (err) {
      console.error(`[DurableJobStore] Failed to persist job ${job.id}:`, err);
    }
  }

  private loadFromDisk(): void {
    if (!this.storageDir || !fs.existsSync(this.storageDir)) return;
    try {
      const files = fs.readdirSync(this.storageDir);
      for (const file of files) {
        if (file.endsWith(".json")) {
          try {
            const content = fs.readFileSync(path.join(this.storageDir, file), "utf-8");
            const job = JSON.parse(content) as ScanJob;
            this.jobs.set(job.id, job);
          } catch {
            // ignore
          }
        }
      }
    } catch (err) {
      console.error("[DurableJobStore] Error loading jobs from disk:", err);
    }
  }
}
