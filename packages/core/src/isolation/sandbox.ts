import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { IsolationLimits, SandboxConfig } from "./types";
import { JobInputFile } from "../queue/types";

export const DEFAULT_ISOLATION_LIMITS: IsolationLimits = {
  maxTotalSizeBytes: 50 * 1024 * 1024,
  maxSingleFileSizeBytes: 10 * 1024 * 1024,
  maxFileCount: 500,
  maxCompressionRatio: 100,
  maxDepth: 10,
};

export class TenantSandbox {
  private tenantId: string;
  private jobId: string;
  private sandboxDir: string;
  private limits: IsolationLimits;
  private writtenFiles: string[] = [];

  constructor(config: SandboxConfig) {
    this.tenantId = config.tenantId.replace(/[^a-zA-Z0-9_-]/g, "_");
    this.jobId = config.jobId.replace(/[^a-zA-Z0-9_-]/g, "_");

    this.limits = {
      ...DEFAULT_ISOLATION_LIMITS,
      ...config.limits,
    };

    const base = config.baseDir ?? path.join(os.tmpdir(), "chainproof-sandboxes");
    this.sandboxDir = path.join(base, `tenant-${this.tenantId}`, `job-${this.jobId}`);

    if (!fs.existsSync(this.sandboxDir)) {
      fs.mkdirSync(this.sandboxDir, { recursive: true, mode: 0o700 });
    }
  }

  public getSandboxDir(): string {
    return this.sandboxDir;
  }

  public getSanitizedEnv(): Record<string, string> {
    const cleanEnv: Record<string, string> = {};
    const safeVars = [
      "PATH",
      "HOME",
      "USER",
      "TMPDIR",
      "LANG",
      "LC_ALL",
      "NODE_ENV",
      "PYTHONPATH",
      "SOLC_VERSION",
    ];

    for (const v of safeVars) {
      if (process.env[v]) {
        cleanEnv[v] = process.env[v]!;
      }
    }

    cleanEnv["CHAINPROOF_SANDBOX"] = "true";
    cleanEnv["CHAINPROOF_TENANT_ID"] = this.tenantId;
    cleanEnv["CHAINPROOF_JOB_ID"] = this.jobId;

    return cleanEnv;
  }

  public writeFiles(files: JobInputFile[]): string[] {
    if (files.length > this.limits.maxFileCount) {
      throw new Error(`Exceeded maximum file count limit: ${files.length} > ${this.limits.maxFileCount}`);
    }

    let totalSize = 0;
    const writtenPaths: string[] = [];

    for (const file of files) {
      const contentBuffer = Buffer.from(file.content, "utf-8");
      const fileSize = contentBuffer.length;

      if (fileSize > this.limits.maxSingleFileSizeBytes) {
        throw new Error(
          `File '${file.path}' exceeds single file size limit (${fileSize} > ${this.limits.maxSingleFileSizeBytes} bytes)`
        );
      }

      totalSize += fileSize;
      if (totalSize > this.limits.maxTotalSizeBytes) {
        throw new Error(
          `Total file size exceeds limit (${totalSize} > ${this.limits.maxTotalSizeBytes} bytes)`
        );
      }

      const normalizedPath = path.normalize(file.path).replace(/^(\.\.[/\\])+/, "");
      if (path.isAbsolute(normalizedPath) || normalizedPath.startsWith("..")) {
        throw new Error(`Illegal path traversal detected in file path: '${file.path}'`);
      }

      const fullPath = path.join(this.sandboxDir, normalizedPath);

      const relative = path.relative(this.sandboxDir, fullPath);
      if (relative.startsWith("..") || path.isAbsolute(relative)) {
        throw new Error(`Path traversal escape detected: '${file.path}'`);
      }

      const dirName = path.dirname(fullPath);
      if (!fs.existsSync(dirName)) {
        fs.mkdirSync(dirName, { recursive: true, mode: 0o700 });
      }

      fs.writeFileSync(fullPath, contentBuffer, { mode: 0o600 });
      writtenPaths.push(fullPath);
      this.writtenFiles.push(fullPath);
    }

    return writtenPaths;
  }

  public cleanup(): void {
    try {
      if (fs.existsSync(this.sandboxDir)) {
        fs.rmSync(this.sandboxDir, { recursive: true, force: true });
      }
    } catch {
      // Ignore
    }
  }
}
