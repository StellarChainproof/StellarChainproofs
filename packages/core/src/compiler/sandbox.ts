/**
 * @packageDocumentation
 * @chainproof/core — Sandboxed Execution, Environment Isolation & Error Sanitizer
 */

import * as path from "path";
import * as fs from "fs";

export interface SandboxExecutionOptions {
  timeoutMs: number;
  maxBufferBytes: number;
  allowedEnvVars?: string[];
  workingDirectory?: string;
}

export const DEFAULT_SANDBOX_OPTIONS: SandboxExecutionOptions = {
  timeoutMs: 15_000,
  maxBufferBytes: 10 * 1024 * 1024, // 10MB
  allowedEnvVars: ["PATH", "NODE_ENV", "LANG", "TMPDIR"],
};

/**
 * Creates an isolated, scrubbed environment object stripping credentials and secrets.
 */
export function createIsolatedEnvironment(
  customEnv?: Record<string, string>,
  allowedKeys: string[] = DEFAULT_SANDBOX_OPTIONS.allowedEnvVars ?? [],
): NodeJS.ProcessEnv {
  const cleanEnv: NodeJS.ProcessEnv = {};

  // Copy safe system env keys only
  for (const key of allowedKeys) {
    if (process.env[key]) {
      cleanEnv[key] = process.env[key];
    }
  }

  // Explicitly deny known sensitive tokens
  const BLOCKED_PATTERNS = [
    /KEY/i,
    /SECRET/i,
    /TOKEN/i,
    /PASSWORD/i,
    /AUTH/i,
    /CREDENTIAL/i,
    /PRIVATE/i,
  ];

  if (customEnv) {
    for (const [k, v] of Object.entries(customEnv)) {
      if (!BLOCKED_PATTERNS.some((p) => p.test(k))) {
        cleanEnv[k] = v;
      }
    }
  }

  return cleanEnv;
}

/**
 * Sanitizes an error message or output string to prevent leaking local filesystem paths or credentials.
 */
export function sanitizeCompilerOutput(text: string, baseDir?: string): string {
  if (!text) return "";

  let sanitized = text;

  // Strip user home directory paths (/home/username or /Users/username)
  sanitized = sanitized.replace(
    /(?:\/home\/[a-zA-Z0-9_-]+|\/Users\/[a-zA-Z0-9_-]+|\/root|[a-zA-Z]:\\[Uu]sers\\[a-zA-Z0-9_-]+)/g,
    "<sanitized-home>",
  );

  // If baseDir provided, normalize relative to workspace
  if (baseDir) {
    const escapedBase = baseDir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    sanitized = sanitized.replace(new RegExp(escapedBase, "g"), ".");
  }

  // Remove potential bearer tokens / API keys in output
  sanitized = sanitized.replace(/([sS]k-[a-zA-Z0-9_-]{20,})/g, "[REDACTED_API_KEY]");
  sanitized = sanitized.replace(/(0x[a-fA-F0-9]{64})/g, "[REDACTED_PRIVATE_KEY]");

  return sanitized;
}

export interface CacheValidationReport {
  cacheDir: string;
  totalFiles: number;
  validFiles: number;
  corruptFiles: string[];
  cleanedFiles: string[];
}

/**
 * Validates a compiler cache directory, identifying and optionally removing corrupted cache files.
 */
export function validateCompilerCache(
  cacheDir: string,
  autoClean: boolean = false,
): CacheValidationReport {
  const report: CacheValidationReport = {
    cacheDir,
    totalFiles: 0,
    validFiles: 0,
    corruptFiles: [],
    cleanedFiles: [],
  };

  if (!fs.existsSync(cacheDir)) {
    return report;
  }

  try {
    const entries = fs.readdirSync(cacheDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      report.totalFiles++;
      const filePath = path.join(cacheDir, entry.name);

      let isCorrupt = false;
      try {
        const stats = fs.statSync(filePath);
        if (stats.size === 0) {
          isCorrupt = true;
        } else if (entry.name.endsWith(".json")) {
          const content = fs.readFileSync(filePath, "utf-8");
          JSON.parse(content);
        }
      } catch {
        isCorrupt = true;
      }

      if (isCorrupt) {
        report.corruptFiles.push(filePath);
        if (autoClean) {
          try {
            fs.unlinkSync(filePath);
            report.cleanedFiles.push(filePath);
          } catch {
            // ignore deletion errors
          }
        }
      } else {
        report.validFiles++;
      }
    }
  } catch {
    // Return partial report on read failure
  }

  return report;
}
