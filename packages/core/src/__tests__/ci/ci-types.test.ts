import {
  redactSecrets,
  validateCIToken,
  truncateMessage,
  ANNOTATION_MESSAGE_MAX_LENGTH,
  SEVERITY_MAP,
  DEFAULT_RETRY_CONFIG,
} from "../../ci/types";
import type { Finding, Severity } from "../../types";

describe("CI Types", () => {
  describe("redactSecrets", () => {
    it("redacts Bearer tokens", () => {
      const text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456";
      const redacted = redactSecrets(text);
      expect(redacted).toContain("[REDACTED]");
      expect(redacted).not.toContain("abcdefghijklmnopqrstuvwxyz123456");
    });

    it("redacts Basic auth tokens", () => {
      const text = "Basic dXNlcm5hbWU6cGFzc3dvcmQxMjM0NTY3ODk=";
      const redacted = redactSecrets(text);
      expect(redacted).toContain("[REDACTED]");
      expect(redacted).not.toContain("dXNlcm5hbWU6cGFzc3dvcmQxMjM0NTY3ODk=");
    });

    it("redacts 64-char hex strings (private keys)", () => {
      const text = "The key is 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
      const redacted = redactSecrets(text);
      expect(redacted).toContain("[REDACTED]");
      expect(redacted).not.toContain("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    });

    it("redacts env vars containing TOKEN in the name", () => {
      const envVars = {
        GITLAB_TOKEN: "glpat-xxxxxxxxxxxxxxxxxxxx",
        CI_JOB_TOKEN: "ci-job-token-value",
        NODE_DEBUG: "not-a-secret",
      };
      const text = "Using token glpat-xxxxxxxxxxxxxxxxxxxx for auth";
      const redacted = redactSecrets(text, envVars);
      expect(redacted).toContain("[REDACTED]");
      expect(redacted).not.toContain("glpat-xxxxxxxxxxxxxxxxxxxx");
    });

    it("does not redact non-secret env vars", () => {
      const envVars = {
        NODE_ENV: "production",
        PORT: "4243",
      };
      const text = "Running in production mode on port 4243";
      const redacted = redactSecrets(text, envVars);
      expect(redacted).toBe(text);
    });

    it("returns unchanged text when there is nothing to redact", () => {
      const text = "ChainProof scan completed successfully";
      expect(redactSecrets(text)).toBe(text);
    });
  });

  describe("validateCIToken", () => {
    it("rejects undefined tokens", () => {
      expect(validateCIToken(undefined, "gitlab")).toBe(false);
    });

    it("rejects empty strings", () => {
      expect(validateCIToken("", "gitlab")).toBe(false);
      expect(validateCIToken("   ", "gitlab")).toBe(false);
    });

    it("rejects placeholder tokens", () => {
      expect(validateCIToken("your-token-here", "gitlab")).toBe(false);
      expect(validateCIToken("CHANGE_ME", "gitlab")).toBe(false);
      expect(validateCIToken("REPLACE_ME_1234567890", "bitbucket")).toBe(false);
    });

    it("validates GitLab tokens (minimum 20 chars)", () => {
      expect(validateCIToken("short", "gitlab")).toBe(false);
      expect(validateCIToken("a".repeat(19), "gitlab")).toBe(false);
      expect(validateCIToken("a".repeat(20), "gitlab")).toBe(true);
      expect(validateCIToken("glpat-xxxxxxxxxxxxxxxxxxxx", "gitlab")).toBe(true);
    });

    it("validates Bitbucket tokens (minimum 20 chars)", () => {
      expect(validateCIToken("short", "bitbucket")).toBe(false);
      expect(validateCIToken("a".repeat(20), "bitbucket")).toBe(true);
    });

    it("validates GitHub tokens (40+ chars or ghp_ prefix)", () => {
      expect(validateCIToken("short", "github")).toBe(false);
      expect(validateCIToken("a".repeat(39), "github")).toBe(false);
      expect(validateCIToken("a".repeat(40), "github")).toBe(true);
      expect(validateCIToken("ghp_" + "a".repeat(36), "github")).toBe(true);
      expect(validateCIToken("gho_" + "a".repeat(36), "github")).toBe(true);
    });
  });

  describe("truncateMessage", () => {
    it("does not truncate short messages", () => {
      const msg = "Short message";
      expect(truncateMessage(msg)).toBe(msg);
    });

    it("truncates messages exceeding ANNOTATION_MESSAGE_MAX_LENGTH", () => {
      const longMsg = "A".repeat(ANNOTATION_MESSAGE_MAX_LENGTH + 100);
      const result = truncateMessage(longMsg);
      expect(result.length).toBe(ANNOTATION_MESSAGE_MAX_LENGTH);
      expect(result.endsWith("...")).toBe(true);
    });

    it("does not truncate messages at exactly the max length", () => {
      const exactMsg = "B".repeat(ANNOTATION_MESSAGE_MAX_LENGTH);
      expect(truncateMessage(exactMsg)).toBe(exactMsg);
      expect(truncateMessage(exactMsg).length).toBe(ANNOTATION_MESSAGE_MAX_LENGTH);
    });
  });

  describe("SEVERITY_MAP", () => {
    it("has mappings for all providers", () => {
      expect(SEVERITY_MAP.gitlab).toBeDefined();
      expect(SEVERITY_MAP.bitbucket).toBeDefined();
      expect(SEVERITY_MAP.github).toBeDefined();
    });

    it("maps all severity levels for each provider", () => {
      const severities: Severity[] = ["critical", "high", "medium", "low", "info", "gas"];
      for (const provider of ["gitlab", "bitbucket", "github"] as const) {
        for (const sev of severities) {
          expect(SEVERITY_MAP[provider][sev]).toBeDefined();
          expect(typeof SEVERITY_MAP[provider][sev]).toBe("string");
        }
      }
    });

    it("gitlab blocker maps to critical", () => {
      expect(SEVERITY_MAP.gitlab.critical).toBe("blocker");
      expect(SEVERITY_MAP.gitlab.high).toBe("critical");
    });

    it("bitbucket uses uppercase severity names", () => {
      expect(SEVERITY_MAP.bitbucket.critical).toBe("BLOCKER");
      expect(SEVERITY_MAP.bitbucket.high).toBe("CRITICAL");
      expect(SEVERITY_MAP.bitbucket.medium).toBe("MAJOR");
    });
  });

  describe("DEFAULT_RETRY_CONFIG", () => {
    it("has reasonable defaults", () => {
      expect(DEFAULT_RETRY_CONFIG.maxRetries).toBe(3);
      expect(DEFAULT_RETRY_CONFIG.baseDelayMs).toBe(1000);
      expect(DEFAULT_RETRY_CONFIG.maxDelayMs).toBe(30000);
      expect(DEFAULT_RETRY_CONFIG.retryableStatusCodes).toContain(429);
      expect(DEFAULT_RETRY_CONFIG.retryableStatusCodes).toContain(500);
      expect(DEFAULT_RETRY_CONFIG.retryableStatusCodes).toContain(503);
    });
  });
});
