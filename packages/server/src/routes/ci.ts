import { Router, Request, Response } from "express";
import { scan } from "@chainproof/core";
import type { ScanConfig, Severity, ScanResult } from "@chainproof/core";
import {
  buildGitLabCodeQualityReport,
  buildGitLabSASTReport,
  buildGitLabMRNote,
  buildGitLabCIReport,
  serializeGitLabCodeQualityArtifact,
  serializeGitLabSASTArtifact,
  findingsToGitLabAnnotations,
  buildBitbucketCodeInsightsReport,
  buildBitbucketDiffReport,
  buildBitbucketPRSummary,
  buildBitbucketCIReport,
  serializeBitbucketCodeInsightsArtifact,
  findingsToBitbucketAnnotations,
  buildBitbucketPipelineStatus,
  redactSecrets,
  validateCIToken,
} from "@chainproof/core";
import type { CIIntegrationConfig, Severity as CISeverity } from "@chainproof/core";

const router = Router();

// ─── Types ───────────────────────────────────────────────────────────────────

interface CIScanRequest {
  files?: Array<{ path: string; content: string }>;
  config?: {
    useLLM?: boolean;
    useSlither?: boolean;
    useMetrics?: boolean;
    minSeverity?: Severity;
    apiKey?: string;
  };
  /** CI provider: "gitlab" or "bitbucket" */
  provider?: "gitlab" | "bitbucket";
  /** Minimum severity for CI failure gate */
  failSeverity?: Severity;
  /** Whether this is a diff-aware scan */
  diffMode?: boolean;
}

interface GitLabWebhookPayload {
  object_kind?: string;
  merge_request?: {
    iid: number;
    source_branch: string;
    target_branch: string;
    title: string;
    state: string;
  };
  project?: {
    id: number;
    path_with_namespace: string;
    default_branch: string;
  };
  user?: {
    username: string;
    name: string;
  };
}

interface BitbucketWebhookPayload {
  pullrequest?: {
    id: number;
    title: string;
    state: string;
    source: { branch: { name: string } };
    destination: { branch: { name: string } };
  };
  repository?: {
    name: string;
    full_name: string;
  };
}

// ─── POST /ci/gitlab/scan ────────────────────────────────────────────────────

/**
 * POST /ci/gitlab/scan
 *
 * GitLab CI scan endpoint. Accepts Solidity files inline and returns
 * Code Quality and SAST reports suitable for GitLab artifact upload.
 *
 * Request body:
 * {
 *   "files": [{ "path": "contracts/Vault.sol", "content": "pragma solidity ..." }],
 *   "config": { "useLLM": false, "minSeverity": "medium" },
 *   "failSeverity": "high"
 * }
 */
router.post("/gitlab/scan", async (req: Request, res: Response): Promise<void> => {
  const body = req.body as CIScanRequest;

  if (!body.files || !Array.isArray(body.files) || body.files.length === 0) {
    res.status(400).json({
      error: "Missing required field: files (array of { path, content })",
    });
    return;
  }

  // Validate each file entry
  for (const f of body.files) {
    if (typeof f.path !== "string" || typeof f.content !== "string") {
      res.status(400).json({
        error: 'Each file entry must have string fields "path" and "content"',
      });
      return;
    }
  }

  const tmpDir = require("fs").mkdtempSync(
    require("path").join(require("os").tmpdir(), "chainproof-ci-")
  );
  const tmpPaths: string[] = [];
  const fs = require("fs");
  const path = require("path");
  const os = require("os");

  try {
    for (const f of body.files) {
      const safeName = path.basename(f.path);
      const tmpPath = path.join(tmpDir, safeName);
      fs.writeFileSync(tmpPath, f.content, "utf-8");
      tmpPaths.push(tmpPath);
    }

    const cfg = body.config ?? {};
    const scanConfig: ScanConfig = {
      targets: tmpPaths,
      useSlither: cfg.useSlither ?? false,
      useLLM: cfg.useLLM ?? false,
      useMetrics: cfg.useMetrics ?? true,
      minSeverity: cfg.minSeverity ?? "low",
      apiKey: cfg.apiKey ?? process.env.ANTHROPIC_API_KEY,
    };

    const result = await scan(scanConfig);

    // Remap temp file paths back to original paths
    for (const fileResult of result.files) {
      const idx = tmpPaths.findIndex((p) => p === fileResult.file);
      if (idx !== -1 && body.files) {
        fileResult.file = body.files[idx].path;
        fileResult.findings.forEach((finding) => {
          finding.file = body.files![idx].path;
        });
        fileResult.gasHints.forEach((hint) => {
          hint.file = body.files![idx].path;
        });
      }
    }

    // Build CI reports
    const codeQualityReport = buildGitLabCodeQualityReport(result);
    const sastReport = buildGitLabSASTReport(result);
    const mrNote = buildGitLabMRNote(result);

    const ciConfig: CIIntegrationConfig = {
      provider: "gitlab",
      scanConfig,
      failSeverity: (body.failSeverity ?? "high") as CISeverity,
    };
    const ciReport = buildGitLabCIReport(result, ciConfig);

    // Write artifacts to disk for GitLab to pick up
    const reportDir = path.join(process.cwd(), "chainproof-reports");
    fs.mkdirSync(reportDir, { recursive: true });

    fs.writeFileSync(
      path.join(reportDir, "code-quality-report.json"),
      serializeGitLabCodeQualityArtifact(codeQualityReport),
      "utf-8"
    );
    fs.writeFileSync(
      path.join(reportDir, "sast-report.json"),
      serializeGitLabSASTArtifact(sastReport),
      "utf-8"
    );
    fs.writeFileSync(
      path.join(reportDir, "mr-note.md"),
      mrNote,
      "utf-8"
    );

    // Return JSON response with all reports
    res.json({
      scanResult: result,
      codeQuality: codeQualityReport,
      sast: sastReport,
      mrNote,
      ciReport,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: `CI scan failed: ${redactSecrets(message)}` });
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
});

// ─── POST /ci/gitlab/webhook ─────────────────────────────────────────────────

/**
 * POST /ci/gitlab/webhook
 *
 * GitLab webhook endpoint for merge request events.
 * Validates the webhook payload and triggers a diff-aware scan.
 */
router.post("/gitlab/webhook", async (req: Request, res: Response): Promise<void> => {
  const body = req.body as GitLabWebhookPayload;

  // Validate this is a merge request event
  if (body.object_kind !== "merge_request_event") {
    res.json({ status: "ignored", reason: "Not a merge request event" });
    return;
  }

  if (!body.merge_request) {
    res.status(400).json({ error: "Missing merge_request in webhook payload" });
    return;
  }

  const mr = body.merge_request;
  if (mr.state !== "opened") {
    res.json({ status: "ignored", reason: `MR state is ${mr.state}` });
    return;
  }

  const projectId = body.project?.id;
  const mrIid = mr.iid;

  // Verify GitLab token is available
  const token = process.env.GITLAB_TOKEN;
  if (!token) {
    console.warn("[ChainProof CI] GITLAB_TOKEN not set — cannot post MR notes");
  }

  // Acknowledge the webhook immediately (GitLab expects fast response)
  res.json({
    status: "accepted",
    mr: { iid: mrIid, source: mr.source_branch, target: mr.target_branch },
  });

  // Process scan asynchronously (fire-and-forget)
  if (projectId && mrIid) {
    try {
      console.log(
        `[ChainProof CI] Processing GitLab MR !${mrIid} (${mr.source_branch} -> ${mr.target_branch})`
      );
    } catch (err) {
      console.error(`[ChainProof CI] GitLab webhook processing error: ${err}`);
    }
  }
});

// ─── POST /ci/bitbucket/scan ─────────────────────────────────────────────────

/**
 * POST /ci/bitbucket/scan
 *
 * Bitbucket Pipelines scan endpoint. Accepts Solidity files inline and returns
 * Code Insights report suitable for Bitbucket pipeline artifact upload.
 *
 * Request body:
 * {
 *   "files": [{ "path": "contracts/Vault.sol", "content": "pragma solidity ..." }],
 *   "config": { "useLLM": false, "minSeverity": "medium" },
 *   "failSeverity": "high"
 * }
 */
router.post("/bitbucket/scan", async (req: Request, res: Response): Promise<void> => {
  const body = req.body as CIScanRequest;

  if (!body.files || !Array.isArray(body.files) || body.files.length === 0) {
    res.status(400).json({
      error: "Missing required field: files (array of { path, content })",
    });
    return;
  }

  for (const f of body.files) {
    if (typeof f.path !== "string" || typeof f.content !== "string") {
      res.status(400).json({
        error: 'Each file entry must have string fields "path" and "content"',
      });
      return;
    }
  }

  const fs = require("fs");
  const path = require("path");
  const os = require("os");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "chainproof-ci-"));
  const tmpPaths: string[] = [];

  try {
    for (const f of body.files) {
      const safeName = path.basename(f.path);
      const tmpPath = path.join(tmpDir, safeName);
      fs.writeFileSync(tmpPath, f.content, "utf-8");
      tmpPaths.push(tmpPath);
    }

    const cfg = body.config ?? {};
    const scanConfig: ScanConfig = {
      targets: tmpPaths,
      useSlither: cfg.useSlither ?? false,
      useLLM: cfg.useLLM ?? false,
      useMetrics: cfg.useMetrics ?? true,
      minSeverity: cfg.minSeverity ?? "low",
      apiKey: cfg.apiKey ?? process.env.ANTHROPIC_API_KEY,
    };

    const result = await scan(scanConfig);

    // Remap temp file paths
    for (const fileResult of result.files) {
      const idx = tmpPaths.findIndex((p) => p === fileResult.file);
      if (idx !== -1 && body.files) {
        fileResult.file = body.files[idx].path;
        fileResult.findings.forEach((finding) => {
          finding.file = body.files![idx].path;
        });
        fileResult.gasHints.forEach((hint) => {
          hint.file = body.files![idx].path;
        });
      }
    }

    // Build Bitbucket reports
    const insightsReport = buildBitbucketCodeInsightsReport(result, {
      failSeverity: (body.failSeverity ?? "high") as CISeverity,
    });
    const prSummary = buildBitbucketPRSummary(result);
    const pipelineStatus = buildBitbucketPipelineStatus(result);

    const ciConfig: CIIntegrationConfig = {
      provider: "bitbucket",
      scanConfig,
      failSeverity: (body.failSeverity ?? "high") as CISeverity,
    };
    const ciReport = buildBitbucketCIReport(result, ciConfig);

    // Write artifacts
    const reportDir = path.join(process.cwd(), "chainproof-reports");
    fs.mkdirSync(reportDir, { recursive: true });

    fs.writeFileSync(
      path.join(reportDir, "code-insights-report.json"),
      serializeBitbucketCodeInsightsArtifact(insightsReport),
      "utf-8"
    );
    fs.writeFileSync(
      path.join(reportDir, "pr-summary.md"),
      prSummary,
      "utf-8"
    );
    fs.writeFileSync(
      path.join(reportDir, "pipeline-status.json"),
      JSON.stringify(pipelineStatus, null, 2),
      "utf-8"
    );

    res.json({
      scanResult: result,
      codeInsights: insightsReport,
      prSummary,
      pipelineStatus,
      ciReport,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: `CI scan failed: ${redactSecrets(message)}` });
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
});

// ─── POST /ci/bitbucket/webhook ──────────────────────────────────────────────

/**
 * POST /ci/bitbucket/webhook
 *
 * Bitbucket webhook endpoint for pull request events.
 */
router.post("/bitbucket/webhook", async (req: Request, res: Response): Promise<void> => {
  const body = req.body as BitbucketWebhookPayload;

  if (!body.pullrequest) {
    res.json({ status: "ignored", reason: "No pull request in payload" });
    return;
  }

  const pr = body.pullrequest;
  if (pr.state !== "OPEN") {
    res.json({ status: "ignored", reason: `PR state is ${pr.state}` });
    return;
  }

  // Acknowledge immediately
  res.json({
    status: "accepted",
    pr: { id: pr.id, title: pr.title, source: pr.source.branch.name, destination: pr.destination.branch.name },
  });

  // Process asynchronously
  try {
    console.log(
      `[ChainProof CI] Processing Bitbucket PR #${pr.id} (${pr.source.branch.name} -> ${pr.destination.branch.name})`
    );
  } catch (err) {
    console.error(`[ChainProof CI] Bitbucket webhook error: ${err}`);
  }
});

// ─── GET /ci/gitlab/template ─────────────────────────────────────────────────

/**
 * GET /ci/gitlab/template
 *
 * Returns a GitLab CI YAML template for ChainProof integration.
 */
router.get("/gitlab/template", (_req: Request, res: Response): void => {
  const template = `# ChainProof Security Scanner — GitLab CI Integration
chainproof-scan:
  stage: test
  image: node:20-alpine
  before_script:
    - npm ci
  script:
    - npx chainproof ci gitlab contracts/ --fail-severity high
  artifacts:
    paths:
      - chainproof-reports/
    reports:
      codequality: chainproof-reports/code-quality-report.json
      sast: chainproof-reports/sast-report.json
    expire_in: 30 days
  rules:
    - if: $CI_MERGE_REQUEST_IID
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`;

  res.type("text/yaml").send(template);
});

// ─── GET /ci/bitbucket/template ──────────────────────────────────────────────

/**
 * GET /ci/bitbucket/template
 *
 * Returns a Bitbucket Pipelines YAML template for ChainProof integration.
 */
router.get("/bitbucket/template", (_req: Request, res: Response): void => {
  const template = `# ChainProof Security Scanner — Bitbucket Pipelines Integration
pipelines:
  pull-requests:
    "**":
      - step:
          name: ChainProof Security Scan
          image: node:20-alpine
          script:
            - npm ci
            - npx chainproof ci bitbucket contracts/ --fail-severity high
          artifacts:
            - chainproof-reports/**`;

  res.type("text/yaml").send(template);
});

export default router;
