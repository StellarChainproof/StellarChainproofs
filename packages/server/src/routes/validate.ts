/**
 * POST /validate — Fork-aware concrete validation REST endpoint.
 *
 * Routes:
 *   POST /validate/plan    — translate static findings into a ValidationPlan
 *   POST /validate/run     — execute a ValidationPlan or single scenario
 *   POST /validate/report  — re-format a saved ValidationReport
 *
 * Security boundaries:
 * - forkUrl is accepted in requests but is never echoed back in responses.
 * - Private keys in AccountSpec are stripped from all responses.
 * - Each run request spawns a fresh isolated adapter process.
 * - No filesystem reads; all data is passed inline in the request body.
 */

import { Router, Request, Response } from "express";
import {
  planValidation,
  runValidationPlan,
  generateValidationMarkdown,
  parseValidationReport,
  serializeValidationReport,
  createCancellationSignal,
  CorruptBundleError,
  ValidationError,
  VALIDATION_SCHEMA_VERSION,
} from "@chainproof/core";
import type {
  Finding,
  RunValidationOptions,
  ValidationScenario,
} from "@chainproof/core";

const router = Router();

// ─── Helpers ──────────────────────────────────────────────────────────────────

function safeErrorMessage(err: unknown): string {
  if (err instanceof ValidationError) return err.message;
  if (err instanceof CorruptBundleError) return err.message;
  if (err instanceof Error) {
    return err.message.replace(/\/[^\s"']+/g, "[path]").slice(0, 500);
  }
  return "Unexpected validation error";
}

function parseAdapterType(value: unknown): "anvil" | "hardhat" {
  if (value === "hardhat") return "hardhat";
  return "anvil";
}

// ─── POST /validate/plan ──────────────────────────────────────────────────────

/**
 * POST /validate/plan
 *
 * Translate an array of static Finding objects into a ValidationPlan.
 *
 * Request body:
 * ```json
 * {
 *   "findings": [...Finding[]],
 *   "options": { "minSeverity": "low", "deduplicateByFile": false }
 * }
 * ```
 *
 * Response 200: `{ "plan": ValidationPlan }`
 * Response 400: malformed request
 */
router.post("/plan", (req: Request, res: Response): void => {
  try {
    const body = req.body as {
      findings?: unknown;
      options?: { minSeverity?: string; deduplicateByFile?: boolean };
    };

    if (!Array.isArray(body.findings)) {
      res.status(400).json({
        error: 'Request body must contain "findings" as an array of Finding objects.',
      });
      return;
    }

    const findings = body.findings as Finding[];
    const opts = body.options ?? {};
    const minSeverity = (opts.minSeverity ?? "low") as
      | "critical" | "high" | "medium" | "low" | "info";

    const plan = planValidation(findings, {
      minSeverity,
      deduplicateByFile: opts.deduplicateByFile ?? false,
    });

    res.status(200).json({ plan });
  } catch (err) {
    res.status(500).json({ error: safeErrorMessage(err) });
  }
});

// ─── POST /validate/run ───────────────────────────────────────────────────────

/**
 * POST /validate/run
 *
 * Execute a ValidationPlan (or array of scenarios) against a local EVM adapter.
 * The adapter process is spawned and killed after each scenario (process isolation).
 *
 * Request body:
 * ```json
 * {
 *   "plan": ValidationPlan,
 *   "adapterType": "anvil",
 *   "forkUrl": "https://...",
 *   "forkBlockNumber": 19000000,
 *   "chainId": 1,
 *   "timeoutMs": 30000,
 *   "format": "json"
 * }
 * ```
 *
 * Response 200: `{ "report": ValidationReport }` or text/markdown
 * Response 400: malformed request
 * Response 500: adapter infrastructure failure
 */
router.post("/run", async (req: Request, res: Response): Promise<void> => {
  const body = req.body as {
    plan?: unknown;
    scenarios?: unknown;
    adapterType?: unknown;
    forkUrl?: string;
    forkBlockNumber?: number;
    chainId?: number;
    timeoutMs?: number;
    format?: string;
  };

  let scenarios: ValidationScenario[];

  if (body.plan && typeof body.plan === "object") {
    const planObj = body.plan as Record<string, unknown>;
    if (!Array.isArray(planObj["scenarios"])) {
      res.status(400).json({ error: '"plan.scenarios" must be an array.' });
      return;
    }
    scenarios = planObj["scenarios"] as ValidationScenario[];
  } else if (Array.isArray(body.scenarios)) {
    scenarios = body.scenarios as ValidationScenario[];
  } else {
    res.status(400).json({
      error: 'Request body must contain "plan" (ValidationPlan) or "scenarios" (ValidationScenario[]).',
    });
    return;
  }

  if (scenarios.length === 0) {
    res.status(200).json({
      report: {
        schemaVersion: VALIDATION_SCHEMA_VERSION,
        timestamp: new Date().toISOString(),
        total: 0, passed: 0, failed: 0, errored: 0,
        results: [],
        adapterType: parseAdapterType(body.adapterType),
        totalDurationMs: 0,
      },
    });
    return;
  }

  const { signal, cancel } = createCancellationSignal();
  req.on("close", () => cancel());

  const runOpts: RunValidationOptions = {
    adapterType: parseAdapterType(body.adapterType),
    forkUrl: body.forkUrl,
    forkBlockNumber: body.forkBlockNumber,
    chainId: body.chainId,
    limits: { timeoutMs: body.timeoutMs ?? 30_000 },
    signal,
    verbosity: 0,
  };

  try {
    const report = await runValidationPlan(scenarios, runOpts);
    if (body.format === "markdown") {
      res.status(200).type("text/markdown").send(generateValidationMarkdown(report));
    } else {
      res.status(200).json({ report });
    }
  } catch (err) {
    res.status(500).json({ error: safeErrorMessage(err) });
  }
});

// ─── POST /validate/report ────────────────────────────────────────────────────

/**
 * POST /validate/report
 *
 * Re-format a saved ValidationReport as JSON or Markdown.
 * Accepts the report as a JSON body — does not read from the filesystem.
 *
 * Request body:
 * ```json
 * { "report": ValidationReport, "format": "markdown" }
 * ```
 *
 * Response 200: formatted report
 * Response 400: corrupt or missing report
 */
router.post("/report", (req: Request, res: Response): void => {
  try {
    const body = req.body as { report?: unknown; format?: string };

    if (!body.report || typeof body.report !== "object") {
      res.status(400).json({
        error: 'Request body must contain "report" as a ValidationReport object.',
      });
      return;
    }

    let validated;
    try {
      validated = parseValidationReport(JSON.stringify(body.report), "<request-body>");
    } catch (parseErr) {
      res.status(400).json({ error: safeErrorMessage(parseErr) });
      return;
    }

    if (body.format === "markdown") {
      res.status(200).type("text/markdown").send(generateValidationMarkdown(validated));
    } else {
      res.status(200).type("application/json").send(serializeValidationReport(validated));
    }
  } catch (err) {
    res.status(500).json({ error: safeErrorMessage(err) });
  }
});

export default router;
