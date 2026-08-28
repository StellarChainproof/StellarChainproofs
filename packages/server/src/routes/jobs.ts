import { Router, Response } from "express";
import {
  AuditLogger,
  JobPriority,
  JobQueueManager,
  QueueWorker,
  SafeArchiveExtractor,
  StreamEvent,
  SubmitJobOptions,
} from "@chainproof/core";
import { AuthenticatedRequest, requireScope } from "../middleware/auth";

export interface JobsRouterOptions {
  queueManager: JobQueueManager;
  worker: QueueWorker;
  auditLogger?: AuditLogger;
}

export function createJobsRouter(options: JobsRouterOptions): Router {
  const router = Router();
  const { queueManager, worker, auditLogger } = options;

  router.post("/", requireScope("scan:create"), async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const principal = req.principal!;
    const body = req.body ?? {};

    let files = body.files ?? [];

    if (body.archiveBase64 && typeof body.archiveBase64 === "string") {
      try {
        const zipBuffer = Buffer.from(body.archiveBase64, "base64");
        const extractor = new SafeArchiveExtractor();
        const extracted = extractor.extractZipBuffer(zipBuffer);
        files = extracted.files;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        res.status(400).json({ error: `Archive extraction failed: ${msg}` });
        return;
      }
    }

    if (!Array.isArray(files) || files.length === 0) {
      res.status(400).json({
        error: "Missing required scan input: 'files' array or 'archiveBase64'",
      });
      return;
    }

    for (const f of files) {
      if (typeof f.path !== "string" || typeof f.content !== "string") {
        res.status(400).json({
          error: 'Each file entry must have string fields "path" and "content"',
        });
        return;
      }
    }

    const priority: JobPriority = typeof body.priority === "number" ? (body.priority as JobPriority) : 2;

    const submitOpts: SubmitJobOptions = {
      tenantId: principal.tenantId,
      projectId: body.projectId ?? principal.projectId,
      principalId: principal.id,
      priority,
      idempotencyKey: body.idempotencyKey ?? (req.headers["x-idempotency-key"] as string),
      files,
      config: body.config ?? {},
      timeoutMs: body.timeoutMs,
      maxRetries: body.maxRetries,
      tags: body.tags,
    };

    const { job, deduplicated } = queueManager.submitJob(submitOpts);

    if (auditLogger) {
      auditLogger.record({
        type: "job.submitted",
        tenantId: principal.tenantId,
        projectId: job.projectId,
        principalId: principal.id,
        action: "job.submit",
        status: "success",
        details: { jobId: job.id, fileCount: files.length, deduplicated },
      });
    }

    res.status(deduplicated ? 200 : 202).json({
      jobId: job.id,
      status: job.status,
      deduplicated,
      createdAt: job.createdAt,
      progress: job.progress,
      links: {
        self: `/jobs/${job.id}`,
        stream: `/jobs/${job.id}/stream`,
        cancel: `/jobs/${job.id}/cancel`,
      },
    });
  });

  router.get("/", requireScope("scan:read"), (req: AuthenticatedRequest, res: Response): void => {
    const principal = req.principal!;
    const { status, projectId, search, limit, offset } = req.query;

    const tenantId = principal.roles.includes("admin") && req.query.tenantId ? (req.query.tenantId as string) : principal.tenantId;

    const filterResult = queueManager.listJobs({
      tenantId,
      projectId: projectId as string,
      status: status as any,
      search: search as string,
      limit: limit ? parseInt(limit as string, 10) : 50,
      offset: offset ? parseInt(offset as string, 10) : 0,
    });

    res.json(filterResult);
  });

  router.get("/:id", requireScope("scan:read"), (req: AuthenticatedRequest, res: Response): void => {
    const principal = req.principal!;
    const jobId = req.params.id;

    const job = queueManager.getJob(jobId);
    if (!job) {
      res.status(404).json({ error: `Job not found: ${jobId}` });
      return;
    }

    if (!principal.roles.includes("admin") && job.tenantId !== principal.tenantId) {
      res.status(403).json({ error: "Access denied to job" });
      return;
    }

    res.json(job);
  });

  router.get("/:id/stream", requireScope("scan:read"), (req: AuthenticatedRequest, res: Response): void => {
    const principal = req.principal!;
    const jobId = req.params.id;

    const job = queueManager.getJob(jobId);
    if (!job) {
      res.status(404).json({ error: `Job not found: ${jobId}` });
      return;
    }

    if (!principal.roles.includes("admin") && job.tenantId !== principal.tenantId) {
      res.status(403).json({ error: "Access denied to job stream" });
      return;
    }

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    res.write(
      `data: ${JSON.stringify({
        type: "status",
        jobId: job.id,
        status: job.status,
        progress: job.progress,
        timestamp: Date.now(),
      })}\n\n`
    );

    if (job.status === "completed" || job.status === "failed" || job.status === "cancelled") {
      res.write(
        `data: ${JSON.stringify({
          type: "complete",
          jobId: job.id,
          status: job.status,
          progress: job.progress,
          data: job.result ?? { error: job.error },
          timestamp: Date.now(),
        })}\n\n`
      );
      res.end();
      return;
    }

    const unsubscribe = worker.subscribe(jobId, (event: StreamEvent) => {
      res.write(`data: ${JSON.stringify(event)}\n\n`);

      if (event.type === "complete" || event.type === "error") {
        unsubscribe();
        res.end();
      }
    });

    req.on("close", () => {
      unsubscribe();
    });
  });

  router.post("/:id/cancel", requireScope("scan:cancel"), (req: AuthenticatedRequest, res: Response): void => {
    const principal = req.principal!;
    const jobId = req.params.id;

    const tenantId = principal.roles.includes("admin") ? undefined : principal.tenantId;

    const { success, job, error } = queueManager.cancelJob(jobId, tenantId);

    if (!success) {
      res.status(400).json({ error: error ?? "Failed to cancel job" });
      return;
    }

    if (auditLogger) {
      auditLogger.record({
        type: "job.cancelled",
        tenantId: job!.tenantId,
        projectId: job!.projectId,
        principalId: principal.id,
        action: "job.cancel",
        status: "success",
        details: { jobId },
      });
    }

    res.json({ message: "Job cancellation requested", job });
  });

  router.delete("/:id", requireScope("scan:delete"), (req: AuthenticatedRequest, res: Response): void => {
    const principal = req.principal!;
    const jobId = req.params.id;

    const tenantId = principal.roles.includes("admin") ? undefined : principal.tenantId;

    const { success, error } = queueManager.deleteJob(jobId, tenantId);

    if (!success) {
      res.status(404).json({ error: error ?? "Job not found" });
      return;
    }

    if (auditLogger) {
      auditLogger.record({
        type: "job.deleted",
        tenantId: principal.tenantId,
        principalId: principal.id,
        action: "job.delete",
        status: "success",
        details: { jobId },
      });
    }

    res.json({ message: `Job ${jobId} deleted successfully` });
  });

  return router;
}
