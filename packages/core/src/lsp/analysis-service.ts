import { DiagnosticSeverity, type Diagnostic as LspDiagnostic, type ProgressToken } from "vscode-languageserver";
import type { CancellationToken } from "vscode-languageserver";
import * as path from "path";
import * as fs from "fs";
import { scan, scanIncremental, collectSolFiles, type WatchScanState } from "../scanner";
import { DocumentStore, type OverlayDocument } from "./document-store";
import { getCacheStats, ASTCache } from "../ast/cache";
import type { ScanConfig, ScanResult, Finding, GasHint, FileScanResult } from "../types";
import type { ExtendedLspDiagnostic, DiagnosticData, LspDaemonOptions } from "./types";

export interface AnalysisJob {
  id: string;
  uri: string;
  filePath: string;
  version: number;
  workspaceFolders: string[];
  cancellationToken?: CancellationToken;
  progressToken?: ProgressToken;
  resolve: (diagnostics: Map<string, ExtendedLspDiagnostic[]>) => void;
  reject: (err: Error) => void;
}

export type PublishDiagnosticsCallback = (
  uri: string,
  diagnostics: ExtendedLspDiagnostic[],
  version?: number
) => void;

export type WorkDoneProgressCallback = (
  token: ProgressToken,
  action: "begin" | "report" | "end",
  value: { title?: string; percentage?: number; message?: string }
) => void;

/**
 * Background analysis service orchestrating cancellable incremental scans,
 * bounded queue management, diagnostic mapping, and progress reporting.
 */
export class AnalysisService {
  private readonly documentStore: DocumentStore;
  private readonly options: LspDaemonOptions;
  private readonly queue: AnalysisJob[] = [];
  private activeJobsCount = 0;
  private watchState: WatchScanState | undefined;
  private pendingDebounceTimers = new Map<string, NodeJS.Timeout>();
  private activeCancellations = new Map<string, CancellationToken>();
  private latestPublishedVersions = new Map<string, number>();

  public onPublishDiagnostics?: PublishDiagnosticsCallback;
  public onWorkDoneProgress?: WorkDoneProgressCallback;

  constructor(documentStore: DocumentStore, options: LspDaemonOptions = {}) {
    this.documentStore = documentStore;
    this.options = {
      maxQueueDepth: 50,
      maxConcurrent: 2,
      debounceMs: 150,
      ...options,
    };
  }

  public get queueDepth(): number {
    return this.queue.length;
  }

  public get activeAnalyses(): number {
    return this.activeJobsCount;
  }

  /** Convert ChainProof Finding severity to LSP DiagnosticSeverity */
  public static toLspSeverity(severity: Finding["severity"]): DiagnosticSeverity {
    switch (severity) {
      case "critical":
      case "high":
        return DiagnosticSeverity.Error;
      case "medium":
        return DiagnosticSeverity.Warning;
      case "low":
        return DiagnosticSeverity.Information;
      case "info":
      case "gas":
      default:
        return DiagnosticSeverity.Hint;
    }
  }

  /** Schedule a document for analysis with debouncing and cancellation */
  public scheduleAnalysis(
    uri: string,
    workspaceFolders: string[],
    cancellationToken?: CancellationToken,
    progressToken?: ProgressToken
  ): Promise<Map<string, ExtendedLspDiagnostic[]>> {
    // Cancel any existing debounce timer for this URI
    const existingTimer = this.pendingDebounceTimers.get(uri);
    if (existingTimer) {
      clearTimeout(existingTimer);
      this.pendingDebounceTimers.delete(uri);
    }

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingDebounceTimers.delete(uri);

        const overlay = this.documentStore.get(uri);
        const version = overlay ? overlay.version : 0;
        const filePath = DocumentStore.uriToFilePath(uri);

        // Shed oldest request if queue depth exceeded
        if (this.queue.length >= (this.options.maxQueueDepth ?? 50)) {
          const dropped = this.queue.shift();
          if (dropped) {
            dropped.reject(new Error("Analysis queue capacity exceeded (load shedding)"));
          }
        }

        const job: AnalysisJob = {
          id: `${uri}:${version}:${Date.now()}`,
          uri,
          filePath,
          version,
          workspaceFolders,
          cancellationToken,
          progressToken,
          resolve,
          reject,
        };

        this.queue.push(job);
        this.processQueue();
      }, this.options.debounceMs ?? 150);

      this.pendingDebounceTimers.set(uri, timer);
    });
  }

  private async processQueue(): Promise<void> {
    const maxConcurrent = this.options.maxConcurrent ?? 2;
    if (this.activeJobsCount >= maxConcurrent || this.queue.length === 0) {
      return;
    }

    const job = this.queue.shift();
    if (!job) return;

    this.activeJobsCount++;

    try {
      if (job.cancellationToken) {
        this.activeCancellations.set(job.uri, job.cancellationToken);
      }

      if (job.progressToken && this.onWorkDoneProgress) {
        this.onWorkDoneProgress(job.progressToken, "begin", {
          title: "ChainProof Security Scan",
          percentage: 0,
          message: `Analyzing ${path.basename(job.filePath)}...`,
        });
      }

      const diagnosticsMap = await this.runAnalysisJob(job);
      job.resolve(diagnosticsMap);

      if (job.progressToken && this.onWorkDoneProgress) {
        this.onWorkDoneProgress(job.progressToken, "end", {
          message: "Scan complete",
        });
      }
    } catch (err) {
      if (job.progressToken && this.onWorkDoneProgress) {
        this.onWorkDoneProgress(job.progressToken, "end", {
          message: "Scan cancelled or failed",
        });
      }
      job.reject(err instanceof Error ? err : new Error(String(err)));
    } finally {
      this.activeCancellations.delete(job.uri);
      this.activeJobsCount--;
      this.processQueue();
    }
  }

  private async runAnalysisJob(
    job: AnalysisJob
  ): Promise<Map<string, ExtendedLspDiagnostic[]>> {
    const targets = this.determineScanTargets(job);
    const config: ScanConfig = {
      targets,
      useSlither: this.options.scanConfig?.useSlither ?? false,
      useLLM: this.options.scanConfig?.useLLM ?? false,
      useMetrics: this.options.scanConfig?.useMetrics ?? true,
      minSeverity: this.options.scanConfig?.minSeverity ?? "info",
      apiKey: this.options.scanConfig?.apiKey,
      plugins: this.options.scanConfig?.plugins,
    };

    let scanResult: ScanResult;

    if (!this.watchState || this.watchState.allFiles.length === 0) {
      if (job.cancellationToken?.isCancellationRequested) {
        throw new Error("Analysis cancelled");
      }
      scanResult = await scan(config);
      this.watchState = {
        allFiles: collectSolFiles(targets),
        result: scanResult,
      };
    } else {
      if (job.cancellationToken?.isCancellationRequested) {
        throw new Error("Analysis cancelled");
      }
      const outcome = await scanIncremental(config, this.watchState, [job.filePath]);
      this.watchState = outcome.state;
      scanResult = outcome.state.result;
    }

    if (job.cancellationToken?.isCancellationRequested) {
      throw new Error("Analysis cancelled");
    }

    const diagnosticsMap = this.mapScanResultToDiagnostics(scanResult);

    // Publish diagnostics to listeners
    if (this.onPublishDiagnostics) {
      for (const [uri, diagnostics] of diagnosticsMap.entries()) {
        const overlay = this.documentStore.get(uri);
        const version = overlay ? overlay.version : undefined;

        // Guard against publishing stale diagnostics if document was updated since scan started
        const latestPublished = this.latestPublishedVersions.get(uri);
        if (version !== undefined && latestPublished !== undefined && version < latestPublished) {
          continue;
        }

        if (version !== undefined) {
          this.latestPublishedVersions.set(uri, version);
        }

        this.onPublishDiagnostics(uri, diagnostics, version);
      }
    }

    return diagnosticsMap;
  }

  private determineScanTargets(job: AnalysisJob): string[] {
    if (job.workspaceFolders.length > 0) {
      return job.workspaceFolders;
    }
    const dir = path.dirname(job.filePath);
    return fs.existsSync(dir) ? [dir] : [job.filePath];
  }

  private mapScanResultToDiagnostics(
    scanResult: ScanResult
  ): Map<string, ExtendedLspDiagnostic[]> {
    const map = new Map<string, ExtendedLspDiagnostic[]>();

    for (const fileResult of scanResult.files) {
      const uri = DocumentStore.filePathToUri(fileResult.file);
      const overlay = this.documentStore.get(uri);
      const diagnostics: ExtendedLspDiagnostic[] = [];

      // Vulnerability findings
      for (const finding of fileResult.findings) {
        const range = overlay
          ? DocumentStore.lineToRange(overlay.textDocument, finding.line)
          : {
              start: { line: Math.max(0, finding.line - 1), character: 0 },
              end: { line: Math.max(0, finding.line - 1), character: 999 },
            };

        const evidenceItems = finding.evidence
          ? finding.evidence.map((e) => ({
              file: finding.file,
              line: e.line ?? finding.line,
              description: e.description,
            }))
          : undefined;

        const data: DiagnosticData = {
          findingId: finding.id,
          swcId: finding.swcId,
          recommendation: finding.recommendation,
          evidencePath: evidenceItems,
          confidence: finding.confidence,
          assumptions: finding.assumptions,
          isGasHint: false,
        };

        const diag: ExtendedLspDiagnostic = {
          range,
          severity: AnalysisService.toLspSeverity(finding.severity),
          code: finding.swcId ?? finding.id,
          source: "ChainProof",
          message: `[${finding.id}] ${finding.title}\n${finding.description}\n\nFix: ${finding.recommendation}`,
          data,
        };

        if (finding.swcId) {
          diag.relatedInformation = [
            {
              location: {
                uri,
                range,
              },
              message: `SWC Registry Entry: https://swcregistry.io/docs/${finding.swcId}`,
            },
          ];
        }

        diagnostics.push(diag);
      }

      // Gas hints
      for (const hint of fileResult.gasHints) {
        const range = overlay
          ? DocumentStore.lineToRange(overlay.textDocument, hint.line)
          : {
              start: { line: Math.max(0, hint.line - 1), character: 0 },
              end: { line: Math.max(0, hint.line - 1), character: 999 },
            };

        const data: DiagnosticData = {
          ruleId: "GAS",
          recommendation: hint.description,
          isGasHint: true,
        };

        diagnostics.push({
          range,
          severity: DiagnosticSeverity.Hint,
          code: "GAS",
          source: "ChainProof",
          message: `⛽ Gas Optimization: ${hint.description} (${hint.estimatedSaving})`,
          data,
        });
      }

      map.set(uri, diagnostics);
    }

    return map;
  }

  /** Reset internal watch state cache */
  public resetWatchState(): void {
    this.watchState = undefined;
    this.latestPublishedVersions.clear();
  }
}
