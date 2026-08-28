import {
  createConnection,
  ProposedFeatures,
  TextDocumentSyncKind,
  type Connection,
  type InitializeParams,
  type InitializeResult,
  type ServerCapabilities,
  type DidOpenTextDocumentParams,
  type DidChangeTextDocumentParams,
  type DidCloseTextDocumentParams,
  type DidSaveTextDocumentParams,
} from "vscode-languageserver/node";
import type { CancellationToken } from "vscode-languageserver";

import { DocumentStore } from "./document-store";
import { AnalysisService } from "./analysis-service";
import { LspTransportListener } from "./transports";
import { ChainProofCodeActionProvider } from "./code-actions";
import { ChainProofProviders } from "./providers";
import { clearCache, getCacheStats } from "../ast/cache";
import { generateThreatModel, generateMarkdownThreatModel, generateJSONThreatModel } from "../threat-model";
import { generateMarkdownReport, generateJSONReport, generateTableReport } from "../report/generator";
import { scan as runScan } from "../scanner";
import type { ScanConfig } from "../types";

import {
  ChainProofLspMethods,
  type LspDaemonOptions,
  type LspStatus,
  type ThreatModelRequestParams,
  type ScanReportRequestParams,
  type ScanReportResponse,
  type ClearCacheResponse,
  type ExtendedLspDiagnostic,
} from "./types";

export class ChainProofLspServer {
  private readonly documentStore: DocumentStore;
  private readonly analysisService: AnalysisService;
  private readonly codeActionProvider: ChainProofCodeActionProvider;
  private readonly providers: ChainProofProviders;
  private readonly transportListener: LspTransportListener;
  private readonly options: LspDaemonOptions;

  private connection: Connection | undefined;
  private workspaceFolders: string[] = [];
  private startTime = Date.now();

  constructor(options: LspDaemonOptions = {}) {
    this.options = options;
    this.documentStore = new DocumentStore();
    this.analysisService = new AnalysisService(this.documentStore, options);
    this.codeActionProvider = new ChainProofCodeActionProvider(this.documentStore);
    this.providers = new ChainProofProviders(this.documentStore);
    this.transportListener = new LspTransportListener(options);

    // Wire up diagnostic publishing callback
    this.analysisService.onPublishDiagnostics = (uri, diagnostics) => {
      this.providers.setDiagnostics(uri, diagnostics);
      if (this.connection) {
        this.connection.sendDiagnostics({ uri, diagnostics });
      }
    };
  }

  /**
   * Start the LSP daemon server listening on configured transport.
   */
  public start(): void {
    this.transportListener.listen((transportConn) => {
      const conn = createConnection(ProposedFeatures.all, transportConn.reader, transportConn.writer);
      this.connection = conn;
      this.bindConnectionHandlers(conn);
      conn.listen();
    });
  }

  /** Stop the server and release resources */
  public stop(): void {
    this.transportListener.close();
    if (this.connection) {
      this.connection.dispose();
      this.connection = undefined;
    }
  }

  private bindConnectionHandlers(connection: Connection): void {
    // ── 1. Lifecycle Handlers ──────────────────────────────────────────────────
    connection.onInitialize((params: InitializeParams): InitializeResult => {
      this.workspaceFolders = [];
      if (params.workspaceFolders) {
        this.workspaceFolders = params.workspaceFolders.map((wf) => DocumentStore.uriToFilePath(wf.uri));
      } else if (params.rootUri) {
        this.workspaceFolders = [DocumentStore.uriToFilePath(params.rootUri)];
      } else if (params.rootPath) {
        this.workspaceFolders = [params.rootPath];
      }

      const capabilities: ServerCapabilities = {
        textDocumentSync: TextDocumentSyncKind.Full,
        codeActionProvider: {
          codeActionKinds: ["quickfix", "refactor"],
        },
        hoverProvider: true,
        documentSymbolProvider: true,
        callHierarchyProvider: true,
        referencesProvider: true,
        workspace: {
          workspaceFolders: {
            supported: true,
            changeNotifications: true,
          },
        },
      };

      return { capabilities };
    });

    connection.onInitialized(() => {
      this.options.logger?.("info", "ChainProof LSP Daemon initialized.");
    });

    connection.onShutdown(() => {
      this.options.logger?.("info", "ChainProof LSP Daemon shutting down.");
      this.analysisService.resetWatchState();
    });

    connection.onExit(() => {
      this.stop();
    });

    // Workspace folder updates
    connection.workspace.onDidChangeWorkspaceFolders((event) => {
      for (const removed of event.removed) {
        const pathRemoved = DocumentStore.uriToFilePath(removed.uri);
        this.workspaceFolders = this.workspaceFolders.filter((f) => f !== pathRemoved);
      }
      for (const added of event.added) {
        const pathAdded = DocumentStore.uriToFilePath(added.uri);
        if (!this.workspaceFolders.includes(pathAdded)) {
          this.workspaceFolders.push(pathAdded);
        }
      }
      this.analysisService.resetWatchState();
    });

    // ── 2. Document Synchronization Handlers ────────────────────────────────
    connection.onDidOpenTextDocument((params: DidOpenTextDocumentParams) => {
      const { uri, version, text, languageId } = params.textDocument;
      this.documentStore.openOrUpdate(uri, version, text, languageId);
      this.analysisService.scheduleAnalysis(uri, this.workspaceFolders).catch(() => {});
    });

    connection.onDidChangeTextDocument((params: DidChangeTextDocumentParams) => {
      const { uri, version } = params.textDocument;
      const change = params.contentChanges[0];
      if (change && "text" in change) {
        this.documentStore.openOrUpdate(uri, version, change.text);
        this.analysisService.scheduleAnalysis(uri, this.workspaceFolders).catch(() => {});
      }
    });

    connection.onDidSaveTextDocument((params: DidSaveTextDocumentParams) => {
      const { uri } = params.textDocument;
      if (params.text) {
        const overlay = this.documentStore.get(uri);
        const version = overlay ? overlay.version : 0;
        this.documentStore.openOrUpdate(uri, version, params.text);
      }
      this.analysisService.scheduleAnalysis(uri, this.workspaceFolders).catch(() => {});
    });

    connection.onDidCloseTextDocument((params: DidCloseTextDocumentParams) => {
      this.documentStore.close(params.textDocument.uri);
    });

    // ── 3. Language Intelligence Handlers ─────────────────────────────────────
    connection.onCodeAction((params) => this.codeActionProvider.provideCodeActions(params));
    connection.onHover((params) => this.providers.provideHover(params));
    connection.onDocumentSymbol((params) => this.providers.provideDocumentSymbols(params));
    connection.languages.callHierarchy.onPrepare((params) => this.providers.prepareCallHierarchy(params));
    connection.languages.callHierarchy.onIncomingCalls((params) => this.providers.provideIncomingCalls(params));
    connection.languages.callHierarchy.onOutgoingCalls((params) => this.providers.provideOutgoingCalls(params));
    connection.onReferences((params) => this.providers.provideReferences(params));

    // ── 4. Custom Request Handlers ───────────────────────────────────────────

    // chainproof/threatModel
    connection.onRequest(
      ChainProofLspMethods.ThreatModel,
      async (params: ThreatModelRequestParams, cancelToken: CancellationToken) => {
        let targets: string[] = [];
        if (params.uri) {
          targets = [DocumentStore.uriToFilePath(params.uri)];
        } else if (params.workspacePath) {
          targets = [params.workspacePath];
        } else if (this.workspaceFolders.length > 0) {
          targets = this.workspaceFolders;
        } else {
          throw new Error("No target URI or workspace specified for threat model generation");
        }

        const model = await generateThreatModel({
          targets,
          assumptionsPath: params.assumptionsPath,
          minSeverity: params.minSeverity ?? "low",
        });

        if (cancelToken.isCancellationRequested) {
          throw new Error("Request cancelled");
        }

        return {
          threatModel: model,
          markdown: generateMarkdownThreatModel(model),
          json: generateJSONThreatModel(model),
        };
      }
    );

    // chainproof/scanReport
    connection.onRequest(
      ChainProofLspMethods.ScanReport,
      async (params: ScanReportRequestParams, cancelToken: CancellationToken): Promise<ScanReportResponse> => {
        let targets: string[] = [];
        if (params.uri) {
          targets = [DocumentStore.uriToFilePath(params.uri)];
        } else if (params.workspacePath) {
          targets = [params.workspacePath];
        } else if (this.workspaceFolders.length > 0) {
          targets = this.workspaceFolders;
        } else {
          throw new Error("No target URI or workspace specified for scan report generation");
        }

        const config: ScanConfig = {
          targets,
          useSlither: this.options.scanConfig?.useSlither ?? false,
          useLLM: this.options.scanConfig?.useLLM ?? false,
          useMetrics: this.options.scanConfig?.useMetrics ?? true,
          minSeverity: params.minSeverity ?? "low",
        };

        const scanResult = await runScan(config);

        if (cancelToken.isCancellationRequested) {
          throw new Error("Request cancelled");
        }

        const format = params.format ?? "markdown";
        let content: string;
        if (format === "json") {
          content = generateJSONReport(scanResult);
        } else if (format === "table") {
          content = generateTableReport(scanResult);
        } else {
          content = generateMarkdownReport(scanResult);
        }

        return {
          format,
          content,
          summary: scanResult.summary,
        };
      }
    );

    // chainproof/clearCache
    connection.onRequest(ChainProofLspMethods.ClearCache, (): ClearCacheResponse => {
      clearCache();
      this.analysisService.resetWatchState();
      return {
        cleared: true,
        message: "AST cache and watch state cleared successfully.",
      };
    });

    // chainproof/status
    connection.onRequest(ChainProofLspMethods.Status, (): LspStatus => {
      const stats = getCacheStats();
      return {
        openDocumentsCount: this.documentStore.size,
        queueDepth: this.analysisService.queueDepth,
        activeAnalyses: this.analysisService.activeAnalyses,
        cacheStats: {
          hits: stats.hits,
          misses: stats.misses,
          entries: stats.hits + stats.misses,
        },
        uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
        workspaceFolders: this.workspaceFolders,
      };
    });
  }
}

/** Utility function to start LSP Daemon server instance */
export function startLspDaemon(options: LspDaemonOptions = {}): ChainProofLspServer {
  const server = new ChainProofLspServer(options);
  server.start();
  return server;
}
