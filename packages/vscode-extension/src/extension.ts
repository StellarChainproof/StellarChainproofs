import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import {
  scan,
  generateMarkdownReport,
  isSlitherAvailable,
  loadPlugins,
} from "@chainproof/core";
import type { Finding, GasHint, ScanConfig } from "@chainproof/core";

// ─── Severity → VS Code DiagnosticSeverity ───────────────────────────────────

function toVSCodeSeverity(
  severity: Finding["severity"],
): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
    case "info":
    case "gas":
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

// ─── Extension state ──────────────────────────────────────────────────────────

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;

// ─── Activation ───────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel("ChainProof");
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("chainproof");
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100,
  );
  statusBarItem.command = "chainproof.scanCurrentFile";
  statusBarItem.text = "$(shield) ChainProof";
  statusBarItem.tooltip = "Click to scan current Solidity file";
  statusBarItem.show();

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand("chainproof.scanCurrentFile", () =>
      scanCurrentFile(),
    ),
    vscode.commands.registerCommand("chainproof.scanWorkspace", () =>
      scanWorkspace(),
    ),
    vscode.commands.registerCommand("chainproof.generateReport", () =>
      generateReport(),
    ),
    vscode.commands.registerCommand("chainproof.clearDiagnostics", () => {
      diagnosticCollection.clear();
      statusBarItem.text = "$(shield) ChainProof";
      statusBarItem.backgroundColor = undefined;
    }),
    diagnosticCollection,
    statusBarItem,
    outputChannel,
  );

  // Auto-scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration("chainproof");
      if (config.get("enableOnSave") && doc.fileName.endsWith(".sol")) {
        scanDocument(doc);
      }
    }),
  );

  // Scan on open
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (doc.fileName.endsWith(".sol")) {
        scanDocument(doc);
      }
    }),
  );

  // Scan any already-open .sol files
  vscode.workspace.textDocuments
    .filter((d) => d.fileName.endsWith(".sol"))
    .forEach((d) => scanDocument(d));

  outputChannel.appendLine(
    "[ChainProof] Extension activated. Ready to scan Solidity files.",
  );
}

// ─── Scan a single TextDocument ───────────────────────────────────────────────

async function scanDocument(document: vscode.TextDocument) {
  const config = vscode.workspace.getConfiguration("chainproof");
  const apiKey =
    config.get<string>("apiKey") || process.env.ANTHROPIC_API_KEY || undefined;

  // Load plugins from settings
  const pluginSpecs = config.get<string[]>("plugins") || [];
  const plugins = loadPlugins(pluginSpecs);

  const scanConfig: ScanConfig = {
    targets: [document.fileName],
    useSlither: config.get("useSlither") ?? true,
    useLLM: (config.get("useLLM") ?? false) && !!apiKey,
    apiKey,
    minSeverity: config.get("minSeverity") ?? "low",
    plugins,
  };

  statusBarItem.text = "$(sync~spin) ChainProof scanning...";

  try {
    const result = await scan(scanConfig);
    const fileResult = result.files[0];
    if (!fileResult) return;

    const diagnostics: vscode.Diagnostic[] = [];

    // ── Vulnerability findings → diagnostics ─────────────────────────────────
    for (const finding of fileResult.findings) {
      const line = Math.max(0, finding.line - 1);
      const range = new vscode.Range(line, 0, line, 9999);
      const message = `[${finding.id}] ${finding.title}\n${finding.description}\n\nFix: ${finding.recommendation}`;

      const diag = new vscode.Diagnostic(
        range,
        message,
        toVSCodeSeverity(finding.severity),
      );
      diag.source = "ChainProof";
      diag.code = finding.swcId ?? finding.id;

      // Attach related info link for SWC entries
      if (finding.swcId) {
        diag.relatedInformation = [
          new vscode.DiagnosticRelatedInformation(
            new vscode.Location(document.uri, range),
            `SWC Registry: https://swcregistry.io/docs/${finding.swcId}`,
          ),
        ];
      }

      diagnostics.push(diag);
    }

    // ── Gas hints → informational diagnostics ─────────────────────────────────
    for (const hint of fileResult.gasHints) {
      const line = Math.max(0, hint.line - 1);
      const range = new vscode.Range(line, 0, line, 9999);
      const diag = new vscode.Diagnostic(
        range,
        `⛽ Gas: ${hint.description} (${hint.estimatedSaving})`,
        vscode.DiagnosticSeverity.Hint,
      );
      diag.source = "ChainProof";
      diag.code = "GAS";
      diagnostics.push(diag);
    }

    diagnosticCollection.set(document.uri, diagnostics);

    // Update status bar
    const { critical, high, total } = result.summary;
    if (critical > 0) {
      statusBarItem.text = `$(error) ChainProof: ${critical} critical`;
      statusBarItem.backgroundColor = new vscode.ThemeColor(
        "statusBarItem.errorBackground",
      );
    } else if (high > 0) {
      statusBarItem.text = `$(warning) ChainProof: ${high} high`;
      statusBarItem.backgroundColor = new vscode.ThemeColor(
        "statusBarItem.warningBackground",
      );
    } else if (total > 0) {
      statusBarItem.text = `$(info) ChainProof: ${total} hints`;
      statusBarItem.backgroundColor = undefined;
    } else {
      statusBarItem.text = "$(pass) ChainProof: clean";
      statusBarItem.backgroundColor = undefined;
    }

    outputChannel.appendLine(
      `[ChainProof] ${document.fileName}: ${total} findings (${critical} critical, ${high} high)`,
    );
  } catch (err) {
    statusBarItem.text = "$(error) ChainProof: error";
    outputChannel.appendLine(
      `[ChainProof] Error scanning ${document.fileName}: ${err}`,
    );
  }
}

// ─── Commands ─────────────────────────────────────────────────────────────────

async function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("ChainProof: No active editor");
    return;
  }
  if (!editor.document.fileName.endsWith(".sol")) {
    vscode.window.showWarningMessage(
      "ChainProof: Active file is not a Solidity file",
    );
    return;
  }
  await scanDocument(editor.document);
  vscode.window.showInformationMessage(
    "ChainProof: Scan complete — check Problems panel",
  );
}

async function scanWorkspace() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) {
    vscode.window.showWarningMessage("ChainProof: No workspace open");
    return;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "ChainProof: Scanning workspace...",
      cancellable: false,
    },
    async () => {
      const docs = vscode.workspace.textDocuments.filter((d) =>
        d.fileName.endsWith(".sol"),
      );
      await Promise.all(docs.map((d) => scanDocument(d)));
    },
  );

  vscode.window.showInformationMessage("ChainProof: Workspace scan complete");
}

async function generateReport() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) {
    vscode.window.showWarningMessage("ChainProof: No workspace open");
    return;
  }

  const workspacePath = folders[0].uri.fsPath;
  const config = vscode.workspace.getConfiguration("chainproof");
  const apiKey =
    config.get<string>("apiKey") || process.env.ANTHROPIC_API_KEY || undefined;

  // Load plugins from settings
  const pluginSpecs = config.get<string[]>("plugins") || [];
  const plugins = loadPlugins(pluginSpecs);

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "ChainProof: Generating audit report...",
      cancellable: false,
    },
    async () => {
      const scanConfig: ScanConfig = {
        targets: [workspacePath],
        useSlither: config.get("useSlither") ?? true,
        useLLM: (config.get("useLLM") ?? false) && !!apiKey,
        apiKey,
        minSeverity: "low",
        plugins,
      };

      const result = await scan(scanConfig);
      const report = generateMarkdownReport(result);
      const reportPath = path.join(workspacePath, "chainproof-audit-report.md");
      fs.writeFileSync(reportPath, report, "utf-8");

      const doc = await vscode.workspace.openTextDocument(reportPath);
      await vscode.window.showTextDocument(doc);
      vscode.window.showInformationMessage(
        `ChainProof: Report generated at chainproof-audit-report.md`,
      );
    },
  );
}

export function deactivate() {
  diagnosticCollection?.dispose();
  statusBarItem?.dispose();
  outputChannel?.dispose();
}
