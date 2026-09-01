import {
  CodeAction,
  CodeActionKind,
  Command,
  TextEdit,
  WorkspaceEdit,
  type CodeActionParams,
} from "vscode-languageserver";
import { DocumentStore } from "./document-store";
import type { ExtendedLspDiagnostic } from "./types";

/**
 * Provider for LSP CodeActions: deterministic remediations (QuickFixes),
 * inline suppression comment insertion, SWC documentation links, and evidence path navigation.
 */
export class ChainProofCodeActionProvider {
  private readonly documentStore: DocumentStore;

  constructor(documentStore: DocumentStore) {
    this.documentStore = documentStore;
  }

  public provideCodeActions(params: CodeActionParams): CodeAction[] {
    const actions: CodeAction[] = [];
    const overlay = this.documentStore.get(params.textDocument.uri);
    if (!overlay) return actions;

    const chainProofDiagnostics = params.context.diagnostics.filter(
      (d) => d.source === "ChainProof"
    ) as ExtendedLspDiagnostic[];

    for (const diag of chainProofDiagnostics) {
      const data = diag.data;

      // 1. Deterministic QuickFixes
      if (data?.findingId === "CP-115" || diag.code === "SWC-115" || diag.code === "CP-115") {
        const fixAction = this.createTxOriginQuickFix(overlay.uri, diag);
        if (fixAction) actions.push(fixAction);
      } else if (data?.findingId === "CP-104" || diag.code === "CP-104") {
        const fixAction = this.createUncheckedReturnQuickFix(overlay.uri, diag);
        if (fixAction) actions.push(fixAction);
      }

      // 2. Suppression CodeAction
      const findingOrRuleId = data?.findingId ?? (typeof diag.code === "string" ? diag.code : undefined);
      if (findingOrRuleId) {
        const suppressAction = this.createSuppressionAction(overlay.uri, diag, findingOrRuleId);
        if (suppressAction) actions.push(suppressAction);
      }

      // 3. Rule Documentation Link CodeAction
      if (data?.swcId) {
        actions.push({
          title: `Open SWC-${data.swcId} Documentation`,
          kind: CodeActionKind.Empty,
          command: Command.create(
            "Open Documentation",
            "vscode.open",
            `https://swcregistry.io/docs/${data.swcId}`
          ),
          diagnostics: [diag],
        });
      }

      // 4. Evidence Path Navigation CodeAction
      if (data?.evidencePath && data.evidencePath.length > 0) {
        actions.push({
          title: `Show Vulnerability Evidence Trail (${data.evidencePath.length} steps)`,
          kind: CodeActionKind.Empty,
          command: Command.create(
            "Show Evidence Trail",
            "chainproof.showEvidenceTrail",
            overlay.uri,
            data.evidencePath
          ),
          diagnostics: [diag],
        });
      }
    }

    return actions;
  }

  private createTxOriginQuickFix(uri: string, diag: ExtendedLspDiagnostic): CodeAction | null {
    const overlay = this.documentStore.get(uri);
    if (!overlay) return null;

    const line = diag.range.start.line;
    const lineText = overlay.textDocument.getText({
      start: { line, character: 0 },
      end: { line: line + 1, character: 0 },
    });

    if (!lineText.includes("tx.origin")) return null;

    const newText = lineText.replace(/\btx\.origin\b/g, "msg.sender");
    const edit: WorkspaceEdit = {
      changes: {
        [uri]: [
          TextEdit.replace(
            {
              start: { line, character: 0 },
              end: { line, character: lineText.length },
            },
            newText
          ),
        ],
      },
    };

    return {
      title: "Replace tx.origin with msg.sender (ChainProof QuickFix)",
      kind: CodeActionKind.QuickFix,
      isPreferred: true,
      edit,
      diagnostics: [diag],
    };
  }

  private createUncheckedReturnQuickFix(uri: string, diag: ExtendedLspDiagnostic): CodeAction | null {
    const overlay = this.documentStore.get(uri);
    if (!overlay) return null;

    const line = diag.range.start.line;
    const lineText = overlay.textDocument.getText({
      start: { line, character: 0 },
      end: { line: line + 1, character: 0 },
    });

    const trimmed = lineText.trim();
    const indent = lineText.substring(0, lineText.indexOf(trimmed));
    let newText: string;

    if (trimmed.endsWith(";")) {
      const stmt = trimmed.slice(0, -1).trim();
      newText = `${indent}(bool success, ) = ${stmt};\n${indent}require(success, "External call failed");\n`;
    } else {
      newText = `${indent}(bool success, ) = ${trimmed};\n${indent}require(success, "External call failed");\n`;
    }

    const edit: WorkspaceEdit = {
      changes: {
        [uri]: [
          TextEdit.replace(
            {
              start: { line, character: 0 },
              end: { line, character: lineText.length },
            },
            newText
          ),
        ],
      },
    };

    return {
      title: "Check call return value with require(success) (ChainProof QuickFix)",
      kind: CodeActionKind.QuickFix,
      isPreferred: true,
      edit,
      diagnostics: [diag],
    };
  }

  private createSuppressionAction(
    uri: string,
    diag: ExtendedLspDiagnostic,
    ruleId: string
  ): CodeAction | null {
    const overlay = this.documentStore.get(uri);
    if (!overlay) return null;

    const line = diag.range.start.line;
    const lineText = overlay.textDocument.getText({
      start: { line, character: 0 },
      end: { line: line + 1, character: 0 },
    });

    const trimmed = lineText.trim();
    const indent = lineText.substring(0, lineText.indexOf(trimmed));
    const suppressionComment = `${indent}// chainproof-disable-next-line ${ruleId}\n`;

    const edit: WorkspaceEdit = {
      changes: {
        [uri]: [
          TextEdit.insert({ line, character: 0 }, suppressionComment),
        ],
      },
    };

    return {
      title: `Suppress finding ${ruleId} with inline comment (ChainProof)`,
      kind: CodeActionKind.QuickFix,
      edit,
      diagnostics: [diag],
    };
  }
}
