import {
  Hover,
  DocumentSymbol,
  SymbolKind,
  CallHierarchyItem,
  CallHierarchyIncomingCall,
  CallHierarchyOutgoingCall,
  Location,
  MarkupKind,
  type HoverParams,
  type DocumentSymbolParams,
  type CallHierarchyPrepareParams,
  type CallHierarchyIncomingCallsParams,
  type CallHierarchyOutgoingCallsParams,
  type ReferenceParams,
} from "vscode-languageserver";
import { DocumentStore } from "./document-store";
import { visit } from "../ast/parser";
import type { ASTNode } from "../types";
import type { ExtendedLspDiagnostic } from "./types";

/**
 * Providers for language intelligence features:
 * Hover cards, Document Symbols, Call Hierarchy, and References.
 */
export class ChainProofProviders {
  private readonly documentStore: DocumentStore;
  private readonly currentDiagnostics = new Map<string, ExtendedLspDiagnostic[]>();

  constructor(documentStore: DocumentStore) {
    this.documentStore = documentStore;
  }

  public setDiagnostics(uri: string, diagnostics: ExtendedLspDiagnostic[]): void {
    this.currentDiagnostics.set(uri, diagnostics);
  }

  // ── 1. Hover Provider ────────────────────────────────────────────────────────

  public provideHover(params: HoverParams): Hover | null {
    const overlay = this.documentStore.get(params.textDocument.uri);
    if (!overlay) return null;

    const line = params.position.line;
    const diagnostics = this.currentDiagnostics.get(params.textDocument.uri) ?? [];
    const lineDiagnostics = diagnostics.filter(
      (d) => d.range.start.line <= line && line <= d.range.end.line
    );

    if (lineDiagnostics.length > 0) {
      const markdownContents = lineDiagnostics.map((d) => {
        const data = d.data;
        const confidenceBadge = data?.confidence ? ` **[Confidence: ${data.confidence}]**` : "";
        const swcLink = data?.swcId ? `\n\n[SWC-${data.swcId} Reference](https://swcregistry.io/docs/${data.swcId})` : "";
        const rec = data?.recommendation ? `\n\n**Recommendation:**\n${data.recommendation}` : "";

        return `### 🛡️ ChainProof Security Finding (${d.code || "CP"}) ${confidenceBadge}\n\n${d.message}${rec}${swcLink}`;
      });

      return {
        contents: {
          kind: MarkupKind.Markdown,
          value: markdownContents.join("\n\n---\n\n"),
        },
      };
    }

    return null;
  }

  // ── 2. Document Symbols Provider ─────────────────────────────────────────────

  public provideDocumentSymbols(params: DocumentSymbolParams): DocumentSymbol[] {
    const overlay = this.documentStore.get(params.textDocument.uri);
    if (!overlay || !overlay.ast) return [];

    const symbols: DocumentSymbol[] = [];

    visit(overlay.ast, {
      ContractDefinition(node: ASTNode) {
        const contract = node as {
          name?: string;
          kind?: string;
          loc?: { start: { line: number; column: number }; end: { line: number; column: number } };
        };
        if (!contract.name || !contract.loc) return;

        const range = {
          start: DocumentStore.toPosition(contract.loc.start.line, contract.loc.start.column),
          end: DocumentStore.toPosition(contract.loc.end.line, contract.loc.end.column),
        };

        const children: DocumentSymbol[] = [];
        visit(node, {
          FunctionDefinition(fnNode: ASTNode) {
            const fn = fnNode as {
              name?: string;
              visibility?: string;
              isConstructor?: boolean;
              loc?: { start: { line: number; column: number }; end: { line: number; column: number } };
            };
            if (!fn.loc) return;
            const fnName = fn.isConstructor ? "constructor" : fn.name || "fallback";

            children.push({
              name: fnName,
              detail: fn.visibility || "public",
              kind: SymbolKind.Function,
              range: {
                start: DocumentStore.toPosition(fn.loc.start.line, fn.loc.start.column),
                end: DocumentStore.toPosition(fn.loc.end.line, fn.loc.end.column),
              },
              selectionRange: {
                start: DocumentStore.toPosition(fn.loc.start.line, fn.loc.start.column),
                end: DocumentStore.toPosition(fn.loc.start.line, fn.loc.start.column + fnName.length),
              },
            });
          },
          StateVariableDeclaration(varNode: ASTNode) {
            const decl = varNode as {
              variables?: Array<{
                name?: string;
                typeName?: { name?: string };
                loc?: { start: { line: number; column: number }; end: { line: number; column: number } };
              }>;
            };
            for (const v of decl.variables ?? []) {
              if (!v.name || !v.loc) continue;
              children.push({
                name: v.name,
                detail: v.typeName?.name || "var",
                kind: SymbolKind.Variable,
                range: {
                  start: DocumentStore.toPosition(v.loc.start.line, v.loc.start.column),
                  end: DocumentStore.toPosition(v.loc.end.line, v.loc.end.column),
                },
                selectionRange: {
                  start: DocumentStore.toPosition(v.loc.start.line, v.loc.start.column),
                  end: DocumentStore.toPosition(v.loc.start.line, v.loc.start.column + v.name.length),
                },
              });
            }
          },
          EventDefinition(evtNode: ASTNode) {
            const evt = evtNode as {
              name?: string;
              loc?: { start: { line: number; column: number }; end: { line: number; column: number } };
            };
            if (!evt.name || !evt.loc) return;
            children.push({
              name: evt.name,
              kind: SymbolKind.Event,
              range: {
                start: DocumentStore.toPosition(evt.loc.start.line, evt.loc.start.column),
                end: DocumentStore.toPosition(evt.loc.end.line, evt.loc.end.column),
              },
              selectionRange: {
                start: DocumentStore.toPosition(evt.loc.start.line, evt.loc.start.column),
                end: DocumentStore.toPosition(evt.loc.start.line, evt.loc.start.column + evt.name.length),
              },
            });
          },
        });

        symbols.push({
          name: contract.name,
          detail: contract.kind || "contract",
          kind: contract.kind === "interface" ? SymbolKind.Interface : SymbolKind.Class,
          range,
          selectionRange: {
            start: range.start,
            end: { line: range.start.line, character: range.start.character + contract.name.length },
          },
          children,
        });
      },
    });

    return symbols;
  }

  // ── 3. Call Hierarchy Provider ───────────────────────────────────────────────

  public prepareCallHierarchy(params: CallHierarchyPrepareParams): CallHierarchyItem[] | null {
    const overlay = this.documentStore.get(params.textDocument.uri);
    if (!overlay || !overlay.ast) return null;

    const targetLine = params.position.line + 1;
    let targetFnName: string | null = null;
    let targetFnLoc: { start: { line: number; column: number }; end: { line: number; column: number } } | null = null;

    visit(overlay.ast, {
      FunctionDefinition(node: ASTNode) {
        const fn = node as {
          name?: string;
          loc?: { start: { line: number; column: number }; end: { line: number; column: number } };
        };
        if (fn.loc && fn.loc.start.line <= targetLine && targetLine <= fn.loc.end.line) {
          targetFnName = fn.name || "anonymous";
          targetFnLoc = fn.loc;
        }
      },
    });

    if (!targetFnName || !targetFnLoc) return null;

    const loc = targetFnLoc as { start: { line: number; column: number }; end: { line: number; column: number } };
    const fnRange = {
      start: DocumentStore.toPosition(loc.start.line, loc.start.column),
      end: DocumentStore.toPosition(loc.end.line, loc.end.column),
    };

    return [
      {
        name: targetFnName,
        kind: SymbolKind.Function,
        uri: params.textDocument.uri,
        range: fnRange,
        selectionRange: fnRange,
      },
    ];
  }

  public provideIncomingCalls(params: CallHierarchyIncomingCallsParams): CallHierarchyIncomingCall[] {
    const incoming: CallHierarchyIncomingCall[] = [];
    const targetItem = params.item;
    const allDocs = this.documentStore.getAll();

    for (const doc of allDocs) {
      if (!doc.ast) continue;

      visit(doc.ast, {
        FunctionCall(node: ASTNode) {
          const call = node as {
            expression?: { name?: string; memberName?: string };
            loc?: { start: { line: number; column: number }; end: { line: number; column: number } };
          };
          const calledName = call.expression?.name || call.expression?.memberName;

          if (calledName === targetItem.name && call.loc) {
            const callRange = {
              start: DocumentStore.toPosition(call.loc.start.line, call.loc.start.column),
              end: DocumentStore.toPosition(call.loc.end.line, call.loc.end.column),
            };

            incoming.push({
              from: {
                name: "caller",
                kind: SymbolKind.Function,
                uri: doc.uri,
                range: callRange,
                selectionRange: callRange,
              },
              fromRanges: [callRange],
            });
          }
        },
      });
    }

    return incoming;
  }

  public provideOutgoingCalls(params: CallHierarchyOutgoingCallsParams): CallHierarchyOutgoingCall[] {
    const outgoing: CallHierarchyOutgoingCall[] = [];
    const targetItem = params.item;
    const overlay = this.documentStore.get(targetItem.uri);
    if (!overlay || !overlay.ast) return outgoing;

    visit(overlay.ast, {
      FunctionCall(node: ASTNode) {
        const call = node as {
          expression?: { name?: string; memberName?: string };
          loc?: { start: { line: number; column: number }; end: { line: number; column: number } };
        };
        const calledName = call.expression?.name || call.expression?.memberName;

        if (calledName && call.loc) {
          const callRange = {
            start: DocumentStore.toPosition(call.loc.start.line, call.loc.start.column),
            end: DocumentStore.toPosition(call.loc.end.line, call.loc.end.column),
          };

          outgoing.push({
            to: {
              name: calledName,
              kind: SymbolKind.Function,
              uri: targetItem.uri,
              range: callRange,
              selectionRange: callRange,
            },
            fromRanges: [callRange],
          });
        }
      },
    });

    return outgoing;
  }

  // ── 4. References Provider ───────────────────────────────────────────────────

  public provideReferences(params: ReferenceParams): Location[] {
    const locations: Location[] = [];
    const overlay = this.documentStore.get(params.textDocument.uri);
    if (!overlay) return locations;

    const line = params.position.line;
    const diagnostics = this.currentDiagnostics.get(params.textDocument.uri) ?? [];
    const lineDiagnostics = diagnostics.filter(
      (d) => d.range.start.line <= line && line <= d.range.end.line
    );

    for (const d of lineDiagnostics) {
      if (d.data?.evidencePath) {
        for (const item of d.data.evidencePath) {
          const itemUri = DocumentStore.filePathToUri(item.file);
          const targetOverlay = this.documentStore.get(itemUri);
          const range = targetOverlay
            ? DocumentStore.lineToRange(targetOverlay.textDocument, item.line)
            : {
                start: { line: Math.max(0, item.line - 1), character: 0 },
                end: { line: Math.max(0, item.line - 1), character: 999 },
              };
          locations.push({ uri: itemUri, range });
        }
      }
    }

    return locations;
  }
}
