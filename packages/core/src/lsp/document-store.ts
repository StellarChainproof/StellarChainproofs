import { TextDocument } from "vscode-languageserver-textdocument";
import type { Position, Range } from "vscode-languageserver";
import * as path from "path";
import * as fs from "fs";
import { parseSolidity } from "../ast/parser";
import { ASTCache } from "../ast/cache";
import { buildImportGraph, type ImportGraph, type ParsedSolidityFile } from "../ast/import-graph";
import type { ASTNode } from "../types";

export interface OverlayDocument {
  uri: string;
  filePath: string;
  version: number;
  textDocument: TextDocument;
  ast?: ASTNode;
  parseError?: string;
  contentHash: string;
  lastUpdated: number;
}

/**
 * Manages open documents in memory (editor overlays), tracking buffer edits,
 * line/character offsets, AST caching, and dependency relationships with on-disk files.
 */
export class DocumentStore {
  private readonly documents = new Map<string, OverlayDocument>();
  private readonly astCache: ASTCache;

  constructor(astCache?: ASTCache) {
    this.astCache = astCache ?? new ASTCache();
  }

  /** Convert file URI or file path into normalized absolute file path */
  public static uriToFilePath(uri: string): string {
    if (uri.startsWith("file://")) {
      const decoded = decodeURIComponent(uri.replace(/^file:\/\//, ""));
      // Handle Windows drive letter formatting (e.g. /c:/ -> c:/)
      if (process.platform === "win32" && /^\/[a-zA-Z]:/.test(decoded)) {
        return path.normalize(decoded.slice(1));
      }
      return path.normalize(decoded);
    }
    return path.resolve(uri);
  }

  /** Convert file path to file:// URI */
  public static filePathToUri(filePath: string): string {
    const absPath = path.resolve(filePath).replace(/\\/g, "/");
    if (!absPath.startsWith("/")) {
      return `file:///${absPath}`;
    }
    return `file://${absPath}`;
  }

  /** Open or update a document buffer from an LSP didOpen or didChange event */
  public openOrUpdate(
    uri: string,
    version: number,
    text: string,
    languageId = "solidity"
  ): OverlayDocument {
    const filePath = DocumentStore.uriToFilePath(uri);
    const existing = this.documents.get(uri);

    let doc: TextDocument;
    if (existing) {
      doc = TextDocument.create(uri, languageId, version, text);
    } else {
      doc = TextDocument.create(uri, languageId, version, text);
    }

    const contentHash = ASTCache.hashContent(text);
    let ast: ASTNode | undefined;
    let parseError: string | undefined;

    const cached = this.astCache.get(contentHash);
    if (cached) {
      ast = cached.ast;
    } else {
      const parsed = parseSolidity(text, filePath);
      ast = parsed.ast ?? undefined;
      parseError = parsed.error;
      if (ast) {
        this.astCache.set(contentHash, {
          contentHash,
          ast,
          parsedAt: Date.now(),
          filePath,
        });
      }
    }

    const overlay: OverlayDocument = {
      uri,
      filePath,
      version,
      textDocument: doc,
      ast,
      parseError,
      contentHash,
      lastUpdated: Date.now(),
    };

    this.documents.set(uri, overlay);
    return overlay;
  }

  /** Close a document buffer */
  public close(uri: string): boolean {
    return this.documents.delete(uri);
  }

  /** Retrieve overlay document by URI */
  public get(uri: string): OverlayDocument | undefined {
    return this.documents.get(uri);
  }

  /** Retrieve overlay document by physical file path */
  public getByFilePath(filePath: string): OverlayDocument | undefined {
    const resolved = path.resolve(filePath);
    for (const doc of this.documents.values()) {
      if (path.resolve(doc.filePath) === resolved) {
        return doc;
      }
    }
    return undefined;
  }

  /** List all open documents */
  public getAll(): OverlayDocument[] {
    return Array.from(this.documents.values());
  }

  /** Check if document is open */
  public has(uri: string): boolean {
    return this.documents.has(uri);
  }

  /** Count of open documents */
  public get size(): number {
    return this.documents.size;
  }

  /** Convert line (1-indexed) and column (1-indexed) to LSP Position (0-indexed line/char) */
  public static toPosition(line: number, column = 1): Position {
    return {
      line: Math.max(0, line - 1),
      character: Math.max(0, column - 1),
    };
  }

  /** Convert LSP Position (0-indexed) to 1-indexed line number */
  public static positionToLine(position: Position): number {
    return position.line + 1;
  }

  /** Create an LSP Range for a 1-indexed line number */
  public static lineToRange(document: TextDocument, line1Indexed: number): Range {
    const lineIndex = Math.max(0, line1Indexed - 1);
    const lineCount = document.lineCount;

    if (lineIndex >= lineCount) {
      const lastLine = Math.max(0, lineCount - 1);
      const text = document.getText({
        start: { line: lastLine, character: 0 },
        end: { line: lastLine, character: Number.MAX_SAFE_INTEGER },
      });
      return {
        start: { line: lastLine, character: 0 },
        end: { line: lastLine, character: text.length },
      };
    }

    const lineText = document.getText({
      start: { line: lineIndex, character: 0 },
      end: { line: lineIndex + 1, character: 0 },
    });
    // Remove newline char if included
    const length = lineText.replace(/[\r\n]+$/, "").length;

    return {
      start: { line: lineIndex, character: 0 },
      end: { line: lineIndex, character: Math.max(0, length) },
    };
  }

  /**
   * Build a unified ImportGraph combining in-memory overlay documents and on-disk files.
   * Overlay documents override disk content for any open file.
   */
  public buildOverlayImportGraph(knownFiles: string[]): ImportGraph {
    const allFilePaths = new Set<string>();
    for (const f of knownFiles) {
      allFilePaths.add(path.resolve(f));
    }
    for (const doc of this.documents.values()) {
      allFilePaths.add(path.resolve(doc.filePath));
    }

    const graph = buildImportGraph(Array.from(allFilePaths));

    // Override with open overlay files content and ast where applicable
    for (const [absPath, parsed] of graph.files.entries()) {
      const overlay = this.getByFilePath(absPath);
      if (overlay) {
        parsed.source = overlay.textDocument.getText();
        if (overlay.ast) {
          parsed.ast = overlay.ast;
        }
      }
    }

    return graph;
  }
}
