/**
 * @packageDocumentation
 * @chainproof/core — Pragma Parser, Constraint Analyzer & Cross-Import Resolver
 */

import type { ASTNode } from "../types";
import type {
  PragmaConstraint,
  PragmaOperator,
  ResolvedPragmas,
  ProjectPragmaResolution,
} from "./types";
import {
  parseSemVer,
  parseSemVerRange,
  satisfiesSemVer,
  intersectSemVerRanges,
  sortSemVerList,
} from "./semver";
import {
  ALL_SUPPORTED_VERSIONS,
  getHazardsForVersion,
  getRecommendedCompilerVersion,
} from "./matrix";

const PRAGMA_SOL_REGEX = /pragma\s+solidity\s+([^;]+);/g;

export interface ExtractedPragma {
  raw: string;
  value: string;
  line: number;
}

/**
 * Extracts all `pragma solidity ...` directives from a source file.
 */
export function extractPragmas(source: string, ast?: ASTNode): ExtractedPragma[] {
  const pragmas: ExtractedPragma[] = [];

  // First try AST if available
  if (ast) {
    const children = (ast as { children?: ASTNode[] }).children;
    if (Array.isArray(children)) {
      for (const child of children) {
        const node = child as {
          type?: string;
          name?: string;
          value?: string;
          loc?: { start?: { line?: number } };
        };
        if (node.type === "PragmaDirective" && node.name === "solidity" && node.value) {
          pragmas.push({
            raw: `pragma solidity ${node.value};`,
            value: node.value.trim(),
            line: node.loc?.start?.line ?? 1,
          });
        }
      }
    }
  }

  if (pragmas.length > 0) {
    return pragmas;
  }

  // Fallback to regex on source
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const lineContent = lines[i];
    // Strip comments
    const stripped = lineContent.replace(/\/\/.*$/, "").replace(/\/\*.*?\*\//g, "");
    let match: RegExpExecArray | null;
    PRAGMA_SOL_REGEX.lastIndex = 0;
    while ((match = PRAGMA_SOL_REGEX.exec(stripped)) !== null) {
      pragmas.push({
        raw: match[0],
        value: match[1].trim(),
        line: i + 1,
      });
    }
  }

  return pragmas;
}

/**
 * Parses a raw pragma value string into structured constraints.
 */
export function parsePragmaConstraints(pragmaValue: string): PragmaConstraint[] {
  const normalized = pragmaValue.replace(/[\^~><=!]+/g, (op) => ` ${op} `).trim();
  const tokens = normalized.split(/\s+/).filter(Boolean);
  const constraints: PragmaConstraint[] = [];

  let currentOp: PragmaOperator = "=";
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (
      token === "^" ||
      token === "~" ||
      token === ">=" ||
      token === "<=" ||
      token === ">" ||
      token === "<" ||
      token === "=" ||
      token === "!="
    ) {
      currentOp = token as PragmaOperator;
    } else {
      const parsed = parseSemVer(token);
      if (parsed) {
        constraints.push({
          operator: currentOp,
          version: `${parsed.major}.${parsed.minor}.${parsed.patch}`,
          raw: `${currentOp}${token}`,
        });
        currentOp = "=";
      }
    }
  }

  return constraints;
}

/**
 * Analyzes whether a pragma directive is floating (unpinned).
 */
export function isFloatingPragma(pragmaValue: string): boolean {
  const trimmed = pragmaValue.trim();
  return (
    trimmed.includes("^") ||
    trimmed.includes(">") ||
    trimmed.includes(">=") ||
    trimmed.includes("<") ||
    trimmed.includes("<=") ||
    trimmed.includes("~") ||
    trimmed.includes("*") ||
    trimmed.includes("x") ||
    trimmed.includes("||")
  );
}

/**
 * Analyzes whether a pragma directive spans multiple breaking compiler minor families.
 */
export function isOverlyBroadPragma(compatibleVersions: string[]): boolean {
  if (compatibleVersions.length <= 1) return false;

  const families = new Set<string>();
  for (const v of compatibleVersions) {
    const parsed = parseSemVer(v);
    if (parsed) {
      families.add(`${parsed.major}.${parsed.minor}`);
    }
  }

  // If it spans 2 or more minor families (e.g. 0.7 and 0.8), it is overly broad
  return families.size >= 2;
}

/**
 * Analyzes whether a pragma allows security-sensitive compiler versions (<0.8.0 or known critical bugs).
 */
export function isSecuritySensitivePragma(compatibleVersions: string[]): boolean {
  for (const v of compatibleVersions) {
    const parsed = parseSemVer(v);
    if (!parsed) continue;

    // Allows pre-0.8.0 without checked math
    if (parsed.major === 0 && parsed.minor < 8) {
      return true;
    }

    // Allows versions with critical codegen bugs
    const hazards = getHazardsForVersion(v);
    if (hazards.some((h) => h.severity === "critical" || h.severity === "high")) {
      return true;
    }
  }
  return false;
}

/**
 * Analyzes a single file's pragma directive.
 */
export function analyzeFilePragma(
  file: string,
  rawPragma: string,
  pragmaValue: string,
  line: number = 1,
): ResolvedPragmas {
  const constraints = parsePragmaConstraints(pragmaValue);
  const range = parseSemVerRange(pragmaValue);

  const compatibleVersions = ALL_SUPPORTED_VERSIONS.filter((v) =>
    satisfiesSemVer(v, range),
  );
  const sorted = sortSemVerList(compatibleVersions, "asc");

  const isFloating = isFloatingPragma(pragmaValue);
  const isOverlyBroad = isOverlyBroadPragma(sorted);
  const isSecuritySensitive = isSecuritySensitivePragma(sorted);

  // Collect all unique hazards present in any compatible version
  const hazardMap = new Map<string, ReturnType<typeof getHazardsForVersion>[number]>();
  for (const v of sorted) {
    for (const h of getHazardsForVersion(v)) {
      hazardMap.set(h.id, h);
    }
  }

  let rangeDescription = pragmaValue;
  if (sorted.length > 0) {
    rangeDescription =
      sorted.length === 1
        ? `=${sorted[0]}`
        : `${sorted[0]} ... ${sorted[sorted.length - 1]}`;
  }

  return {
    file,
    rawPragma,
    constraints,
    isFloating,
    isOverlyBroad,
    isSecuritySensitive,
    compatibleVersions: sorted,
    lowestCompatible: sorted[0],
    highestCompatible: sorted[sorted.length - 1],
    hazards: [...hazardMap.values()],
    rangeDescription,
    line,
  };
}

/**
 * Resolves pragma constraints across multiple project files and imports.
 * Identifies satisfiability, conflicts, and global compatibility.
 */
export function resolveProjectPragmas(
  files: { file: string; content?: string; source?: string; ast?: ASTNode }[],
): ProjectPragmaResolution {
  const resolvedFiles: ResolvedPragmas[] = [];

  for (const f of files) {
    const srcCode = f.content ?? f.source ?? "";
    const extracted = extractPragmas(srcCode, f.ast);
    if (extracted.length === 0) {
      // Default / unpinned pragma if none specified
      resolvedFiles.push({
        file: f.file,
        rawPragma: "/* unspecified */",
        constraints: [],
        isFloating: true,
        isOverlyBroad: true,
        isSecuritySensitive: true,
        compatibleVersions: [...ALL_SUPPORTED_VERSIONS],
        lowestCompatible: ALL_SUPPORTED_VERSIONS[0],
        highestCompatible: ALL_SUPPORTED_VERSIONS[ALL_SUPPORTED_VERSIONS.length - 1],
        hazards: [],
        rangeDescription: "unspecified (matches all)",
        line: 1,
      });
    } else {
      for (const pragma of extracted) {
        resolvedFiles.push(
          analyzeFilePragma(f.file, pragma.raw, pragma.value, pragma.line),
        );
      }
    }
  }

  const fileRanges = resolvedFiles.map((rf) => rf.rawPragma.replace(/^pragma\s+solidity\s+/, "").replace(/;$/, ""));
  const intersection = intersectSemVerRanges(fileRanges, [...ALL_SUPPORTED_VERSIONS]);

  const unsatisfiable = !intersection.satisfiable;
  const conflictDetails: string[] = [];

  if (unsatisfiable && resolvedFiles.length > 1) {
    // Determine pairwise conflicts
    for (let i = 0; i < resolvedFiles.length; i++) {
      for (let j = i + 1; j < resolvedFiles.length; j++) {
        const fileA = resolvedFiles[i];
        const fileB = resolvedFiles[j];
        const pairIntersect = intersectSemVerRanges(
          [fileA.rawPragma.replace(/^pragma\s+solidity\s+/, "").replace(/;$/, ""), fileB.rawPragma.replace(/^pragma\s+solidity\s+/, "").replace(/;$/, "")],
          [...ALL_SUPPORTED_VERSIONS],
        );
        if (!pairIntersect.satisfiable) {
          conflictDetails.push(
            `Pragma conflict: "${fileA.file}" (${fileA.rawPragma.trim()}) is incompatible with "${fileB.file}" (${fileB.rawPragma.trim()})`,
          );
        }
      }
    }
  }

  const globalCompatible = intersection.satisfyingVersions;
  const recommended = globalCompatible.length > 0
    ? getRecommendedCompilerVersion(intersection.effectiveRangeDescription)
    : undefined;

  const hasFloating = resolvedFiles.some((f) => f.isFloating);
  const hasBroad = resolvedFiles.some((f) => f.isOverlyBroad);
  const hasSensitive = resolvedFiles.some((f) => f.isSecuritySensitive);

  return {
    files: resolvedFiles,
    globalRange: intersection.effectiveRangeDescription,
    globalCompatibleVersions: globalCompatible,
    unsatisfiable,
    conflictDetails: conflictDetails.length > 0 ? conflictDetails : undefined,
    recommendedVersion: recommended,
    lowestCompatibleVersion: intersection.lowestVersion,
    highestCompatibleVersion: intersection.highestVersion,
    totalFiles: files.length,
    hasFloatingPragmas: hasFloating,
    hasBroadPragmas: hasBroad,
    hasSecuritySensitivePragmas: hasSensitive,
  };
}
