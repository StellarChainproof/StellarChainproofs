/**
 * @packageDocumentation
 * @chainproof/core — Compiler Compatibility & Diagnostic Matrix Rules (CP-SOL-001 to CP-SOL-010)
 */

import type { ASTNode, Finding, Severity } from "../types";
import type { CompilerRuleId, ResolvedPragmas } from "./types";
import { extractPragmas, analyzeFilePragma, isFloatingPragma } from "./pragma";
import { getHazardsForVersion } from "./matrix";
import { parseSemVer, compareSemVer } from "./semver";
import { visit } from "../ast/parser";

export interface CompilerRuleContext {
  ast?: ASTNode;
  source: string;
  filePath: string;
  resolvedPragma?: ResolvedPragmas;
  allowedRules?: Set<CompilerRuleId>;
  excludedRules?: Set<CompilerRuleId>;
}

export function shouldRunRule(
  ruleId: CompilerRuleId,
  context?: { includeRules?: CompilerRuleId[]; excludeRules?: CompilerRuleId[] },
): boolean {
  if (context?.excludeRules?.includes(ruleId)) return false;
  if (context?.includeRules && context.includeRules.length > 0) {
    return context.includeRules.includes(ruleId);
  }
  return true;
}

/**
 * CP-SOL-001: Floating Pragma Directive
 */
export function checkFloatingPragma(
  ast: ASTNode,
  source: string,
  filePath: string,
): Finding[] {
  const extracted = extractPragmas(source, ast);
  const findings: Finding[] = [];

  for (const pragma of extracted) {
    if (isFloatingPragma(pragma.value)) {
      findings.push({
        id: "CP-SOL-001",
        title: "Floating Pragma Directive Detected",
        description:
          `Source file uses an unpinned, floating pragma directive "${pragma.raw}". ` +
          `Contracts should be deployed with the exact compiler version they were tested against to avoid unexpected bytecode generation differences.`,
        recommendation:
          `Lock the pragma directive to a concrete compiler release, e.g. "pragma solidity 0.8.28;".`,
        severity: "low",
        file: filePath,
        line: pragma.line,
        snippet: pragma.raw,
      });
    }
  }

  return findings;
}

/**
 * CP-SOL-003: Overly Broad Compiler Version Range
 */
export function checkOverlyBroadPragma(
  ast: ASTNode,
  source: string,
  filePath: string,
): Finding[] {
  const extracted = extractPragmas(source, ast);
  const findings: Finding[] = [];

  for (const pragma of extracted) {
    const analyzed = analyzeFilePragma(filePath, pragma.raw, pragma.value, pragma.line);
    if (analyzed.isOverlyBroad) {
      findings.push({
        id: "CP-SOL-003",
        title: "Overly Broad Compiler Version Range",
        description:
          `Pragma directive "${pragma.raw}" spans multiple major/minor compiler version families (${analyzed.rangeDescription}). ` +
          `Different Solidity minor versions contain breaking syntax and semantic changes that can lead to divergent execution.`,
        recommendation:
          `Constrain the compiler version range to a single minor family, e.g. "^0.8.20".`,
        severity: "medium",
        file: filePath,
        line: pragma.line,
        snippet: pragma.raw,
      });
    }
  }

  return findings;
}

/**
 * CP-SOL-004: Outdated or End-of-Life Compiler Version (<0.8.0)
 */
export function checkOutdatedCompilerVersion(
  ast: ASTNode,
  source: string,
  filePath: string,
): Finding[] {
  const extracted = extractPragmas(source, ast);
  const findings: Finding[] = [];

  for (const pragma of extracted) {
    const analyzed = analyzeFilePragma(filePath, pragma.raw, pragma.value, pragma.line);
    const hasPre08 = analyzed.compatibleVersions.some((v) => {
      const p = parseSemVer(v);
      return p !== null && p.major === 0 && p.minor < 8;
    });

    if (hasPre08) {
      findings.push({
        id: "CP-SOL-004",
        title: "Outdated or End-of-Life Compiler Version (<0.8.0)",
        description:
          `Pragma directive "${pragma.raw}" allows compilation with Solidity <0.8.0 (${analyzed.lowestCompatible}). ` +
          `Versions prior to 0.8.0 do not feature built-in arithmetic overflow/underflow checking and lack modern security improvements.`,
        recommendation:
          `Upgrade contract to Solidity >=0.8.20 and replace legacy SafeMath with built-in checked arithmetic.`,
        severity: "high",
        file: filePath,
        line: pragma.line,
        snippet: pragma.raw,
      });
    }
  }

  return findings;
}

/**
 * CP-SOL-005: Known Compiler Code-Generation Bug / Hazard
 */
export function checkKnownCompilerHazards(
  ast: ASTNode,
  source: string,
  filePath: string,
): Finding[] {
  const extracted = extractPragmas(source, ast);
  const findings: Finding[] = [];

  let hasAssembly = false;
  let hasTransient = false;
  let hasSignedImmutables = false;

  visit(ast, {
    InlineAssemblyStatement: () => {
      hasAssembly = true;
    },
    StateVariableDeclaration: (node: any) => {
      for (const v of node.variables || []) {
        if (v.isImmutable) {
          const typeName = v.typeName?.name || "";
          if (/^int\d*$/.test(typeName) && typeName !== "int256") {
            hasSignedImmutables = true;
          }
        }
      }
    },
  });

  if (source.includes("tstore") || source.includes("tload")) {
    hasTransient = true;
  }

  for (const pragma of extracted) {
    const analyzed = analyzeFilePragma(filePath, pragma.raw, pragma.value, pragma.line);

    for (const ver of analyzed.compatibleVersions) {
      const hazards = getHazardsForVersion(ver, {
        hasTransientStorage: hasTransient,
        hasInlineAssembly: hasAssembly,
        usesSignedImmutables: hasSignedImmutables,
      });

      for (const h of hazards) {
        // Map hazard severity to finding severity
        const sev: Severity =
          h.severity === "critical"
            ? "critical"
            : h.severity === "high"
            ? "high"
            : h.severity === "medium"
            ? "medium"
            : "low";

        findings.push({
          id: "CP-SOL-005",
          title: `Known Compiler Bug: ${h.name} (${h.id})`,
          description:
            `Target version ${ver} permitted by pragma "${pragma.raw}" is vulnerable to ${h.id} (${h.name}): ${h.description}`,
          recommendation: h.recommendation,
          severity: sev,
          file: filePath,
          line: pragma.line,
          snippet: pragma.raw,
        });
      }
    }
  }

  // Deduplicate findings by rule, file, line, title
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.id}:${f.file}:${f.line}:${f.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * CP-SOL-006: PUSH0 Opcode EVM Incompatibility Risk
 */
export function checkPush0Hazard(
  ast: ASTNode,
  source: string,
  filePath: string,
): Finding[] {
  const extracted = extractPragmas(source, ast);
  const findings: Finding[] = [];

  for (const pragma of extracted) {
    const analyzed = analyzeFilePragma(filePath, pragma.raw, pragma.value, pragma.line);
    const uses0820Plus = analyzed.compatibleVersions.some((v) => compareSemVer(v, "0.8.20") >= 0);

    if (uses0820Plus) {
      findings.push({
        id: "CP-SOL-006",
        title: "PUSH0 Opcode EVM Incompatibility Risk (Solidity >=0.8.20)",
        description:
          `Pragma directive "${pragma.raw}" allows compilation with Solidity >=0.8.20 which defaults to the Shanghai EVM target and emits the PUSH0 (0x5f) opcode. ` +
          `Deploying bytecode with PUSH0 to L2 networks or sidechains without Shanghai EVM support will cause transaction reverts.`,
        recommendation:
          `If deploying to Layer-2 networks or chains without PUSH0 support, configure compiler settings with evmVersion: "paris" or "london".`,
        severity: "low",
        file: filePath,
        line: pragma.line,
        snippet: pragma.raw,
      });
    }
  }

  return findings;
}

/**
 * CP-SOL-009: Transient Storage Lifecycle / Reentrancy Hazard
 */
export function checkTransientStorageHazard(
  ast: ASTNode,
  source: string,
  filePath: string,
): Finding[] {
  const findings: Finding[] = [];
  const hasTransient = source.includes("tstore") || source.includes("tload");

  if (hasTransient) {
    let line = 1;
    const lines = source.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes("tstore") || lines[i].includes("tload")) {
        line = i + 1;
        break;
      }
    }

    findings.push({
      id: "CP-SOL-009",
      title: "Transient Storage Operation Detected (EIP-1153)",
      description:
        `Contract uses transient storage (tstore/tload). Transient storage values are discarded at the end of the transaction, ` +
        `but persist across internal and external calls within the same transaction. Ensure transient storage slots are explicitly cleared after use to prevent intra-transaction replay.`,
      recommendation:
        `Always clear transient storage slots in finally/revert handlers and ensure compiler version is >=0.8.26 to avoid transient storage code generator bugs.`,
      severity: "medium",
      file: filePath,
      line,
      snippet: lines[line - 1]?.trim(),
    });
  }

  return findings;
}

/**
 * Public entrypoint for running all compiler compatibility rules on an AST.
 * Integrates directly into `@chainproof/core` scanner.
 */
export function detectCompilerCompatibility(
  ast: ASTNode,
  source: string,
  filePath: string,
  options?: { includeRules?: CompilerRuleId[]; excludeRules?: CompilerRuleId[] },
): Finding[] {
  const findings: Finding[] = [];

  if (shouldRunRule("CP-SOL-001", options)) {
    findings.push(...checkFloatingPragma(ast, source, filePath));
  }
  if (shouldRunRule("CP-SOL-003", options)) {
    findings.push(...checkOverlyBroadPragma(ast, source, filePath));
  }
  if (shouldRunRule("CP-SOL-004", options)) {
    findings.push(...checkOutdatedCompilerVersion(ast, source, filePath));
  }
  if (shouldRunRule("CP-SOL-005", options)) {
    findings.push(...checkKnownCompilerHazards(ast, source, filePath));
  }
  if (shouldRunRule("CP-SOL-006", options)) {
    findings.push(...checkPush0Hazard(ast, source, filePath));
  }
  if (shouldRunRule("CP-SOL-009", options)) {
    findings.push(...checkTransientStorageHazard(ast, source, filePath));
  }

  return findings;
}
