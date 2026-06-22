/**
 * Lightweight symbolic execution engine for arithmetic overflow/underflow
 * path analysis on Solidity ASTs.
 *
 * Design:
 *  - Assign symbolic ranges to operands of arithmetic binary operations
 *  - Propagate range constraints from require/assert guards within the same
 *    function body (narrows false positives from manual bounds checks)
 *  - Detect paths where the symbolic range can exceed uint/int bounds
 *  - Always analyze `unchecked` blocks in Solidity >=0.8 regardless of pragma
 */

import { visit } from "../ast/parser";
import type { ASTNode } from "../types";

// ─── Range types ──────────────────────────────────────────────────────────────

/** A closed numeric interval [lo, hi]. Uses bigint to represent uint256/int256 bounds. */
export interface SymbolicRange {
  lo: bigint;
  hi: bigint;
}

const UINT256_MAX = (1n << 256n) - 1n;
const INT256_MIN = -(1n << 255n);
const INT256_MAX = (1n << 255n) - 1n;

/** Unbounded range — any 256-bit unsigned integer (conservative default). */
const UNBOUNDED_UINT: SymbolicRange = { lo: 0n, hi: UINT256_MAX };
/** Unbounded signed range. */
const UNBOUNDED_INT: SymbolicRange = { lo: INT256_MIN, hi: INT256_MAX };

// ─── Overflow detection result ────────────────────────────────────────────────

export interface OverflowCandidate {
  operator: string;
  line: number;
  snippet: string;
  /** true if guard/require narrows range so overflow is provably unreachable */
  guardedOut: boolean;
  /** true if inside an explicit `unchecked {}` block */
  inUncheckedBlock: boolean;
}

// ─── Utility: extract require/assert constraints ──────────────────────────────

interface Constraint {
  /** variable name being constrained */
  variable: string;
  operator: "<" | "<=" | ">" | ">=" | "==";
  /** constant value on the other side */
  value: bigint;
}

function extractConstraints(statements: ASTNode[]): Constraint[] {
  const constraints: Constraint[] = [];

  for (const stmt of statements) {
    const stmtStr = JSON.stringify(stmt);

    // Detect require/assert calls
    if (
      !stmtStr.includes('"name":"require"') &&
      !stmtStr.includes('"name":"assert"')
    ) {
      continue;
    }

    // Walk this statement for BinaryOperation nodes that look like bounds checks
    visit(stmt, {
      BinaryOperation(node: ASTNode) {
        const op = node as {
          operator?: string;
          left?: ASTNode;
          right?: ASTNode;
        };

        const relOps = ["<", "<=", ">", ">=", "=="];
        if (!relOps.includes(op.operator ?? "")) return;

        const left = op.left as { type?: string; name?: string; number?: string } | undefined;
        const right = op.right as { type?: string; name?: string; number?: string } | undefined;

        // Pattern: varName </<= constant  or  constant </<=  varName
        if (left?.type === "Identifier" && right?.type === "NumberLiteral") {
          const val = safeParseInt(right.number ?? "");
          if (val !== null) {
            constraints.push({
              variable: left.name ?? "",
              operator: op.operator as Constraint["operator"],
              value: val,
            });
          }
        } else if (right?.type === "Identifier" && left?.type === "NumberLiteral") {
          const val = safeParseInt(left.number ?? "");
          if (val !== null) {
            // flip: constant < var  →  var > constant
            const flipped = flipOperator(op.operator as Constraint["operator"]);
            constraints.push({
              variable: right.name ?? "",
              operator: flipped,
              value: val,
            });
          }
        }

        // Pattern: a + b >= a  (classic overflow guard)
        // Detect by presence of both operands being Identifiers and the
        // overall expression suggesting a sum-overflow guard
        if (
          (op.operator === ">=" || op.operator === ">") &&
          left?.type === "BinaryOperation"
        ) {
          const sum = left as { operator?: string; left?: ASTNode; right?: ASTNode };
          if (sum.operator === "+" || sum.operator === "-") {
            // Mark both operands as guarded (conservative: full unbounded-but-guarded)
            const sumLeft = sum.left as { name?: string };
            const sumRight = sum.right as { name?: string };
            if (sumLeft?.name) {
              constraints.push({ variable: sumLeft.name, operator: ">=", value: 0n });
            }
            if (sumRight?.name) {
              constraints.push({ variable: sumRight.name, operator: ">=", value: 0n });
            }
          }
        }
      },
    });
  }

  return constraints;
}

function flipOperator(op: Constraint["operator"]): Constraint["operator"] {
  switch (op) {
    case "<":  return ">";
    case "<=": return ">=";
    case ">":  return "<";
    case ">=": return "<=";
    default:   return op;
  }
}

function safeParseInt(s: string): bigint | null {
  try {
    // Handle hex literals
    if (s.startsWith("0x") || s.startsWith("0X")) return BigInt(s);
    // Strip numeric separators (Solidity allows 1_000_000)
    return BigInt(s.replace(/_/g, ""));
  } catch {
    return null;
  }
}

// ─── Apply constraints to narrow a symbolic range ────────────────────────────

function applyConstraints(
  varName: string,
  base: SymbolicRange,
  constraints: Constraint[]
): SymbolicRange {
  let { lo, hi } = base;

  for (const c of constraints) {
    if (c.variable !== varName) continue;
    switch (c.operator) {
      case "<":  hi = c.value - 1n < hi ? c.value - 1n : hi; break;
      case "<=": hi = c.value < hi ? c.value : hi; break;
      case ">":  lo = c.value + 1n > lo ? c.value + 1n : lo; break;
      case ">=": lo = c.value > lo ? c.value : lo; break;
      case "==": lo = c.value; hi = c.value; break;
    }
  }

  return { lo, hi };
}

// ─── Arithmetic range propagation ────────────────────────────────────────────

/**
 * Given two operand ranges and an operator, compute the output range.
 * Returns whether the result can overflow a 256-bit unsigned boundary.
 */
function canOverflow(
  lRange: SymbolicRange,
  rRange: SymbolicRange,
  operator: string
): boolean {
  switch (operator) {
    case "+": {
      // max possible result = lRange.hi + rRange.hi
      const maxResult = lRange.hi + rRange.hi;
      return maxResult > UINT256_MAX;
    }
    case "-": {
      // underflow: min result = lRange.lo - rRange.hi
      const minResult = lRange.lo - rRange.hi;
      return minResult < 0n;
    }
    case "*": {
      if (lRange.hi === 0n || rRange.hi === 0n) return false;
      const maxResult = lRange.hi * rRange.hi;
      return maxResult > UINT256_MAX;
    }
    case "**": {
      // Exponentiation: conservatively flag unless base/exp is trivially zero/one
      if (lRange.hi <= 1n || rRange.hi <= 1n) return false;
      // 2^256 already overflows uint256; if base can be >= 2 and exp >= 256, flag
      if (lRange.lo >= 2n && rRange.hi >= 256n) return true;
      // For smaller exponents, compute pessimistically
      try {
        const maxResult = lRange.hi ** rRange.hi;
        return maxResult > UINT256_MAX;
      } catch {
        return true; // BigInt overflow in our analysis → conservatively flag
      }
    }
    default:
      return false;
  }
}

// ─── Walk a function's statements to collect arithmetic operations ────────────

interface ArithmeticOp {
  node: ASTNode;
  operator: string;
  line: number;
  inUncheckedBlock: boolean;
  /** Names of identifiers found on left/right */
  leftName?: string;
  rightName?: string;
  leftLiteral?: bigint;
  rightLiteral?: bigint;
}

/**
 * Walk a function body, tracking whether we are inside an unchecked block.
 * Collects all arithmetic BinaryOperation nodes with their unchecked context.
 *
 * Handles both regular operators (+, -, *, **) and compound assignments
 * (+=, -=, *=) which the solidity-parser also emits as BinaryOperation.
 *
 * Note: @solidity-parser/parser emits UncheckedStatement with a `block` property
 * (not `body`). We cannot rely on the generic visitor to pass the unchecked flag
 * down, so we traverse the tree manually.
 */
function collectArithmeticOps(
  node: ASTNode,
  inUnchecked: boolean = false
): ArithmeticOp[] {
  const ops: ArithmeticOp[] = [];

  // Canonical operators: both binary and compound-assignment forms
  const ARITH_OPS = new Set(["+", "-", "*", "**", "+=", "-=", "*="]);

  // Normalise compound assignment operator to its simple form for range analysis
  function normalise(op: string): string {
    if (op === "+=") return "+";
    if (op === "-=") return "-";
    if (op === "*=") return "*";
    return op;
  }

  function walk(n: ASTNode, unchecked: boolean): void {
    if (!n || typeof n !== "object") return;

    const typed = n as {
      type?: string;
      operator?: string;
      left?: ASTNode;
      right?: ASTNode;
      loc?: { start?: { line?: number } };
      statements?: ASTNode[];
      block?: ASTNode;
      body?: ASTNode;
      trueBody?: ASTNode;
      falseBody?: ASTNode;
      expression?: ASTNode;
      value?: ASTNode;
      initialValue?: ASTNode;
      subNodes?: ASTNode[];
    };

    if (typed.type === "UncheckedStatement") {
      // Inner block is in `block` (not `body`) per solidity-parser AST
      if (typed.block) walk(typed.block, true);
      return;
    }

    if (typed.type === "BinaryOperation") {
      const op = typed.operator ?? "";
      if (ARITH_OPS.has(op)) {
        const left = typed.left as { type?: string; name?: string; number?: string } | undefined;
        const right = typed.right as { type?: string; name?: string; number?: string } | undefined;
        ops.push({
          node: n,
          operator: normalise(op),
          line: typed.loc?.start?.line ?? 0,
          inUncheckedBlock: unchecked,
          leftName: left?.type === "Identifier" ? left.name : undefined,
          rightName: right?.type === "Identifier" ? right.name : undefined,
          leftLiteral: left?.type === "NumberLiteral" ? (safeParseInt(left.number ?? "") ?? undefined) : undefined,
          rightLiteral: right?.type === "NumberLiteral" ? (safeParseInt(right.number ?? "") ?? undefined) : undefined,
        });
      }
      // Always recurse into operands — handles assignment `x = a + b` and comparisons
      if (typed.left) walk(typed.left, unchecked);
      if (typed.right) walk(typed.right, unchecked);
      return;
    }

    // Recurse into known child-bearing properties
    if (typed.statements) {
      for (const s of typed.statements) walk(s, unchecked);
    }
    if (typed.subNodes) {
      for (const s of typed.subNodes) walk(s, unchecked);
    }
    if (typed.body) walk(typed.body, unchecked);
    if (typed.expression) walk(typed.expression, unchecked);
    if (typed.trueBody) walk(typed.trueBody, unchecked);
    if (typed.falseBody) walk(typed.falseBody, unchecked);
    if (typed.value) walk(typed.value, unchecked);
    if (typed.initialValue) walk(typed.initialValue, unchecked);
  }

  walk(node, inUnchecked);
  return ops;
}

// ─── Additional guard: detect sum-overflow patterns ──────────────────────────

/**
 * Returns true if any statement in the list is a require/assert that contains
 * the classic `require(a + b >= a)` or `require(a + b >= b)` pattern.
 * When present, all `+` operations in the function are considered guarded.
 */
function hasSumOverflowGuard(statements: ASTNode[]): boolean {
  for (const stmt of statements) {
    const s = JSON.stringify(stmt);
    if (
      (s.includes('"name":"require"') || s.includes('"name":"assert"')) &&
      s.includes('"operator":"+"') &&
      (s.includes('"operator":">="') || s.includes('"operator":">"'))
    ) {
      return true;
    }
  }
  return false;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface SymbolicExecOptions {
  /** Whether the contract uses Solidity >=0.8 (built-in checked arithmetic). */
  is08Plus: boolean;
}

/**
 * Run symbolic execution over a function body.
 *
 * Returns a list of OverflowCandidates: arithmetic operations that may
 * overflow/underflow, along with whether a guard was found to suppress them.
 *
 * For >=0.8 contracts, only `unchecked {}` blocks are analyzed.
 * For <0.8 contracts, all arithmetic is analyzed with constraint narrowing.
 */
export function analyzeFunction(
  fnBody: { statements?: ASTNode[] },
  opts: SymbolicExecOptions
): OverflowCandidate[] {
  const statements = fnBody.statements ?? [];
  const candidates: OverflowCandidate[] = [];

  // Collect constraints from require/assert at the top of the function
  const constraints = extractConstraints(statements);

  // Detect classic sum-overflow guard pattern: require(a + b >= a)
  const sumGuarded = hasSumOverflowGuard(statements);

  // Collect all arithmetic ops via tree walk (tracks unchecked context)
  const fakeBlock: ASTNode = { type: "Block", statements } as ASTNode;
  const ops = collectArithmeticOps(fakeBlock, false);

  for (const op of ops) {
    // For >=0.8: only flag ops inside explicit `unchecked` blocks
    if (opts.is08Plus && !op.inUncheckedBlock) continue;

    // Build symbolic ranges for each operand
    let lRange: SymbolicRange = { ...UNBOUNDED_UINT };
    let rRange: SymbolicRange = { ...UNBOUNDED_UINT };

    // Apply literal constants directly
    if (op.leftLiteral !== undefined) {
      lRange = { lo: op.leftLiteral, hi: op.leftLiteral };
    } else if (op.leftName) {
      lRange = applyConstraints(op.leftName, UNBOUNDED_UINT, constraints);
    }

    if (op.rightLiteral !== undefined) {
      rRange = { lo: op.rightLiteral, hi: op.rightLiteral };
    } else if (op.rightName) {
      rRange = applyConstraints(op.rightName, UNBOUNDED_UINT, constraints);
    }

    const overflowPossible = canOverflow(lRange, rRange, op.operator);

    // A sum-overflow guard (require(a+b >= a)) covers all addition ops in this fn
    const sumGuardCovers = sumGuarded && (op.operator === "+" || op.operator === "-");

    // Check whether the guard provably rules out overflow:
    const guardedOut = !overflowPossible || sumGuardCovers;

    candidates.push({
      operator: op.operator,
      line: op.line,
      snippet: "",
      guardedOut,
      inUncheckedBlock: op.inUncheckedBlock,
    });
  }

  return candidates;
}

/**
 * Top-level entry: run symbolic execution on every function in the contract AST.
 * Returns candidates that are NOT guarded out (i.e., genuine potential overflows).
 */
export function runSymbolicExec(
  ast: ASTNode,
  opts: SymbolicExecOptions
): OverflowCandidate[] {
  const results: OverflowCandidate[] = [];

  visit(ast, {
    FunctionDefinition(node: ASTNode) {
      const fn = node as {
        body?: { type?: string; statements?: ASTNode[] };
      };
      if (!fn.body) return;

      const candidates = analyzeFunction(fn.body as { statements?: ASTNode[] }, opts);
      results.push(...candidates.filter((c) => !c.guardedOut));
    },
  });

  return results;
}
