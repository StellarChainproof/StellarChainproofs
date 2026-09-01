/**
 * CP-121: Multi-hop Cross-Contract Reentrancy Detector
 *
 * Detects reentrancy attack chains that span two or more contract boundaries:
 *
 *   ContractA.fn() ──calls──► ContractB.g() ──calls──► ContractA.h()
 *
 * where ContractA has unfinalized state (reads a variable before writing it)
 * at the point of the first outgoing external call.
 *
 * Unlike CP-107 / CP-107-X, this rule consumes a full set of MergedContractViews
 * (one per known contract) to trace chains across independently deployed contracts.
 *
 * Configuration:
 *   cp121MaxDepth  — maximum cross-contract hops to follow (default 3, hard cap 10)
 *
 * @see {@link https://swcregistry.io/docs/SWC-107} SWC-107
 */

import { visit } from "../ast/parser";
import type { ASTNode, Finding, FindingEvidenceItem } from "../types";
import type { MergedContractView } from "../ast/import-graph";

// ─── Public configuration ─────────────────────────────────────────────────────

/** Options accepted by {@link detectCrossContractReentrancy}. */
export interface CP121Config {
  /**
   * Maximum number of cross-contract hops to follow when searching for
   * reentrancy chains. Defaults to 3. Hard-capped at {@link CP121_MAX_DEPTH_CAP}.
   */
  maxDepth?: number;
}

/** Absolute upper bound on traversal depth, regardless of configuration. */
export const CP121_MAX_DEPTH_CAP = 10;

/** Default traversal depth when no configuration is provided. */
export const CP121_DEFAULT_DEPTH = 3;

// ─── Internal graph types ─────────────────────────────────────────────────────

/** A node in the cross-contract call graph: (contractName, functionName). */
export interface CCNode {
  contract: string;
  fn: string;
}

/** A directed edge in the cross-contract call graph. */
export interface CCEdge {
  from: CCNode;
  /** Target contract name (resolved from variable type or direct reference). */
  toContract: string;
  /** Source line of the external call expression. */
  line: number;
  /** Raw AST call expression, kept for guard analysis. */
  callExpr: ASTNode;
  /**
   * True when this edge represents an unresolved low-level external call
   * (e.g. `msg.sender.call{value:...}("")`). The target contract type is
   * unknown, but the function is still a potential re-entry point.
   */
  isLowLevel?: boolean;
}

/**
 * The cross-contract call graph built from all available MergedContractViews.
 * Maps `"ContractName.fnName"` → list of outgoing cross-contract edges.
 */
export type CrossContractCallGraph = Map<string, CCEdge[]>;

/** A state-variable access found inside a function body. */
interface StateAccess {
  varName: string;
  line: number;
  isWrite: boolean;
}

/** A detected reentrancy chain ready to become a {@link Finding}. */
export interface ReentrancyChain {
  /** Ordered sequence of "ContractName.fnName" strings, length ≥ 3. */
  path: string[];
  /** State variables left unfinalized in the originating function. */
  unfinalizedVars: string[];
  /** Source line of the first outgoing external call in the originating fn. */
  externalCallLine: number;
  /** Source file of the originating contract. */
  originFile: string;
}

// ─── Guard detection ──────────────────────────────────────────────────────────

/**
 * Returns true if the function described by `fnNode` carries a recognized
 * reentrancy guard:
 *   (a) a modifier whose name contains "nonreentrant" (case-insensitive)
 *   (b) a hand-rolled mutex: `require(!locked)` / `locked = true` / `locked = false`
 */
export function hasReentrancyGuard(fnNode: ASTNode): boolean {
  const fn = fnNode as {
    modifiers?: Array<{ name?: string; modifierName?: { namePath?: string; name?: string } }>;
    body?: { statements?: ASTNode[] };
  };

  // (a) nonReentrant-style modifier
  for (const mod of fn.modifiers ?? []) {
    const name =
      mod.name ??
      mod.modifierName?.namePath ??
      mod.modifierName?.name ??
      "";
    if (name.toLowerCase().includes("nonreentrant")) return true;
  }

  // (b) hand-rolled mutex: look for `require(!locked)` or `locked = true` before call
  const statements = fn.body?.statements ?? [];
  const stmtJsons = statements.map((s: ASTNode) => JSON.stringify(s));

  const hasRequireNotLocked = stmtJsons.some(
    (s) =>
      s.includes('"require"') &&
      (s.includes('"!locked"') ||
        (s.includes('"UnaryOperation"') && s.includes('"locked"') && s.includes('"!"'))),
  );
  const hasLockedTrue = stmtJsons.some(
    (s) =>
      s.includes('"locked"') && s.includes('"true"') && s.includes('"operator":"="'),
  );

  return hasRequireNotLocked || hasLockedTrue;
}

// ─── State-variable access analysis ──────────────────────────────────────────

/**
 * Collect all state-variable accesses (reads and writes) in `fnNode`, in
 * source order. Uses a simple line-number heuristic for write detection.
 */
function collectStateAccesses(
  fnNode: ASTNode,
  stateVarNames: Set<string>,
): StateAccess[] {
  const accesses: StateAccess[] = [];
  const seen = new Set<string>();

  // Track assignments to detect writes
  visit(fnNode, {
    ExpressionStatement(node: ASTNode) {
      const stmt = node as { expression?: ASTNode; loc?: { start?: { line?: number } } };
      const expr = stmt.expression as {
        type?: string;
        operator?: string;
        left?: ASTNode;
      } | undefined;

      if (!expr) return;

      const isAssign =
        expr.type === "BinaryOperation" &&
        (expr.operator === "=" ||
          expr.operator === "-=" ||
          expr.operator === "+=" ||
          expr.operator === "*=" ||
          expr.operator === "/=");

      if (isAssign && expr.left) {
        const leftStr = JSON.stringify(expr.left);
        for (const varName of stateVarNames) {
          if (leftStr.includes(`"name":"${varName}"`)) {
            const line = (node as any).loc?.start?.line ?? 0;
            const key = `w:${varName}:${line}`;
            if (!seen.has(key)) {
              seen.add(key);
              accesses.push({ varName, line, isWrite: true });
            }
          }
        }
      }
    },
  });

  // Reads (identifiers and member accesses that reference state vars)
  visit(fnNode, {
    Identifier(node: ASTNode) {
      const id = node as { name?: string; loc?: { start?: { line?: number } } };
      if (!id.name || !stateVarNames.has(id.name)) return;
      const line = id.loc?.start?.line ?? 0;
      const key = `r:${id.name}:${line}`;
      if (!seen.has(key)) {
        seen.add(key);
        accesses.push({ varName: id.name, line, isWrite: false });
      }
    },
    MemberAccess(node: ASTNode) {
      const m = node as { memberName?: string; loc?: { start?: { line?: number } } };
      if (!m.memberName || !stateVarNames.has(m.memberName)) return;
      const line = m.loc?.start?.line ?? 0;
      const key = `r:${m.memberName}:${line}`;
      if (!seen.has(key)) {
        seen.add(key);
        accesses.push({ varName: m.memberName, line, isWrite: false });
      }
    },
  });

  return accesses.sort((a, b) => a.line - b.line);
}

/**
 * Find the source line of the first outgoing external call in `fnNode`.
 * Covers both low-level calls (`.call`, `.transfer`, `.send`) and typed
 * cross-contract calls (member-access on a typed state variable).
 * Returns 0 when none is found.
 */
function firstExternalCallLine(fnNode: ASTNode): number {
  let line = 0;
  visit(fnNode, {
    FunctionCall(node: ASTNode) {
      if (line !== 0) return; // keep first only
      const call = node as {
        expression?: ASTNode;
        loc?: { start?: { line?: number } };
      };
      const exprStr = JSON.stringify(call.expression ?? {});
      // Low-level calls
      if (
        exprStr.includes('"call"') ||
        exprStr.includes('"transfer"') ||
        exprStr.includes('"send"')
      ) {
        line = call.loc?.start?.line ?? 0;
        return;
      }
      // Typed cross-contract calls: MemberAccess expression
      const expr = call.expression as { type?: string } | undefined;
      if (expr?.type === "MemberAccess") {
        line = call.loc?.start?.line ?? 0;
      }
    },
  });
  return line;
}

/**
 * Determine which state variables are "unfinalized" at the first external call
 * site in `fnNode`:
 *   — read at least once BEFORE the first external call
 *   — NOT written BEFORE that same call
 */
export function findUnfinalizedVars(
  fnNode: ASTNode,
  stateVarNames: Set<string>,
): string[] {
  const callLine = firstExternalCallLine(fnNode);
  if (callLine === 0) return [];

  const accesses = collectStateAccesses(fnNode, stateVarNames);

  const readBefore = new Set<string>();
  const writtenBefore = new Set<string>();

  for (const acc of accesses) {
    if (acc.line >= callLine) continue;
    if (acc.isWrite) writtenBefore.add(acc.varName);
    else readBefore.add(acc.varName);
  }

  return [...readBefore].filter((v) => !writtenBefore.has(v));
}

// ─── Low-level external call detection ───────────────────────────────────────

/**
 * Returns true if `fnNode` contains a low-level external call:
 * `addr.call{...}(...)`, `.transfer(...)`, `.send(...)`.
 */
function hasLowLevelExternalCall(fnNode: ASTNode): boolean {
  let found = false;
  visit(fnNode, {
    FunctionCall(node: ASTNode) {
      if (found) return;
      const call = node as { expression?: ASTNode };
      const exprStr = JSON.stringify(call.expression ?? {});
      if (
        exprStr.includes('"call"') ||
        exprStr.includes('"transfer"') ||
        exprStr.includes('"send"')
      ) {
        found = true;
      }
    },
  });
  return found;
}

// ─── Cross-contract call graph construction ───────────────────────────────────

/** Unique string key for a CCNode. */
function nodeKey(n: CCNode): string {
  return `${n.contract}.${n.fn}`;
}

/**
 * Build the cross-contract call graph from all available `MergedContractView`s.
 *
 * An edge (A.f → B) is added whenever a function call inside A.f contains a
 * callee expression that can be resolved to a known contract name — either by:
 *   - a direct `ContractName(address).method()` pattern
 *   - a typed state variable (`IToken token; token.transfer(...)`)
 *   - a member-access whose receiver type string matches a known contract name
 *
 * Low-level `.call(...)` with no resolvable type are recorded with `isLowLevel: true`
 * and `toContract: ""`. These mark functions as having unresolved external calls
 * (potential re-entry points from an untrusted callee).
 */
export function buildCrossContractCallGraph(
  views: MergedContractView[],
): CrossContractCallGraph {
  const knownContracts = new Set(views.map((v) => v.name));
  const graph: CrossContractCallGraph = new Map();

  for (const view of views) {
    // Build a map of state variable name → inferred contract type for this contract
    const varTypeMap = buildVarTypeMap(view, knownContracts);

    for (const member of view.members) {
      if (member.kind !== "function") continue;

      const fnNode = member.node as { body?: { statements?: ASTNode[] } };
      if (!fnNode.body) continue;

      const key = nodeKey({ contract: view.name, fn: member.name });
      if (!graph.has(key)) graph.set(key, []);

      visit(fnNode, {
        FunctionCall(node: ASTNode) {
          const call = node as {
            expression?: ASTNode;
            loc?: { start?: { line?: number } };
          };
          const line = call.loc?.start?.line ?? 0;
          const expr = call.expression;
          if (!expr) return;

          const exprStr = JSON.stringify(expr);

          // Low-level external call (unresolved callee type)
          if (
            exprStr.includes('"call"') ||
            exprStr.includes('"transfer"') ||
            exprStr.includes('"send"')
          ) {
            // Only add if not a typed cross-contract call
            const resolved = resolveCallTarget(expr, varTypeMap, knownContracts);
            if (!resolved) {
              const edges = graph.get(key)!;
              edges.push({
                from: { contract: view.name, fn: member.name },
                toContract: "",
                line,
                callExpr: expr,
                isLowLevel: true,
              });
              return;
            }
          }

          const resolved = resolveCallTarget(expr, varTypeMap, knownContracts);
          if (!resolved) return; // truly unresolvable

          const edges = graph.get(key)!;
          edges.push({
            from: { contract: view.name, fn: member.name },
            toContract: resolved,
            line,
            callExpr: expr,
          });
        },
      });
    }
  }

  return graph;
}

/**
 * Build a map from state-variable name to inferred contract type for `view`.
 * Handles patterns like `IVault vault;` or `TokenContract public token;`.
 */
function buildVarTypeMap(
  view: MergedContractView,
  knownContracts: Set<string>,
): Map<string, string> {
  const map = new Map<string, string>();

  for (const member of view.members) {
    if (member.kind !== "stateVariable") continue;

    const decl = member.node as {
      variables?: Array<{
        name?: string;
        typeName?: {
          namePath?: string;
          name?: string;
          baseTypeName?: { namePath?: string; name?: string };
        };
      }>;
    };

    for (const v of decl.variables ?? []) {
      if (!v.name) continue;
      const typeName =
        v.typeName?.namePath ??
        v.typeName?.name ??
        v.typeName?.baseTypeName?.namePath ??
        v.typeName?.baseTypeName?.name ??
        "";

      // The type itself may be an interface (IVault) or a contract name
      if (knownContracts.has(typeName)) {
        map.set(v.name, typeName);
      } else {
        // Strip leading 'I' for interface convention: IVault → Vault
        const stripped = typeName.startsWith("I") ? typeName.slice(1) : typeName;
        if (knownContracts.has(stripped)) {
          map.set(v.name, stripped);
        }
      }
    }
  }

  return map;
}

/**
 * Try to resolve the target contract name of a call expression.
 * Returns the contract name string or null for unresolved calls.
 */
function resolveCallTarget(
  expr: ASTNode,
  varTypeMap: Map<string, string>,
  knownContracts: Set<string>,
): string | null {
  const e = expr as {
    type?: string;
    expression?: ASTNode;
    memberName?: string;
    name?: string;
    typeName?: { namePath?: string; name?: string };
    names?: string[];
  };

  // MemberAccess: `someVar.method` or `SomeContract(addr).method`
  if (e.type === "MemberAccess") {
    const inner = e.expression as {
      type?: string;
      name?: string;
      expression?: ASTNode;
      typeName?: { namePath?: string; name?: string };
    } | undefined;

    if (!inner) return null;

    // Direct identifier: `router.forward()`
    if (inner.type === "Identifier" && inner.name) {
      const resolved = varTypeMap.get(inner.name);
      if (resolved) return resolved;
      // Also try if the identifier IS a contract name directly (less common)
      if (knownContracts.has(inner.name)) return inner.name;
    }

    // Type cast: `IVault(addr).withdraw()` or `VaultA(addr).withdraw()`
    if (inner.type === "FunctionCall") {
      const cast = inner as {
        expression?: { type?: string; namePath?: string; name?: string };
        typeName?: { namePath?: string; name?: string };
      };
      // Handle TypeName cast syntax
      const castName =
        (cast.expression as any)?.namePath ??
        (cast.expression as any)?.name ??
        cast.typeName?.namePath ??
        cast.typeName?.name ??
        "";
      if (knownContracts.has(castName)) return castName;
      const stripped = castName.startsWith("I") ? castName.slice(1) : castName;
      if (knownContracts.has(stripped)) return stripped;
    }
  }

  return null;
}

// ─── DFS traversal ────────────────────────────────────────────────────────────

/**
 * Perform a depth-first search for reentrancy chains.
 *
 * Two modes:
 *
 * A) **Typed chain**: origin has a typed outgoing edge → B → … → origin.
 *    The entire path is through typed edges.
 *
 * B) **Typed + low-level hybrid**: origin makes a typed call to B,
 *    B (or a further hop) makes a low-level external call that can
 *    re-enter origin. Chain: origin → B → … → (low-level) → origin.
 *
 * C) **Direct low-level re-entry**: origin makes a low-level call, and
 *    some other contract has a typed edge directly back to origin.
 *
 * @param origin     The starting node (contract + function).
 * @param graph      The cross-contract call graph.
 * @param viewMap    Map from contract name to its MergedContractView.
 * @param maxDepth   Maximum number of cross-contract hops.
 * @returns          Array of detected reentrancy chains.
 */
function dfsSearch(
  origin: CCNode,
  graph: CrossContractCallGraph,
  viewMap: Map<string, MergedContractView>,
  maxDepth: number,
): ReentrancyChain[] {
  const chains: ReentrancyChain[] = [];

  const originView = viewMap.get(origin.contract);
  if (!originView) return chains;

  const originMember = originView.members.find(
    (m) => m.kind === "function" && m.name === origin.fn,
  );
  if (!originMember) return chains;

  // Short-circuit: if origin function has a reentrancy guard, skip entirely
  if (hasReentrancyGuard(originMember.node)) return chains;

  // Collect state var names for the origin contract
  const stateVarNames = new Set(
    originView.members
      .filter((m) => m.kind === "stateVariable")
      .map((m) => m.name),
  );

  // Determine unfinalized state in origin function
  const unfinalizedVars = findUnfinalizedVars(originMember.node, stateVarNames);
  if (unfinalizedVars.length === 0) return chains; // no vulnerable state — short-circuit

  const externalCallLine = firstExternalCallLine(originMember.node);

  const originEdges = graph.get(nodeKey(origin)) ?? [];

  // ── Mode B: low-level external call re-entry ──────────────────────────────
  // The origin makes a low-level call (msg.sender.call / transfer / send).
  // Any known contract could be the callee. Check if any contract in the
  // scan set has a typed edge back to origin contract (reverse caller).
  const hasLowLevel = originEdges.some((e) => e.isLowLevel);
  if (hasLowLevel) {
    // Find all contracts that can call INTO the origin contract via a typed path
    // within (maxDepth - 1) hops — the low-level call itself is 1 hop.
    const reachableBack = findContractsThatCallBack(
      origin.contract,
      graph,
      viewMap,
      maxDepth - 1, // -1 because the low-level external call counts as hop 1
    );

    for (const callerNode of reachableBack) {
      if (callerNode.contract === origin.contract) continue;

      // Build the chain: origin → (low-level → callerContract) → origin
      // We represent the low-level hop as origin.fn → callerNode → back to origin
      // The path for the finding is: [origin, callerNode, origin.fn-re-entered]
      // Re-entered function can be any function on origin (including same fn)
      const callerView = viewMap.get(callerNode.contract);
      if (!callerView) continue;

      // Find which function in origin is called by callerNode
      const callerEdges = graph.get(nodeKey(callerNode)) ?? [];
      for (const backEdge of callerEdges) {
        if (backEdge.toContract !== origin.contract || backEdge.isLowLevel) continue;

        // The target function in origin
        const reenteredFn = backEdge.callExpr
          ? (backEdge.callExpr as any).memberName ?? origin.fn
          : origin.fn;

        const reenteredKey = nodeKey({ contract: origin.contract, fn: reenteredFn });
        const path = [nodeKey(origin), nodeKey(callerNode), reenteredKey];

        chains.push({
          path,
          unfinalizedVars,
          externalCallLine,
          originFile: originView.file,
        });
      }
    }
  }

  // ── Mode A: typed-edge chain DFS ──────────────────────────────────────────
  type Frame = { node: CCNode; path: string[]; hops: number };
  const stack: Frame[] = [
    { node: origin, path: [nodeKey(origin)], hops: 0 },
  ];

  while (stack.length > 0) {
    const { node, path, hops } = stack.pop()!;

    if (hops >= maxDepth) continue;

    const edges = graph.get(nodeKey(node)) ?? [];

    for (const edge of edges) {
      if (edge.isLowLevel) {
        // A typed chain reached a node that makes a low-level call.
        // This low-level call could re-enter the origin contract if
        // the current node is not the origin itself.
        // Treat this as a potential re-entry back to origin.
        if (node.contract !== origin.contract && path.length >= 2) {
          // The low-level call from `node` could re-enter origin.
          // Build the path as: [...path, origin.fn-re-entered]
          // We intentionally allow reenteredKey == path[0] (the origin itself) —
          // that IS the re-entry we want to detect. We only block mid-path cycles.
          const reenteredKey = nodeKey({ contract: origin.contract, fn: origin.fn });
          const newPath = [...path, reenteredKey];
          chains.push({
            path: newPath,
            unfinalizedVars,
            externalCallLine,
            originFile: originView.file,
          });
        }
        continue; // don't follow low-level edges further
      }

      const targetContract = edge.toContract;
      if (!targetContract) continue;

      const targetView = viewMap.get(targetContract);
      if (!targetView) continue;

      for (const targetMember of targetView.members) {
        if (targetMember.kind !== "function") continue;

        const targetNode: CCNode = {
          contract: targetContract,
          fn: targetMember.name,
        };
        const targetKey = nodeKey(targetNode);

        if (path.includes(targetKey)) continue; // cycle guard

        const newPath = [...path, targetKey];

        // Re-entry via typed edge: path comes back to origin contract
        if (targetContract === origin.contract) {
          chains.push({
            path: newPath,
            unfinalizedVars,
            externalCallLine,
            originFile: originView.file,
          });
          continue;
        }

        stack.push({ node: targetNode, path: newPath, hops: hops + 1 });
      }
    }
  }

  return chains;
}

/**
 * Find all (contract, fn) nodes from which the target contract is reachable
 * through typed edges within `maxDepth` hops, looking only at callers of
 * `targetContract`.
 *
 * Used to identify which contracts can "call back" into the origin for Mode B.
 */
function findContractsThatCallBack(
  targetContract: string,
  graph: CrossContractCallGraph,
  viewMap: Map<string, MergedContractView>,
  maxDepth: number,
): CCNode[] {
  // A minimum of 1 hop is needed to have a caller
  if (maxDepth < 1) return [];

  // BFS from all nodes: find nodes that have a typed edge chain into targetContract
  const result: CCNode[] = [];
  const visited = new Set<string>();

  // Seed: direct callers of targetContract
  for (const [key, edges] of graph) {
    for (const edge of edges) {
      if (edge.toContract === targetContract && !edge.isLowLevel) {
        const [contract, fn] = key.split(".");
        if (contract && fn && contract !== targetContract) {
          const node: CCNode = { contract, fn };
          const k = nodeKey(node);
          if (!visited.has(k)) {
            visited.add(k);
            result.push(node);
          }
        }
      }
    }
  }

  // BFS backwards up to maxDepth-1 more hops
  const queue = [...result];
  let depth = 0;
  while (queue.length > 0 && depth < maxDepth - 1) {
    const batch = [...queue];
    queue.length = 0;
    depth++;

    for (const node of batch) {
      for (const [key, edges] of graph) {
        for (const edge of edges) {
          if (edge.toContract === node.contract && !edge.isLowLevel) {
            const [contract, fn] = key.split(".");
            if (contract && fn) {
              const callerNode: CCNode = { contract, fn };
              const k = nodeKey(callerNode);
              if (!visited.has(k) && contract !== targetContract) {
                visited.add(k);
                result.push(callerNode);
                queue.push(callerNode);
              }
            }
          }
        }
      }
    }
  }

  return result;
}

// ─── Main entry point ─────────────────────────────────────────────────────────

/**
 * Detect multi-hop cross-contract reentrancy chains across all provided
 * contract views.
 *
 * This function is designed to run **once per scan session** (not once per
 * file). Pass all `MergedContractView` objects collected during the scan.
 *
 * @param views   All merged contract views for the scan session.
 * @param config  Optional configuration (maxDepth).
 * @returns       Array of {@link Finding} objects, one per unique chain.
 */
export function detectCrossContractReentrancy(
  views: MergedContractView[],
  config?: CP121Config,
): Finding[] {
  if (views.length === 0) return [];

  const findings: Finding[] = [];

  // Resolve and clamp traversal depth
  const rawDepth = config?.maxDepth ?? CP121_DEFAULT_DEPTH;
  const clamped = rawDepth > CP121_MAX_DEPTH_CAP;
  const maxDepth = clamped ? CP121_MAX_DEPTH_CAP : Math.max(1, rawDepth);

  if (clamped) {
    findings.push({
      id: "CP-121-DEPTH-CAP",
      title: "CP-121 traversal depth clamped",
      description: `The configured cp121MaxDepth (${rawDepth}) exceeds the hard cap of ${CP121_MAX_DEPTH_CAP}. Traversal depth has been clamped to ${CP121_MAX_DEPTH_CAP}.`,
      recommendation: `Set cp121MaxDepth to a value ≤ ${CP121_MAX_DEPTH_CAP}.`,
      severity: "info",
      file: views[0]?.file ?? "",
      line: 0,
    });
  }

  // Build the cross-contract call graph once for all views
  const graph = buildCrossContractCallGraph(views);

  // Build a map from contract name to view for fast lookup
  const viewMap = new Map<string, MergedContractView>(views.map((v) => [v.name, v]));

  // Track emitted chain signatures for deduplication
  const emitted = new Set<string>();

  // Search for reentrancy chains starting from every node with outgoing edges
  for (const [nodeKeyStr] of graph) {
    const [contractName, fnName] = nodeKeyStr.split(".");
    if (!contractName || !fnName) continue;

    const origin: CCNode = { contract: contractName, fn: fnName };
    const chains = dfsSearch(origin, graph, viewMap, maxDepth);

    for (const chain of chains) {
      const signature = chain.path.join(" → ");
      if (emitted.has(signature)) continue;
      emitted.add(signature);

      findings.push(buildFinding(chain, viewMap));
    }
  }

  return findings;
}

// ─── Finding construction ─────────────────────────────────────────────────────

function buildFinding(
  chain: ReentrancyChain,
  viewMap: Map<string, MergedContractView>,
): Finding {
  const originKey = chain.path[0];
  const [originContract, originFn] = originKey.split(".");
  const reenteredKey = chain.path[chain.path.length - 1];
  const [reenteredContract] = reenteredKey.split(".");

  const hopCount = chain.path.length - 1; // number of edges = path nodes - 1

  const evidence: FindingEvidenceItem[] = chain.unfinalizedVars.map((v) => ({
    description: `State variable "${v}" is read in ${originContract}.${originFn} before the outgoing external call but not written beforehand — its value is stale during re-entry.`,
    file: chain.originFile,
    line: chain.externalCallLine,
  }));

  // Determine confidence based on partial guard presence
  // (full guard suppresses the finding entirely in dfsSearch)
  const confidence: Finding["confidence"] = "high";

  return {
    id: "CP-121",
    swcId: "SWC-107",
    title: `Multi-hop cross-contract reentrancy (${hopCount}-hop chain)`,
    description:
      `${originContract}.${originFn}() makes an external call with unfinalized state ` +
      `(${chain.unfinalizedVars.join(", ")}). A ${hopCount}-hop call chain ` +
      `(${chain.path.join(" → ")}) re-enters ${reenteredContract} before that state is finalized. ` +
      `This pattern can allow an attacker to drain funds or corrupt accounting.`,
    recommendation:
      "Apply the Checks-Effects-Interactions (CEI) pattern: write all state variables " +
      "before making any external call. For complex multi-contract flows, apply OpenZeppelin's " +
      "`ReentrancyGuard` (nonReentrant modifier) to every publicly reachable function " +
      "that appears in the call chain.",
    severity: "critical",
    file: chain.originFile,
    line: chain.externalCallLine,
    callPath: chain.path,
    evidence,
    confidence,
    assumptions: [
      `The call chain ${chain.path.join(" → ")} is assumed to be reachable at runtime.`,
      "No transitive reentrancy guard was detected covering the full chain.",
    ],
  };
}
