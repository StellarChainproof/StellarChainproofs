/**
 * Unit tests for CP-121: Multi-hop Cross-Contract Reentrancy Detector
 *
 * Covers:
 *   1. 2-hop exploitable chain — one finding with callPath length 3
 *   2. 3-hop exploitable chain — one finding with callPath length 4
 *   3. Guarded (CEI) chain — zero findings
 *   4. Depth-limited scenario — no finding when chain exceeds configured max
 *   5. Full finding-shape validation (id, swcId, severity, callPath, evidence)
 *   6. Round-trip property: every callPath starts and ends with the same contract
 *   7. Deduplication: same chain not emitted twice
 *   8. Empty input: graceful no-op
 *   9. Depth cap clamping: emits info finding when maxDepth > hard cap
 *  10. findUnfinalizedVars unit tests
 *  11. hasReentrancyGuard unit tests
 *  12. buildCrossContractCallGraph unit tests
 */

import * as path from "path";
import { parseSolidity } from "../../ast/parser";
import { buildImportGraph, buildMergedContractViews } from "../../ast/import-graph";
import {
  detectCrossContractReentrancy,
  findUnfinalizedVars,
  hasReentrancyGuard,
  buildCrossContractCallGraph,
  CP121_DEFAULT_DEPTH,
  CP121_MAX_DEPTH_CAP,
} from "../cp121-cross-contract-reentrancy";
import type { MergedContractView } from "../../ast/import-graph";

// ─── Solidity fixtures (inline strings) ──────────────────────────────────────

/**
 * 2-hop vulnerable: VaultA.withdraw() → calls msg.sender → re-enters VaultA
 *
 * VaultA has an unfinalized `balances` read before the external call.
 * AttackerB.execute() calls back into VaultA.withdraw().
 */
const TWO_HOP_VULNERABLE = `
pragma solidity ^0.7.6;

interface IAttacker {
    function execute() external;
}

contract VaultA {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "empty");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "failed");
        balances[msg.sender] = 0;
    }
}

contract AttackerB {
    VaultA public vault;

    constructor(address _vault) {
        vault = VaultA(_vault);
    }

    function execute() external {
        vault.withdraw();
    }
}
`;

/**
 * 3-hop vulnerable: VaultX.withdraw() → RouterY.forward() → ReceiverZ.onReceive() → VaultX.withdraw()
 */
const THREE_HOP_VULNERABLE = `
pragma solidity ^0.7.6;

contract ReceiverZ {
    address public vaultAddr;

    constructor(address _vault) {
        vaultAddr = _vault;
    }

    function onReceive(address target) external {
        (bool ok, ) = target.call(abi.encodeWithSignature("withdraw()"));
        require(ok, "failed");
    }
}

contract RouterY {
    ReceiverZ public receiver;

    constructor(address _recv) {
        receiver = ReceiverZ(_recv);
    }

    function forward(address origin) external {
        receiver.onReceive(origin);
    }
}

contract VaultX {
    mapping(address => uint256) public deposits;
    RouterY public router;

    constructor(address _router) {
        router = RouterY(_router);
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = deposits[msg.sender];
        require(amount > 0, "empty");
        router.forward(address(this));
        deposits[msg.sender] = 0;
    }
}
`;

/**
 * Guarded (CEI): VaultSafe writes state BEFORE the external call — no unfinalized vars.
 */
const TWO_HOP_GUARDED = `
pragma solidity ^0.7.6;

contract VaultSafe {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "empty");
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "failed");
    }
}

contract AttackerC {
    VaultSafe public vault;

    constructor(address _vault) {
        vault = VaultSafe(_vault);
    }

    function execute() external {
        vault.withdraw();
    }
}
`;

/**
 * nonReentrant guard: modifier suppresses the finding entirely.
 */
const NONREENTRANT_GUARDED = `
pragma solidity ^0.7.6;

contract GuardedVault {
    mapping(address => uint256) public balances;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "empty");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "failed");
        balances[msg.sender] = 0;
    }
}

contract CallerD {
    GuardedVault public vault;

    constructor(address _vault) {
        vault = GuardedVault(_vault);
    }

    function probe() external {
        vault.withdraw();
    }
}
`;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Parse a Solidity source string and return merged contract views. */
function parseViews(source: string, fileName: string): MergedContractView[] {
  const absPath = path.resolve(fileName);
  const { ast } = parseSolidity(source, absPath);
  if (!ast) return [];

  const graph = buildImportGraph([absPath]);
  graph.files.set(absPath, {
    filePath: fileName,
    absolutePath: absPath,
    source,
    ast,
  });

  return buildMergedContractViews(graph);
}

// ─── Test suites ──────────────────────────────────────────────────────────────

describe("CP-121: detectCrossContractReentrancy", () => {
  // ── Test 1: 2-hop exploitable ──────────────────────────────────────────────
  describe("2-hop exploitable fixture", () => {
    let findings: ReturnType<typeof detectCrossContractReentrancy>;

    beforeAll(() => {
      const views = parseViews(TWO_HOP_VULNERABLE, "two-hop-vuln.sol");
      findings = detectCrossContractReentrancy(views);
    });

    it("produces at least one CP-121 finding", () => {
      const cp121 = findings.filter((f) => f.id === "CP-121");
      expect(cp121.length).toBeGreaterThanOrEqual(1);
    });

    it("finding has id CP-121 and swcId SWC-107", () => {
      const f = findings.find((f) => f.id === "CP-121");
      expect(f).toBeDefined();
      expect(f!.id).toBe("CP-121");
      expect(f!.swcId).toBe("SWC-107");
    });

    it("finding has severity critical", () => {
      const f = findings.find((f) => f.id === "CP-121");
      expect(f!.severity).toBe("critical");
    });

    it("finding callPath has length ≥ 3 (at least 2 hops)", () => {
      const f = findings.find((f) => f.id === "CP-121");
      expect(f!.callPath).toBeDefined();
      expect(f!.callPath!.length).toBeGreaterThanOrEqual(3);
    });

    it("finding has non-empty evidence array", () => {
      const f = findings.find((f) => f.id === "CP-121");
      expect(f!.evidence).toBeDefined();
      expect(f!.evidence!.length).toBeGreaterThan(0);
    });

    it("finding has recommendation mentioning CEI and ReentrancyGuard", () => {
      const f = findings.find((f) => f.id === "CP-121");
      expect(f!.recommendation).toMatch(/checks-effects-interactions/i);
      expect(f!.recommendation).toMatch(/reentrancyguard/i);
    });
  });

  // ── Test 2: 3-hop exploitable ──────────────────────────────────────────────
  describe("3-hop exploitable fixture", () => {
    let findings: ReturnType<typeof detectCrossContractReentrancy>;

    beforeAll(() => {
      const views = parseViews(THREE_HOP_VULNERABLE, "three-hop-vuln.sol");
      findings = detectCrossContractReentrancy(views);
    });

    it("produces at least one CP-121 finding", () => {
      const cp121 = findings.filter((f) => f.id === "CP-121");
      expect(cp121.length).toBeGreaterThanOrEqual(1);
    });

    it("finding callPath has length ≥ 4 (at least 3 hops)", () => {
      const f = findings.find((f) => f.id === "CP-121");
      expect(f!.callPath!.length).toBeGreaterThanOrEqual(4);
    });
  });

  // ── Test 3: Guarded (CEI) — zero findings ─────────────────────────────────
  describe("CEI-guarded fixture", () => {
    it("produces zero CP-121 findings", () => {
      const views = parseViews(TWO_HOP_GUARDED, "two-hop-guarded.sol");
      const findings = detectCrossContractReentrancy(views);
      const cp121 = findings.filter((f) => f.id === "CP-121");
      expect(cp121).toHaveLength(0);
    });
  });

  // ── Test 4: nonReentrant modifier — zero findings ─────────────────────────
  describe("nonReentrant modifier fixture", () => {
    it("produces zero CP-121 findings", () => {
      const views = parseViews(NONREENTRANT_GUARDED, "nonreentrant-guarded.sol");
      const findings = detectCrossContractReentrancy(views);
      const cp121 = findings.filter((f) => f.id === "CP-121");
      expect(cp121).toHaveLength(0);
    });
  });

  // ── Test 5: depth limit — chain truncated ─────────────────────────────────
  describe("depth-limited traversal", () => {
    it("produces no finding for 2-hop chain when maxDepth=1", () => {
      const views = parseViews(TWO_HOP_VULNERABLE, "two-hop-depth.sol");
      // maxDepth=1 means we follow at most 1 hop from origin, so we cannot
      // complete a 2-hop chain (needs 2 hops to get back to origin)
      const findings = detectCrossContractReentrancy(views, { maxDepth: 1 });
      const cp121 = findings.filter((f) => f.id === "CP-121");
      expect(cp121).toHaveLength(0);
    });

    it("produces finding for 2-hop chain when maxDepth=2 (enough hops)", () => {
      const views = parseViews(TWO_HOP_VULNERABLE, "two-hop-enough.sol");
      const findings = detectCrossContractReentrancy(views, { maxDepth: 2 });
      const cp121 = findings.filter((f) => f.id === "CP-121");
      expect(cp121.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Test 6: round-trip property ───────────────────────────────────────────
  describe("round-trip property: callPath contract invariant", () => {
    it("every CP-121 callPath starts and ends with the same contract name", () => {
      const views = parseViews(TWO_HOP_VULNERABLE, "roundtrip.sol");
      const findings = detectCrossContractReentrancy(views);
      for (const f of findings.filter((x) => x.id === "CP-121")) {
        const first = f.callPath![0].split(".")[0];
        const last = f.callPath![f.callPath!.length - 1].split(".")[0];
        expect(first).toBe(last);
      }
    });

    it("3-hop callPath also satisfies the round-trip invariant", () => {
      const views = parseViews(THREE_HOP_VULNERABLE, "roundtrip3.sol");
      const findings = detectCrossContractReentrancy(views);
      for (const f of findings.filter((x) => x.id === "CP-121")) {
        const first = f.callPath![0].split(".")[0];
        const last = f.callPath![f.callPath!.length - 1].split(".")[0];
        expect(first).toBe(last);
      }
    });
  });

  // ── Test 7: deduplication ─────────────────────────────────────────────────
  describe("deduplication", () => {
    it("same chain is not emitted more than once", () => {
      const views = parseViews(TWO_HOP_VULNERABLE, "dedup.sol");
      const findings = detectCrossContractReentrancy(views);
      const cp121 = findings.filter((f) => f.id === "CP-121");
      const signatures = cp121.map((f) => f.callPath!.join(" → "));
      const unique = new Set(signatures);
      expect(signatures.length).toBe(unique.size);
    });
  });

  // ── Test 8: empty input ───────────────────────────────────────────────────
  describe("empty input", () => {
    it("returns empty array for empty views list", () => {
      const findings = detectCrossContractReentrancy([]);
      expect(findings).toHaveLength(0);
    });
  });

  // ── Test 9: depth cap clamping ────────────────────────────────────────────
  describe("depth cap clamping", () => {
    it("emits an info finding when maxDepth exceeds the hard cap", () => {
      const views = parseViews(TWO_HOP_VULNERABLE, "cap.sol");
      const findings = detectCrossContractReentrancy(views, {
        maxDepth: CP121_MAX_DEPTH_CAP + 5,
      });
      const capFinding = findings.find((f) => f.id === "CP-121-DEPTH-CAP");
      expect(capFinding).toBeDefined();
      expect(capFinding!.severity).toBe("info");
    });

    it("still detects vulnerabilities after clamping", () => {
      const views = parseViews(TWO_HOP_VULNERABLE, "cap2.sol");
      const findings = detectCrossContractReentrancy(views, {
        maxDepth: CP121_MAX_DEPTH_CAP + 5,
      });
      const cp121 = findings.filter((f) => f.id === "CP-121");
      expect(cp121.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Test 10: default depth constant ──────────────────────────────────────
  it("default depth is 3", () => {
    expect(CP121_DEFAULT_DEPTH).toBe(3);
  });

  it("hard cap is 10", () => {
    expect(CP121_MAX_DEPTH_CAP).toBe(10);
  });
});

// ─── findUnfinalizedVars unit tests ───────────────────────────────────────────

describe("findUnfinalizedVars", () => {
  it("returns unfinalized variable when read before call but not written", () => {
    const source = `
      pragma solidity ^0.7.6;
      contract T {
        mapping(address => uint256) balances;
        function withdraw() external {
          uint256 amount = balances[msg.sender];
          (bool ok,) = msg.sender.call{value: amount}("");
          require(ok);
          balances[msg.sender] = 0;
        }
      }
    `;
    const views = parseViews(source, "unfinalized.sol");
    const vault = views.find((v) => v.name === "T");
    expect(vault).toBeDefined();

    const fn = vault!.members.find((m) => m.kind === "function" && m.name === "withdraw");
    expect(fn).toBeDefined();

    const stateVars = new Set(
      vault!.members.filter((m) => m.kind === "stateVariable").map((m) => m.name),
    );
    const unfinalized = findUnfinalizedVars(fn!.node, stateVars);
    expect(unfinalized).toContain("balances");
  });

  it("returns empty when state is written before external call (CEI)", () => {
    const source = `
      pragma solidity ^0.7.6;
      contract T {
        mapping(address => uint256) balances;
        function withdraw() external {
          uint256 amount = balances[msg.sender];
          balances[msg.sender] = 0;
          (bool ok,) = msg.sender.call{value: amount}("");
          require(ok);
        }
      }
    `;
    const views = parseViews(source, "cei.sol");
    const vault = views.find((v) => v.name === "T");
    const fn = vault!.members.find((m) => m.kind === "function" && m.name === "withdraw");
    const stateVars = new Set(
      vault!.members.filter((m) => m.kind === "stateVariable").map((m) => m.name),
    );
    const unfinalized = findUnfinalizedVars(fn!.node, stateVars);
    expect(unfinalized).not.toContain("balances");
  });

  it("returns empty when function has no external call", () => {
    const source = `
      pragma solidity ^0.7.6;
      contract T {
        uint256 counter;
        function increment() external {
          counter += 1;
        }
      }
    `;
    const views = parseViews(source, "noexternal.sol");
    const vault = views.find((v) => v.name === "T");
    const fn = vault!.members.find((m) => m.kind === "function" && m.name === "increment");
    const stateVars = new Set(["counter"]);
    const unfinalized = findUnfinalizedVars(fn!.node, stateVars);
    expect(unfinalized).toHaveLength(0);
  });
});

// ─── hasReentrancyGuard unit tests ────────────────────────────────────────────

describe("hasReentrancyGuard", () => {
  it("detects nonReentrant modifier", () => {
    const source = `
      pragma solidity ^0.7.6;
      contract G {
        function fn() external nonReentrant {
          uint256 x = 1;
        }
      }
    `;
    const views = parseViews(source, "guard.sol");
    const v = views.find((x) => x.name === "G");
    const fn = v!.members.find((m) => m.kind === "function" && m.name === "fn");
    expect(hasReentrancyGuard(fn!.node)).toBe(true);
  });

  it("returns false when no guard is present", () => {
    const source = `
      pragma solidity ^0.7.6;
      contract G {
        function fn() external {
          uint256 x = 1;
        }
      }
    `;
    const views = parseViews(source, "noguard.sol");
    const v = views.find((x) => x.name === "G");
    const fn = v!.members.find((m) => m.kind === "function" && m.name === "fn");
    expect(hasReentrancyGuard(fn!.node)).toBe(false);
  });
});

// ─── buildCrossContractCallGraph unit tests ───────────────────────────────────

describe("buildCrossContractCallGraph", () => {
  it("builds graph with edges when one contract calls another", () => {
    const views = parseViews(TWO_HOP_VULNERABLE, "graph.sol");
    const graph = buildCrossContractCallGraph(views);

    // Should have at least one entry in the graph
    expect(graph.size).toBeGreaterThan(0);
  });

  it("returns empty graph for single contract with no typed external calls", () => {
    const source = `
      pragma solidity ^0.7.6;
      contract Solo {
        function greet() external pure returns (string memory) {
          return "hello";
        }
      }
    `;
    const views = parseViews(source, "solo.sol");
    const graph = buildCrossContractCallGraph(views);
    // No cross-contract edges expected
    for (const edges of graph.values()) {
      expect(edges).toHaveLength(0);
    }
  });
});

// ─── File-based fixture tests ─────────────────────────────────────────────────

describe("file-based fixture contracts", () => {
  const fixtureDir = path.resolve(__dirname, "../../../../../examples/contracts/cross-contract-reentrancy");

  function loadFixture(fileName: string): MergedContractView[] {
    const filePath = path.join(fixtureDir, fileName);
    const { ast, error } = require("../../ast/parser").parseSolidity(
      require("fs").readFileSync(filePath, "utf-8"),
      filePath,
    );
    if (!ast) throw new Error(`Failed to parse ${fileName}: ${error}`);

    const graph = buildImportGraph([filePath]);
    graph.files.set(filePath, {
      filePath,
      absolutePath: filePath,
      source: require("fs").readFileSync(filePath, "utf-8"),
      ast,
    });
    return buildMergedContractViews(graph);
  }

  it("TwoHopVulnerable.sol produces at least one CP-121 finding", () => {
    const views = loadFixture("TwoHopVulnerable.sol");
    const findings = detectCrossContractReentrancy(views);
    const cp121 = findings.filter((f) => f.id === "CP-121");
    expect(cp121.length).toBeGreaterThanOrEqual(1);
  });

  it("TwoHopGuarded.sol produces zero CP-121 findings", () => {
    const views = loadFixture("TwoHopGuarded.sol");
    const findings = detectCrossContractReentrancy(views);
    const cp121 = findings.filter((f) => f.id === "CP-121");
    expect(cp121).toHaveLength(0);
  });

  it("round-trip invariant holds for all TwoHopVulnerable.sol findings", () => {
    const views = loadFixture("TwoHopVulnerable.sol");
    const findings = detectCrossContractReentrancy(views);
    for (const f of findings.filter((x) => x.id === "CP-121")) {
      const first = f.callPath![0].split(".")[0];
      const last = f.callPath![f.callPath!.length - 1].split(".")[0];
      expect(first).toBe(last);
    }
  });
});
