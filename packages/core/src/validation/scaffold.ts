/**
 * Finding-to-Scaffold Translator.
 *
 * Translates static {@link Finding} objects emitted by ChainProof's analysis
 * pipeline into parameterized {@link ValidationScenario} scaffolds.
 *
 * @remarks
 * This module does NOT claim automatic exploitability. Scenarios produced
 * here are reproduction scaffolds — a starting point for a researcher to
 * fill in contract bytecode and verify behavior. The `expectedOutcome` for
 * all generated scenarios is `"exploit-succeeds"` to indicate "this is
 * what we expect *if* the finding is exploitable"; it is the researcher's
 * job to confirm or refute this by running the scenario.
 *
 * Supported finding IDs:
 * - CP-107 / SWC-107: Reentrancy
 * - CP-115 / SWC-115: tx.origin authentication
 * - CP-101 / SWC-101: Integer overflow/underflow
 * - CP-104 / SWC-104: Unchecked call return value
 * - CP-122: Vault share-price inflation
 * - CP-CB-CEI: Callback CEI violation
 * - CP-CB-CROSSFN: Cross-function reentrancy via callback
 * - CP-CB-SPOOF: Callback spoofing
 *
 * All other findings produce an {@link UnsupportedFinding} entry.
 */

import * as path from "path";
import * as crypto from "crypto";
import type { Finding } from "../types";
import type {
  AccountSpec,
  CallSpec,
  ContractSpec,
  UnsupportedFinding,
  ValidationPlan,
  ValidationScenario,
} from "./types";
import {
  VALIDATION_SCHEMA_VERSION,
  CorruptBundleError,
} from "./types";

// ─── Supported finding IDs ────────────────────────────────────────────────────

const SUPPORTED_FINDING_IDS = new Set([
  "CP-107",
  "SWC-107",
  "CP-107-X",
  "CP-115",
  "SWC-115",
  "CP-101",
  "SWC-101",
  "CP-104",
  "SWC-104",
  "CP-122",
  "CP-CB-CEI",
  "CP-CB-CROSSFN",
  "CP-CB-SPOOF",
  "CP-CB-BATCH",
  "CP-CB-READONLY",
]);

// ─── Default scenario accounts ───────────────────────────────────────────────

const SCAFFOLD_ACCOUNTS: AccountSpec[] = [
  {
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    balance: "100000000000000000000", // 100 ETH
    label: "deployer",
  },
  {
    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    balance: "100000000000000000000",
    label: "attacker",
  },
  {
    address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    balance: "100000000000000000000",
    label: "victim",
  },
];

// ─── Scaffold generators ──────────────────────────────────────────────────────

function makeScenarioId(finding: Finding, suffix?: string): string {
  const base = [
    "scenario",
    finding.id.replace(/[^A-Za-z0-9]/g, "-"),
    path.basename(finding.file, ".sol"),
    finding.line,
  ]
    .join("-")
    .toLowerCase();
  const hash = crypto.createHash("sha1")
    .update(finding.file + ":" + finding.line + ":" + finding.id)
    .digest("hex")
    .slice(0, 8);
  return suffix ? `${base}-${suffix}-${hash}` : `${base}-${hash}`;
}

function scaffoldReentrancy(finding: Finding): ValidationScenario {
  const contracts: ContractSpec[] = [
    {
      name: "VulnerableContract",
      bytecode: "0x", // Researcher must supply compiled bytecode
      abi: "[]",
      deployer: "deployer",
    },
    {
      name: "AttackerContract",
      bytecode: "0x", // Researcher must supply attacker contract bytecode
      abi: "[]",
      deployer: "attacker",
    },
  ];

  const calls: CallSpec[] = [
    {
      to: "VulnerableContract",
      signature: "deposit()",
      value: "1000000000000000000",
      from: "victim",
      description: "Victim deposits 1 ETH into the vulnerable contract",
    },
    {
      to: "AttackerContract",
      signature: "attack()",
      from: "attacker",
      description: "Attacker triggers the reentrancy exploit",
    },
  ];

  return {
    schemaVersion: VALIDATION_SCHEMA_VERSION,
    id: makeScenarioId(finding),
    title: `Reentrancy reproduction scaffold: ${path.basename(finding.file)} L${finding.line}`,
    description:
      `Scaffold for finding ${finding.id}. ` +
      `Supply compiled bytecode for VulnerableContract and AttackerContract, ` +
      `then adjust call sequence to match the actual vulnerable function. ` +
      `This scenario is NOT claimed to be automatically exploitable.`,
    findingId: finding.id,
    findingFile: finding.file,
    findingLine: finding.line,
    chain: { chainId: 31337 },
    accounts: SCAFFOLD_ACCOUNTS,
    contracts,
    calls,
    expectedOutcome: "exploit-succeeds",
    outcomeDescription:
      "AttackerContract should drain VulnerableContract ETH via reentrancy. " +
      "Validate by checking attacker balance increased and vault balance decreased.",
    balanceAssertions: [
      {
        account: "AttackerContract",
        op: "gt",
        value: "1000000000000000000",
        description: "Attacker's contract gained ETH from the reentrancy",
      },
    ],
    tags: ["reentrancy", "CP-107", "SWC-107"],
    createdAt: new Date().toISOString(),
  };
}

function scaffoldTxOrigin(finding: Finding): ValidationScenario {
  const calls: CallSpec[] = [
    {
      to: "VulnerableContract",
      signature: "privilegedAction()",
      from: "attacker",
      description:
        "Attacker calls the function protected only by tx.origin. " +
        "In a real exploit, attacker tricks the owner into calling attacker's contract, " +
        "which then calls this function — bypassing the tx.origin check.",
    },
  ];

  return {
    schemaVersion: VALIDATION_SCHEMA_VERSION,
    id: makeScenarioId(finding),
    title: `tx.origin auth bypass scaffold: ${path.basename(finding.file)} L${finding.line}`,
    description:
      `Scaffold for finding ${finding.id} (tx.origin authentication bypass). ` +
      `Real exploitation requires a phishing vector: owner calls attacker's ` +
      `contract, which calls back into VulnerableContract. ` +
      `This scenario demonstrates the direct call path for analysis purposes.`,
    findingId: finding.id,
    findingFile: finding.file,
    findingLine: finding.line,
    chain: { chainId: 31337 },
    accounts: SCAFFOLD_ACCOUNTS,
    contracts: [
      {
        name: "VulnerableContract",
        bytecode: "0x",
        abi: "[]",
        deployer: "deployer",
      },
    ],
    calls,
    expectedOutcome: "exploit-succeeds",
    tags: ["tx-origin", "CP-115", "SWC-115"],
    createdAt: new Date().toISOString(),
  };
}

function scaffoldIntegerOverflow(finding: Finding): ValidationScenario {
  return {
    schemaVersion: VALIDATION_SCHEMA_VERSION,
    id: makeScenarioId(finding),
    title: `Integer overflow/underflow scaffold: ${path.basename(finding.file)} L${finding.line}`,
    description:
      `Scaffold for finding ${finding.id}. ` +
      `Supply bytecode compiled with solc < 0.8.0 (no checked arithmetic). ` +
      `The scenario attempts to trigger overflow by passing boundary values.`,
    findingId: finding.id,
    findingFile: finding.file,
    findingLine: finding.line,
    chain: { chainId: 31337 },
    accounts: SCAFFOLD_ACCOUNTS,
    contracts: [
      {
        name: "VulnerableContract",
        bytecode: "0x",
        abi: "[]",
        deployer: "deployer",
      },
    ],
    calls: [
      {
        to: "VulnerableContract",
        signature: "transfer(address,uint256)",
        args: ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
        from: "attacker",
        description: "Transfer uint256.MAX to trigger overflow",
      },
    ],
    expectedOutcome: "exploit-succeeds",
    tags: ["overflow", "CP-101", "SWC-101"],
    createdAt: new Date().toISOString(),
  };
}

function scaffoldUncheckedReturn(finding: Finding): ValidationScenario {
  return {
    schemaVersion: VALIDATION_SCHEMA_VERSION,
    id: makeScenarioId(finding),
    title: `Unchecked call return value scaffold: ${path.basename(finding.file)} L${finding.line}`,
    description:
      `Scaffold for finding ${finding.id}. ` +
      `Demonstrates that the contract continues execution even when the low-level ` +
      `call fails (returns false). The calling contract must NOT revert on failure.`,
    findingId: finding.id,
    findingFile: finding.file,
    findingLine: finding.line,
    chain: { chainId: 31337 },
    accounts: SCAFFOLD_ACCOUNTS,
    contracts: [
      {
        name: "VulnerableContract",
        bytecode: "0x",
        abi: "[]",
        deployer: "deployer",
      },
      {
        name: "AlwaysRevertingTarget",
        // Minimal contract: PUSH1 0x00 DUP1 REVERT
        bytecode: "0x600060006000600060006000fa",
        abi: "[]",
        deployer: "deployer",
      },
    ],
    calls: [
      {
        to: "VulnerableContract",
        signature: "sendEther(address)",
        args: ["AlwaysRevertingTarget"],
        from: "attacker",
        description: "Trigger the unchecked send to a reverting contract",
        expectRevert: false,
      },
    ],
    expectedOutcome: "exploit-succeeds",
    tags: ["unchecked-return", "CP-104", "SWC-104"],
    createdAt: new Date().toISOString(),
  };
}

function scaffoldVaultInflation(finding: Finding): ValidationScenario {
  return {
    schemaVersion: VALIDATION_SCHEMA_VERSION,
    id: makeScenarioId(finding),
    title: `Vault share-price inflation scaffold: ${path.basename(finding.file)} L${finding.line}`,
    description:
      `Scaffold for finding ${finding.id} (ERC-4626-style share inflation). ` +
      `The attacker mints a tiny share count, then donates to inflate the price-per-share, ` +
      `forcing the next depositor's shares to round to zero.`,
    findingId: finding.id,
    findingFile: finding.file,
    findingLine: finding.line,
    chain: { chainId: 31337 },
    accounts: SCAFFOLD_ACCOUNTS,
    contracts: [
      {
        name: "VulnerableVault",
        bytecode: "0x",
        abi: "[]",
        deployer: "deployer",
      },
      {
        name: "UnderlyingToken",
        bytecode: "0x",
        abi: "[]",
        deployer: "deployer",
      },
    ],
    calls: [
      {
        to: "UnderlyingToken",
        signature: "approve(address,uint256)",
        args: ["VulnerableVault", "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
        from: "attacker",
        description: "Attacker approves vault to spend unlimited tokens",
      },
      {
        to: "VulnerableVault",
        signature: "deposit(uint256,address)",
        args: [1, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"],
        from: "attacker",
        description: "Attacker deposits 1 wei to get first shares",
      },
      {
        to: "UnderlyingToken",
        signature: "transfer(address,uint256)",
        args: ["VulnerableVault", "1000000000000000000"],
        from: "attacker",
        description: "Attacker donates 1 ETH worth of tokens directly to inflate price-per-share",
      },
      {
        to: "VulnerableVault",
        signature: "deposit(uint256,address)",
        args: ["500000000000000000", "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"],
        from: "victim",
        description: "Victim deposits 0.5 ETH worth — rounds to 0 shares",
      },
    ],
    expectedOutcome: "exploit-succeeds",
    tags: ["vault-inflation", "CP-122", "erc4626"],
    createdAt: new Date().toISOString(),
  };
}

function scaffoldCallbackCEI(finding: Finding): ValidationScenario {
  return {
    schemaVersion: VALIDATION_SCHEMA_VERSION,
    id: makeScenarioId(finding),
    title: `Callback CEI violation scaffold: ${path.basename(finding.file)} L${finding.line}`,
    description:
      `Scaffold for finding ${finding.id}. ` +
      `A callback (ERC-721/1155/777/3156) is fired before state is finalized, ` +
      `allowing a malicious receiver to re-enter with stale state. ` +
      `Supply MaliciousReceiver bytecode that re-enters during the callback.`,
    findingId: finding.id,
    findingFile: finding.file,
    findingLine: finding.line,
    chain: { chainId: 31337 },
    accounts: SCAFFOLD_ACCOUNTS,
    contracts: [
      {
        name: "VulnerableContract",
        bytecode: "0x",
        abi: "[]",
        deployer: "deployer",
      },
      {
        name: "MaliciousReceiver",
        bytecode: "0x",
        abi: "[]",
        deployer: "attacker",
      },
    ],
    calls: [
      {
        to: "VulnerableContract",
        signature: "safeMint(address,uint256)",
        args: ["MaliciousReceiver", 1],
        from: "attacker",
        description: "Trigger mint → callback → re-entry exploit chain",
      },
    ],
    expectedOutcome: "exploit-succeeds",
    tags: ["callback-reentrancy", "CP-CB-CEI"],
    createdAt: new Date().toISOString(),
  };
}

function scaffoldCallbackSpoof(finding: Finding): ValidationScenario {
  return {
    schemaVersion: VALIDATION_SCHEMA_VERSION,
    id: makeScenarioId(finding),
    title: `Callback spoofing scaffold: ${path.basename(finding.file)} L${finding.line}`,
    description:
      `Scaffold for finding ${finding.id}. ` +
      `A receiver hook function lacks msg.sender validation, allowing anyone to ` +
      `call it directly and trigger state changes as if a legitimate transfer occurred.`,
    findingId: finding.id,
    findingFile: finding.file,
    findingLine: finding.line,
    chain: { chainId: 31337 },
    accounts: SCAFFOLD_ACCOUNTS,
    contracts: [
      {
        name: "VulnerableContract",
        bytecode: "0x",
        abi: "[]",
        deployer: "deployer",
      },
    ],
    calls: [
      {
        to: "VulnerableContract",
        signature: "onERC721Received(address,address,uint256,bytes)",
        args: [
          "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
          "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
          1,
          "0x",
        ],
        from: "attacker",
        description: "Attacker directly calls the unguarded hook to spoof a transfer",
      },
    ],
    expectedOutcome: "exploit-succeeds",
    tags: ["callback-spoof", "CP-CB-SPOOF"],
    createdAt: new Date().toISOString(),
  };
}

// ─── Dispatcher ───────────────────────────────────────────────────────────────

function scaffoldFinding(finding: Finding): ValidationScenario | null {
  const id = finding.id;
  if (id === "CP-107" || id === "SWC-107" || id === "CP-107-X") {
    return scaffoldReentrancy(finding);
  }
  if (id === "CP-115" || id === "SWC-115") {
    return scaffoldTxOrigin(finding);
  }
  if (id === "CP-101" || id === "SWC-101") {
    return scaffoldIntegerOverflow(finding);
  }
  if (id === "CP-104" || id === "SWC-104") {
    return scaffoldUncheckedReturn(finding);
  }
  if (id === "CP-122") {
    return scaffoldVaultInflation(finding);
  }
  if (id === "CP-CB-CEI" || id === "CP-CB-CROSSFN" || id === "CP-CB-READONLY") {
    return scaffoldCallbackCEI(finding);
  }
  if (id === "CP-CB-SPOOF") {
    return scaffoldCallbackSpoof(finding);
  }
  if (id === "CP-CB-BATCH") {
    // Batch callback DoS — just note it's not executable without a real contract
    return {
      schemaVersion: VALIDATION_SCHEMA_VERSION,
      id: makeScenarioId(finding),
      title: `Unbounded batch callback DoS scaffold: ${path.basename(finding.file)} L${finding.line}`,
      description:
        `Scaffold for finding ${finding.id}. ` +
        `Supply the contract bytecode and a very large array to demonstrate gas exhaustion.`,
      findingId: finding.id,
      findingFile: finding.file,
      findingLine: finding.line,
      chain: { chainId: 31337 },
      accounts: SCAFFOLD_ACCOUNTS,
      contracts: [{ name: "VulnerableContract", bytecode: "0x", abi: "[]", deployer: "deployer" }],
      calls: [
        {
          to: "VulnerableContract",
          signature: "batchMint(address[],uint256[])",
          args: [
            Array.from({ length: 1000 }, () => "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
            Array.from({ length: 1000 }, (_, i) => i + 1),
          ],
          from: "attacker",
          description: "Send 1000-element array to trigger unbounded gas usage",
          gasLimit: 30_000_000,
        },
      ],
      expectedOutcome: "exploit-reverts",
      outcomeDescription: "Call should run out of gas or hit block gas limit",
      tags: ["dos", "CP-CB-BATCH"],
      createdAt: new Date().toISOString(),
    };
  }
  return null;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/** Options for `planValidation`. */
export interface PlanValidationOptions {
  /**
   * If true, generate one scenario per unique (findingId, file, line) triple.
   * If false (default), deduplicate findings with the same ID and file.
   */
  deduplicateByFile?: boolean;
  /**
   * Only include findings with severity at or above this level.
   * Defaults to "low" (all except gas).
   */
  minSeverity?: "critical" | "high" | "medium" | "low" | "info";
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1, gas: 0,
};

/**
 * Build a {@link ValidationPlan} from an array of static findings.
 *
 * This is the main entry point for the `chainproof validate plan` command.
 */
export function planValidation(
  findings: Finding[],
  opts: PlanValidationOptions = {},
): ValidationPlan {
  const minRank = SEVERITY_RANK[opts.minSeverity ?? "low"] ?? 2;
  const eligible = findings.filter(
    (f) =>
      (SEVERITY_RANK[f.severity] ?? 0) >= minRank &&
      f.severity !== "gas" &&
      !f.id.startsWith("GAS-"),
  );

  const seen = new Set<string>();
  const scenarios: ValidationScenario[] = [];
  const unsupported: UnsupportedFinding[] = [];

  for (const finding of eligible) {
    const key = opts.deduplicateByFile
      ? `${finding.id}|${finding.file}|${finding.line}`
      : `${finding.id}|${finding.file}`;

    if (seen.has(key)) continue;
    seen.add(key);

    if (!SUPPORTED_FINDING_IDS.has(finding.id)) {
      // Check if it's a Slither finding with a known mapping
      if (!finding.id.startsWith("CP-") && !finding.id.startsWith("SWC-")) {
        unsupported.push({
          findingId: finding.id,
          findingFile: finding.file,
          findingLine: finding.line,
          reason: `Finding ID "${finding.id}" is not in the supported scaffold set. ` +
            `Supported IDs: ${[...SUPPORTED_FINDING_IDS].join(", ")}.`,
        });
        continue;
      }
    }

    const scenario = scaffoldFinding(finding);
    if (scenario) {
      scenarios.push(scenario);
    } else {
      unsupported.push({
        findingId: finding.id,
        findingFile: finding.file,
        findingLine: finding.line,
        reason: `No scaffold template for finding ID "${finding.id}".`,
      });
    }
  }

  return {
    schemaVersion: VALIDATION_SCHEMA_VERSION,
    scenarios,
    unsupportedFindings: unsupported,
    createdAt: new Date().toISOString(),
  };
}

/**
 * Serialize a {@link ValidationPlan} to JSON (deterministic key order).
 */
export function serializeValidationPlan(plan: ValidationPlan): string {
  return JSON.stringify(plan, null, 2);
}

/**
 * Parse and validate a {@link ValidationPlan} from a JSON string.
 * Throws {@link CorruptBundleError} on schema mismatch.
 */
export function parseValidationPlan(json: string, filePath = "<string>"): ValidationPlan {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (err) {
    throw new CorruptBundleError(filePath, "Invalid JSON");
  }
  const obj = parsed as Record<string, unknown>;
  if (!obj || typeof obj !== "object") {
    throw new CorruptBundleError(filePath, "Root must be an object");
  }
  if (typeof obj["schemaVersion"] !== "string") {
    throw new CorruptBundleError(filePath, "Missing schemaVersion");
  }
  if (!Array.isArray(obj["scenarios"])) {
    throw new CorruptBundleError(filePath, "Missing scenarios array");
  }
  return obj as unknown as ValidationPlan;
}
