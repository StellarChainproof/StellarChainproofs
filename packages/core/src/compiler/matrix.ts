/**
 * @packageDocumentation
 * @chainproof/core — Supported Compiler Matrix, Capabilities & Codegen Hazard Database
 */

import type {
  CompilerFamily,
  CompilerVersionMetadata,
  CompilerCapabilities,
  CompilerCodegenHazard,
} from "./types";
import {
  parseSemVer,
  compareSemVer,
  satisfiesSemVer,
  sortSemVerList,
} from "./semver";

// ─── EVM Version Constants ───────────────────────────────────────────────────

export const EVM_VERSIONS = [
  "homestead",
  "tangerineWhistle",
  "spuriousDragon",
  "byzantium",
  "constantinople",
  "petersburg",
  "istanbul",
  "berlin",
  "london",
  "paris",
  "shanghai",
  "cancun",
  "prague",
] as const;

export type EVMVersion = (typeof EVM_VERSIONS)[number];

// ─── Known Compiler Codegen Hazards Database ─────────────────────────────────

export const SOL_CODEGEN_BUGS: readonly CompilerCodegenHazard[] = [
  {
    id: "SOL-BUG-2024-1",
    name: "TransientStorageDataCorruption",
    minVersion: "0.8.24",
    maxVersion: "0.8.25",
    affectedVersionsDescription: "0.8.24 - 0.8.25",
    severity: "critical",
    conditions: [
      "Uses transient storage (tstore/tload) in inline assembly or transient state variables",
      "Compiles with viaIR enabled or complex control flow",
    ],
    description:
      "A bug in the Solidity code generator for transient storage can cause improper memory and storage layout optimization, leading to silent state corruption across function calls.",
    recommendation:
      "Upgrade compiler to Solidity >=0.8.26 or avoid transient storage operations in 0.8.24-0.8.25.",
    link: "https://soliditylang.org/blog/2024/05/21/solidity-0.8.26-release-announcement/",
  },
  {
    id: "SOL-BUG-2023-1",
    name: "Push0EVMCompatibilityHazard",
    minVersion: "0.8.20",
    maxVersion: "0.8.28",
    affectedVersionsDescription: ">=0.8.20 (default EVM: shanghai+)",
    severity: "high",
    conditions: [
      "Default EVM version is shanghai or cancun",
      "Deploying to L2 networks or sidechains lacking the PUSH0 (0x5f) opcode (e.g., earlier Arbitrum, Polygon PoS, BNB Chain, Optimism configurations)",
    ],
    description:
      "Solidity 0.8.20+ defaults to the Shanghai EVM target which emits the PUSH0 opcode. Deploying bytecode containing PUSH0 to chains without Shanghai EVM support causes deployment or transaction reverts with invalid opcode.",
    recommendation:
      "Explicitly set evmVersion to 'paris' or 'london' in compiler settings if deploying to non-Shanghai EVM chains.",
    link: "https://soliditylang.org/blog/2023/05/10/solidity-0.8.20-release-announcement/",
  },
  {
    id: "SOL-BUG-2022-7",
    name: "SignedImmutablesBug",
    minVersion: "0.6.5",
    maxVersion: "0.8.8",
    affectedVersionsDescription: "0.6.5 - 0.8.8",
    severity: "medium",
    conditions: [
      "Uses signed integer immutable variables (int8 to int248) with negative values",
    ],
    description:
      "Signed immutable variables narrower than 256 bits with negative values may be sign-extended improperly when loaded, returning corrupted positive values.",
    recommendation:
      "Upgrade to Solidity >=0.8.9 or use int256 for immutable signed values.",
    link: "https://soliditylang.org/blog/2021/09/29/signed-immutables-bug/",
  },
  {
    id: "SOL-BUG-2022-6",
    name: "HeadOverflowCalldataTupleDecoder",
    minVersion: "0.5.8",
    maxVersion: "0.8.15",
    affectedVersionsDescription: "0.5.8 - 0.8.15 (ABI coder v2)",
    severity: "medium",
    conditions: [
      "Uses ABI coder v2 with calldata tuples containing dynamic types or array slices",
    ],
    description:
      "Calldata tuple decoding in ABI coder v2 can miscalculate head offsets when decoding nested dynamic elements near the end of calldata, resulting in invalid memory offsets.",
    recommendation:
      "Upgrade compiler to Solidity >=0.8.16 or use memory parameters instead of calldata tuples.",
    link: "https://soliditylang.org/blog/2022/08/08/calldata-tuple-reencoding-head-overflow-bug/",
  },
  {
    id: "SOL-BUG-2022-4",
    name: "InlineAssemblyMemorySideEffects",
    minVersion: "0.8.13",
    maxVersion: "0.8.14",
    affectedVersionsDescription: "0.8.13 - 0.8.14 (Yul optimizer enabled)",
    severity: "high",
    conditions: [
      "Uses inline assembly that modifies memory without memory-safe annotations",
      "Yul optimizer enabled (viaIR: true)",
    ],
    description:
      "The Yul optimizer may reorder or remove memory operations across inline assembly blocks that do not specify memory safety annotations.",
    recommendation:
      "Upgrade to Solidity >=0.8.15 or disable Yul optimizer in affected versions.",
    link: "https://soliditylang.org/blog/2022/06/15/solidity-0.8.15-release-announcement/",
  },
  {
    id: "SOL-BUG-2022-1",
    name: "NestedCalldataArrayEncoding",
    minVersion: "0.5.8",
    maxVersion: "0.8.13",
    affectedVersionsDescription: "0.5.8 - 0.8.13 (ABI coder v2)",
    severity: "medium",
    conditions: [
      "Passes nested dynamic arrays or structs from calldata directly to abi.encode or external calls",
    ],
    description:
      "Nested dynamic array and slice encoding from calldata can result in incorrect length prefixes or corrupted elements in ABI encoder v2.",
    recommendation:
      "Upgrade to Solidity >=0.8.14 or copy calldata arrays to memory before encoding.",
    link: "https://soliditylang.org/blog/2022/05/17/calldata-reencode-size-check-bug/",
  },
  {
    id: "SOL-BUG-2021-3",
    name: "DirtyBytesArrayToStorage",
    minVersion: "0.0.1",
    maxVersion: "0.8.6",
    affectedVersionsDescription: "<=0.8.6",
    severity: "high",
    conditions: [
      "Copies bytes or string from memory or calldata to storage using direct assignment",
      "Source data has non-zero dirty bits beyond its logical length",
    ],
    description:
      "Direct copying of bytes arrays to storage does not clean dirty higher-order bits in the final 32-byte storage slot, leading to unexpected values when reading packed data.",
    recommendation:
      "Upgrade compiler to Solidity >=0.8.7 or manually sanitize byte buffers.",
    link: "https://soliditylang.org/blog/2021/08/11/dirty-bytes-array-to-storage-bug/",
  },
  {
    id: "SOL-BUG-2021-1",
    name: "DynamicArrayCleanup",
    minVersion: "0.0.1",
    maxVersion: "0.7.2",
    affectedVersionsDescription: "<=0.7.2",
    severity: "medium",
    conditions: [
      "Assigns an empty dynamic array to a storage dynamic array or uses delete on storage arrays of value types",
    ],
    description:
      "Clearing a storage dynamic array does not properly zero out dangling storage slots beyond the new length, which can be resurrected if the array grows again.",
    recommendation:
      "Upgrade to Solidity >=0.7.3 or >=0.8.0, or explicitly zero each slot before clearing.",
    link: "https://soliditylang.org/blog/2020/10/07/solidity-0.7.3-release-announcement/",
  },
  {
    id: "SOL-BUG-2020-5",
    name: "EmptyStringLiteralStorage",
    minVersion: "0.5.14",
    maxVersion: "0.6.7",
    affectedVersionsDescription: "0.5.14 - 0.6.7",
    severity: "low",
    conditions: [
      "Assigns empty string literal '' or hex'' to a storage string/bytes variable",
    ],
    description:
      "Assigning empty string literal to storage variable does not properly clear previously stored data in storage.",
    recommendation: "Upgrade to Solidity >=0.6.8 or >=0.8.0.",
  },
  {
    id: "SOL-BUG-2020-3",
    name: "MemoryArrayCreationOverflow",
    minVersion: "0.6.5",
    maxVersion: "0.6.8",
    affectedVersionsDescription: "0.6.5 - 0.6.8",
    severity: "high",
    conditions: [
      "Creates memory array with user-controlled length expression: new uint256[](length)",
    ],
    description:
      "Large array length in new T[](length) can overflow 256-bit memory allocation calculation without reverting, leading to memory corruption.",
    recommendation: "Upgrade to Solidity >=0.6.9 or >=0.8.0.",
  },
  {
    id: "SOL-BUG-2019-1",
    name: "StorageArrayPacking",
    minVersion: "0.4.0",
    maxVersion: "0.5.9",
    affectedVersionsDescription: "0.4.0 - 0.5.9",
    severity: "medium",
    conditions: [
      "Uses arrays of packed small integer/boolean types in storage (e.g. uint128[], bool[])",
    ],
    description:
      "Storage packing for dynamic arrays of types smaller than 256 bits does not properly clear trailing bits in modified slots.",
    recommendation: "Upgrade to Solidity >=0.5.10 or >=0.8.0.",
  },
  {
    id: "SOL-BUG-2018-2",
    name: "ConstructorCallParameters",
    minVersion: "0.4.22",
    maxVersion: "0.4.24",
    affectedVersionsDescription: "0.4.22 - 0.4.24",
    severity: "high",
    conditions: [
      "Inherits base contract with constructor parameters passed in inheritance specifier",
    ],
    description:
      "Constructor parameters passed in base contract inheritance specifier may be evaluated in incorrect order or skipped when unreferenced.",
    recommendation: "Upgrade to Solidity >=0.4.25 or >=0.8.0.",
  },
  {
    id: "SOL-BUG-2018-1",
    name: "ZeroFunctionSelector",
    minVersion: "0.4.16",
    maxVersion: "0.4.24",
    affectedVersionsDescription: "0.4.16 - 0.4.24",
    severity: "medium",
    conditions: [
      "Contract declares a function whose 4-byte selector computes to 0x00000000",
    ],
    description:
      "Functions with selector 0x00000000 could be invoked unintentionally on empty calldata.",
    recommendation: "Upgrade to Solidity >=0.4.25 or >=0.8.0.",
  },
];

// ─── Breaking Syntax & Semantic Changes Registry ──────────────────────────────

export interface BreakingChangeEntry {
  fromFamily: CompilerFamily;
  toFamily: CompilerFamily;
  summary: string;
  details: string[];
  impactOnAudit: string;
}

export const BREAKING_CHANGES_REGISTRY: readonly BreakingChangeEntry[] = [
  {
    fromFamily: "0.4",
    toFamily: "0.5",
    summary: "Explicit data locations, constructor keyword, and explicit payable addresses",
    details: [
      "constructor keyword required instead of function with contract name",
      "Explicit data location (memory/storage/calldata) required for all struct, array, and mapping variables",
      "address payable distinguished from regular address; address.transfer/send require payable",
      "emit keyword required for event emission",
      "view/pure mutability enforced strictly; unassigned constant variables disallowed",
      "fallback function cannot return values",
    ],
    impactOnAudit:
      "0.4 contracts often miss explicit data locations leading to storage pointer corruption risks.",
  },
  {
    fromFamily: "0.5",
    toFamily: "0.6",
    summary: "Receive/fallback function split, virtual/override keywords, and try/catch",
    details: [
      "fallback() and receive() external payable split into separate functions",
      "virtual and override keywords required for polymorphism and inherited function overrides",
      "abstract contract keyword required for contracts with unimplemented functions",
      "array.push() no longer returns new length",
      "try / catch error handling introduced",
      "immutable state variable keyword introduced in 0.6.5",
    ],
    impactOnAudit:
      "0.5 contracts lacking virtual/override can have unintended function shadowing or hidden overriding.",
  },
  {
    fromFamily: "0.6",
    toFamily: "0.7",
    summary: "State variable visibility required, exponentiation precedence, and now keyword removal",
    details: [
      "State variable visibility defaults removed; must explicitly specify public, internal, or private",
      "now keyword deprecated and removed in favor of block.timestamp",
      "Exponentiation ** operator precedence changed to bind more tightly than unary operators",
      "Shift operations with negative values or shift amounts >= 256 revert or are disallowed",
      "Function definitions in interfaces must be external",
    ],
    impactOnAudit:
      "Implicit visibility in <0.7 could accidentally expose sensitive state variables as public.",
  },
  {
    fromFamily: "0.7",
    toFamily: "0.8",
    summary: "Built-in checked arithmetic, ABI coder v2 default, and custom errors (0.8.4+)",
    details: [
      "Arithmetic operations revert on overflow/underflow by default; unchecked { ... } required for legacy wrapping",
      "ABI coder v2 enabled by default for all contracts",
      "Explicit type conversions required (e.g. uint160 to address requires explicit cast)",
      "byte type removed in favor of bytes1",
      "Custom errors with revert CustomError(...) introduced in 0.8.4",
      "User defined value types introduced in 0.8.8",
      "PUSH0 opcode emitted by default in 0.8.20+ with Shanghai EVM target",
      "Transient storage (tstore/tload) introduced in 0.8.24",
    ],
    impactOnAudit:
      "Arithmetic overflow detector (SWC-101) is critical for <0.8.0 without SafeMath, but low/info for >=0.8.0 unless inside unchecked blocks.",
  },
];

// ─── Supported Solidity Compiler Releases ─────────────────────────────────────

function buildCapabilities(version: string): CompilerCapabilities {
  const v = parseSemVer(version);
  if (!v) {
    throw new Error(`Cannot parse compiler version: ${version}`);
  }

  const gte = (target: string) => compareSemVer(v, target) >= 0;

  let abiEncoderV2: CompilerCapabilities["abiEncoderV2"] = "unsupported";
  if (gte("0.8.0")) {
    abiEncoderV2 = "default";
  } else if (gte("0.4.19")) {
    abiEncoderV2 = "experimental";
  }

  return {
    checkedArithmetic: gte("0.8.0"),
    customErrors: gte("0.8.4"),
    userDefinedValueTypes: gte("0.8.8"),
    transientStorage: gte("0.8.24"),
    push0Opcode: gte("0.8.20"),
    viaIR: gte("0.7.5"),
    immutableVariables: gte("0.6.5"),
    tryCatch: gte("0.6.0"),
    receiveFallbackSplit: gte("0.6.0"),
    abiEncoderV2,
    calldataParameters: gte("0.5.0"),
    constructorKeyword: gte("0.4.22"),
    storageLayoutOutput: gte("0.5.13"),
    yulOptimizer: gte("0.6.0"),
    payableExplicitAddress: gte("0.5.0"),
    virtualOverrideKeywords: gte("0.6.0"),
    globalImports: gte("0.8.13"),
  };
}

export function determineDefaultEvm(version: string): string {
  const v = parseSemVer(version);
  if (!v) return "paris";

  if (compareSemVer(v, "0.8.25") >= 0) return "cancun";
  if (compareSemVer(v, "0.8.20") >= 0) return "shanghai";
  if (compareSemVer(v, "0.8.18") >= 0) return "paris";
  if (compareSemVer(v, "0.8.7") >= 0) return "london";
  if (compareSemVer(v, "0.8.5") >= 0) return "berlin";
  if (compareSemVer(v, "0.5.14") >= 0) return "istanbul";
  if (compareSemVer(v, "0.5.5") >= 0) return "petersburg";
  if (compareSemVer(v, "0.4.21") >= 0) return "byzantium";
  return "homestead";
}

export function determineFamily(version: string): CompilerFamily {
  const v = parseSemVer(version);
  if (!v) return "0.8";
  if (v.major === 0) {
    if (v.minor === 4) return "0.4";
    if (v.minor === 5) return "0.5";
    if (v.minor === 6) return "0.6";
    if (v.minor === 7) return "0.7";
    if (v.minor === 8) return "0.8";
  }
  return "0.8";
}

// Full supported compiler release matrix
const RAW_SUPPORTED_RELEASES: { version: string; releaseDate: string; isStable?: boolean; isPrerelease?: boolean; isDeprecated?: boolean }[] = [
  // 0.4 family
  { version: "0.4.11", releaseDate: "2017-05-03", isDeprecated: true },
  { version: "0.4.18", releaseDate: "2017-10-18", isDeprecated: true },
  { version: "0.4.24", releaseDate: "2018-05-16", isDeprecated: true },
  { version: "0.4.26", releaseDate: "2019-04-18", isDeprecated: true },
  // 0.5 family
  { version: "0.5.0", releaseDate: "2018-11-13", isDeprecated: true },
  { version: "0.5.8", releaseDate: "2019-04-29", isDeprecated: true },
  { version: "0.5.10", releaseDate: "2019-06-25", isDeprecated: true },
  { version: "0.5.16", releaseDate: "2020-01-29", isDeprecated: true },
  { version: "0.5.17", releaseDate: "2020-03-16", isDeprecated: true },
  // 0.6 family
  { version: "0.6.0", releaseDate: "2019-12-17", isDeprecated: true },
  { version: "0.6.6", releaseDate: "2020-04-06", isDeprecated: true },
  { version: "0.6.12", releaseDate: "2020-07-07", isDeprecated: true },
  // 0.7 family
  { version: "0.7.0", releaseDate: "2020-07-28", isDeprecated: true },
  { version: "0.7.4", releaseDate: "2020-10-21", isDeprecated: true },
  { version: "0.7.6", releaseDate: "2021-01-14", isDeprecated: true },
  // 0.8 family (active)
  { version: "0.8.0", releaseDate: "2020-12-16", isStable: true },
  { version: "0.8.4", releaseDate: "2021-04-21", isStable: true },
  { version: "0.8.7", releaseDate: "2021-08-11", isStable: true },
  { version: "0.8.9", releaseDate: "2021-09-29", isStable: true },
  { version: "0.8.13", releaseDate: "2022-03-16", isStable: true },
  { version: "0.8.15", releaseDate: "2022-08-08", isStable: true },
  { version: "0.8.17", releaseDate: "2022-09-08", isStable: true },
  { version: "0.8.19", releaseDate: "2023-02-22", isStable: true },
  { version: "0.8.20", releaseDate: "2023-05-10", isStable: true },
  { version: "0.8.21", releaseDate: "2023-07-19", isStable: true },
  { version: "0.8.23", releaseDate: "2023-11-08", isStable: true },
  { version: "0.8.24", releaseDate: "2024-01-26", isStable: true },
  { version: "0.8.25", releaseDate: "2024-03-13", isStable: true },
  { version: "0.8.26", releaseDate: "2024-05-21", isStable: true },
  { version: "0.8.27", releaseDate: "2024-09-04", isStable: true },
  { version: "0.8.28", releaseDate: "2024-10-09", isStable: true },
];

export const SUPPORTED_SOLC_METADATA: Record<string, CompilerVersionMetadata> = {};

for (const rel of RAW_SUPPORTED_RELEASES) {
  const family = determineFamily(rel.version);
  const defaultEvm = determineDefaultEvm(rel.version);
  const capabilities = buildCapabilities(rel.version);

  SUPPORTED_SOLC_METADATA[rel.version] = {
    version: rel.version,
    family,
    releaseDate: rel.releaseDate,
    defaultEvmVersion: defaultEvm,
    supportedEvmVersions: [...EVM_VERSIONS],
    isStable: rel.isStable ?? false,
    isPrerelease: rel.isPrerelease ?? false,
    isDeprecated: rel.isDeprecated ?? false,
    capabilities,
  };
}

export const ALL_SUPPORTED_VERSIONS: readonly string[] = Object.keys(SUPPORTED_SOLC_METADATA);

// Default recommended version for modern deployments
export const RECOMMENDED_SOLC_VERSION = "0.8.28";

// Standard LTS / Milestone versions for matrix runs
export const MILESTONE_COMPILER_VERSIONS: readonly string[] = [
  "0.4.24",
  "0.4.26",
  "0.5.16",
  "0.6.12",
  "0.7.6",
  "0.8.0",
  "0.8.4",
  "0.8.13",
  "0.8.19",
  "0.8.20",
  "0.8.24",
  "0.8.28",
];

// ─── Query Functions ─────────────────────────────────────────────────────────

export function getSupportedCompilerVersions(): string[] {
  return [...ALL_SUPPORTED_VERSIONS];
}

export function getCompilerVersionMetadata(version: string): CompilerVersionMetadata | null {
  const direct = SUPPORTED_SOLC_METADATA[version];
  if (direct) return direct;

  const parsed = parseSemVer(version);
  if (!parsed) return null;

  const key = `${parsed.major}.${parsed.minor}.${parsed.patch}`;
  if (SUPPORTED_SOLC_METADATA[key]) {
    return SUPPORTED_SOLC_METADATA[key];
  }

  // Synthesize metadata for unlisted / custom version
  return {
    version: key,
    family: determineFamily(key),
    releaseDate: "custom",
    defaultEvmVersion: determineDefaultEvm(key),
    supportedEvmVersions: [...EVM_VERSIONS],
    isStable: parsed.major === 0 && parsed.minor === 8,
    isPrerelease: parsed.prerelease.length > 0,
    isDeprecated: parsed.major === 0 && parsed.minor < 8,
    capabilities: buildCapabilities(key),
  };
}

export function isVersionSupported(version: string): boolean {
  const meta = getCompilerVersionMetadata(version);
  return meta !== null;
}

/**
 * Returns all breaking changes between two compiler versions.
 */
export function getBreakingChangesBetween(
  fromVersion: string,
  toVersion: string,
): BreakingChangeEntry[] {
  const fromMeta = getCompilerVersionMetadata(fromVersion);
  const toMeta = getCompilerVersionMetadata(toVersion);

  if (!fromMeta || !toMeta) return [];

  const fromV = parseSemVer(fromVersion)!;
  const toV = parseSemVer(toVersion)!;

  const order = compareSemVer(fromV, toV);
  if (order === 0) return [];

  const [lowerFamily, higherFamily] =
    order < 0
      ? [fromMeta.family, toMeta.family]
      : [toMeta.family, fromMeta.family];

  if (lowerFamily === higherFamily) return [];

  const familyOrder: CompilerFamily[] = ["0.4", "0.5", "0.6", "0.7", "0.8"];
  const lowIdx = familyOrder.indexOf(lowerFamily);
  const highIdx = familyOrder.indexOf(higherFamily);

  const changes: BreakingChangeEntry[] = [];
  for (let i = lowIdx; i < highIdx; i++) {
    const f1 = familyOrder[i];
    const f2 = familyOrder[i + 1];
    const match = BREAKING_CHANGES_REGISTRY.find(
      (b) => b.fromFamily === f1 && b.toFamily === f2,
    );
    if (match) {
      changes.push(match);
    }
  }

  return changes;
}

/**
 * Returns known compiler code-generation bugs active for a specific compiler version.
 */
export function getHazardsForVersion(
  version: string,
  options?: {
    hasTransientStorage?: boolean;
    hasInlineAssembly?: boolean;
    targetEvmLacksPush0?: boolean;
    usesSignedImmutables?: boolean;
    usesCalldataTuples?: boolean;
  },
): CompilerCodegenHazard[] {
  const parsed = parseSemVer(version);
  if (!parsed) return [];

  const hazards: CompilerCodegenHazard[] = [];

  for (const bug of SOL_CODEGEN_BUGS) {
    const inRange =
      compareSemVer(parsed, bug.minVersion) >= 0 &&
      compareSemVer(parsed, bug.maxVersion) <= 0;

    if (!inRange) continue;

    // Filter by specific source conditions if provided
    if (bug.id === "SOL-BUG-2024-1" && !options?.hasTransientStorage) {
      continue;
    }
    if (bug.id === "SOL-BUG-2023-1" && !options?.targetEvmLacksPush0) {
      continue;
    }
    if (options) {
      if (bug.id === "SOL-BUG-2022-7" && options.usesSignedImmutables === false) {
        continue;
      }
      if (bug.id === "SOL-BUG-2022-6" && options.usesCalldataTuples === false) {
        continue;
      }
    }

    hazards.push(bug);
  }

  return hazards;
}

/**
 * Returns all supported compiler versions satisfying a SemVer range string.
 */
export function getCompatibleCompilerVersions(rangeStr: string): string[] {
  const versions = getSupportedCompilerVersions();
  return versions.filter((v) => satisfiesSemVer(v, rangeStr));
}

/**
 * Chooses the recommended compiler version satisfying a SemVer range.
 * Defaults to the highest stable 0.8.x version matching the range.
 */
export function getRecommendedCompilerVersion(rangeStr: string): string | undefined {
  const compatible = getCompatibleCompilerVersions(rangeStr);
  if (compatible.length === 0) return undefined;

  const sorted = sortSemVerList(compatible, "desc");
  // Prefer modern stable 0.8 versions
  const stable08 = sorted.find((v) => v.startsWith("0.8.") && compareSemVer(v, "0.8.20") >= 0);
  if (stable08) return stable08;

  return sorted[0];
}
