/**
 * @packageDocumentation
 * @chainproof/core — Pure, Zero-Dependency Semantic Versioning & Solidity Range Solver
 */

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
  build: string[];
  raw: string;
}

export type ComparatorOperator = "=" | ">" | ">=" | "<" | "<=" | "!=";

export interface SingleComparator {
  operator: ComparatorOperator;
  version: SemVer;
  raw: string;
}

export type ComparatorSet = SingleComparator[]; // AND logic

export interface SemVerRange {
  raw: string;
  set: ComparatorSet[]; // OR logic: (A AND B) OR (C AND D)
}

const SEMVER_REGEX =
  /^[vV]?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

/**
 * Parses a string into a {@link SemVer} object. Returns null if invalid.
 */
export function parseSemVer(versionStr: string): SemVer | null {
  if (typeof versionStr !== "string") return null;
  const trimmed = versionStr.trim();
  const match = trimmed.match(SEMVER_REGEX);
  if (!match) return null;

  const major = parseInt(match[1], 10);
  const minor = parseInt(match[2], 10);
  const patch = parseInt(match[3], 10);
  const prerelease = match[4] ? match[4].split(".") : [];
  const build = match[5] ? match[5].split(".") : [];

  return {
    major,
    minor,
    patch,
    prerelease,
    build,
    raw: trimmed,
  };
}

/**
 * Formats a {@link SemVer} object back to string (major.minor.patch[-prerelease]).
 */
export function formatSemVer(v: SemVer): string {
  let result = `${v.major}.${v.minor}.${v.patch}`;
  if (v.prerelease.length > 0) {
    result += `-${v.prerelease.join(".")}`;
  }
  if (v.build.length > 0) {
    result += `+${v.build.join(".")}`;
  }
  return result;
}

function compareIdentifiers(a: string, b: string): number {
  const aNum = /^\d+$/.test(a);
  const bNum = /^\d+$/.test(b);

  if (aNum && bNum) {
    const numA = parseInt(a, 10);
    const numB = parseInt(b, 10);
    return numA < numB ? -1 : numA > numB ? 1 : 0;
  }
  if (aNum && !bNum) return -1;
  if (!aNum && bNum) return 1;

  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Compares two SemVer versions.
 * Returns -1 if a < b, 1 if a > b, and 0 if a === b.
 */
export function compareSemVer(a: SemVer | string, b: SemVer | string): number {
  const verA = typeof a === "string" ? parseSemVer(a) : a;
  const verB = typeof b === "string" ? parseSemVer(b) : b;

  if (!verA || !verB) {
    throw new Error(`Invalid SemVer comparison: "${String(a)}" vs "${String(b)}"`);
  }

  if (verA.major !== verB.major) {
    return verA.major < verB.major ? -1 : 1;
  }
  if (verA.minor !== verB.minor) {
    return verA.minor < verB.minor ? -1 : 1;
  }
  if (verA.patch !== verB.patch) {
    return verA.patch < verB.patch ? -1 : 1;
  }

  // Prerelease comparison
  if (verA.prerelease.length === 0 && verB.prerelease.length > 0) {
    return 1; // normal version is greater than prerelease
  }
  if (verA.prerelease.length > 0 && verB.prerelease.length === 0) {
    return -1;
  }
  if (verA.prerelease.length > 0 && verB.prerelease.length > 0) {
    const len = Math.min(verA.prerelease.length, verB.prerelease.length);
    for (let i = 0; i < len; i++) {
      const cmp = compareIdentifiers(verA.prerelease[i], verB.prerelease[i]);
      if (cmp !== 0) return cmp;
    }
    if (verA.prerelease.length !== verB.prerelease.length) {
      return verA.prerelease.length < verB.prerelease.length ? -1 : 1;
    }
  }

  return 0;
}

export function semverEq(a: SemVer | string, b: SemVer | string): boolean {
  return compareSemVer(a, b) === 0;
}

export function semverNeq(a: SemVer | string, b: SemVer | string): boolean {
  return compareSemVer(a, b) !== 0;
}

export function semverGt(a: SemVer | string, b: SemVer | string): boolean {
  return compareSemVer(a, b) > 0;
}

export function semverGte(a: SemVer | string, b: SemVer | string): boolean {
  return compareSemVer(a, b) >= 0;
}

export function semverLt(a: SemVer | string, b: SemVer | string): boolean {
  return compareSemVer(a, b) < 0;
}

export function semverLte(a: SemVer | string, b: SemVer | string): boolean {
  return compareSemVer(a, b) <= 0;
}

/**
 * Evaluates a single comparator against a parsed SemVer.
 */
export function testComparator(version: SemVer, comparator: SingleComparator): boolean {
  const cmp = compareSemVer(version, comparator.version);
  switch (comparator.operator) {
    case "=":
      return cmp === 0;
    case "!=":
      return cmp !== 0;
    case ">":
      return cmp > 0;
    case ">=":
      return cmp >= 0;
    case "<":
      return cmp < 0;
    case "<=":
      return cmp <= 0;
    default:
      return false;
  }
}

/**
 * Normalizes hyphen ranges (e.g. "0.4.24 - 0.8.20" -> ">=0.4.24 <=0.8.20").
 */
function normalizeHyphenRanges(rangeStr: string): string {
  const hyphenRegex =
    /([vV]?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))\s+-\s+([vV]?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))/g;
  return rangeStr.replace(hyphenRegex, ">=$1 <=$2");
}

/**
 * Expands caret ranges (e.g. "^0.8.20" -> ">=0.8.20 <0.9.0", "^0.0.3" -> ">=0.0.3 <0.0.4").
 */
function expandCaret(versionStr: string): ComparatorSet {
  const v = parseSemVer(versionStr);
  if (!v) return [];

  let upperLimit: SemVer;
  if (v.major > 0) {
    upperLimit = { major: v.major + 1, minor: 0, patch: 0, prerelease: [], build: [], raw: `${v.major + 1}.0.0` };
  } else if (v.minor > 0) {
    upperLimit = { major: 0, minor: v.minor + 1, patch: 0, prerelease: [], build: [], raw: `0.${v.minor + 1}.0` };
  } else {
    upperLimit = { major: 0, minor: 0, patch: v.patch + 1, prerelease: [], build: [], raw: `0.0.${v.patch + 1}` };
  }

  return [
    { operator: ">=", version: v, raw: `>=${formatSemVer(v)}` },
    { operator: "<", version: upperLimit, raw: `<${formatSemVer(upperLimit)}` },
  ];
}

/**
 * Expands tilde ranges (e.g. "~0.8.20" -> ">=0.8.20 <0.9.0", "~0.8" -> ">=0.8.0 <0.9.0").
 */
function expandTilde(versionStr: string): ComparatorSet {
  let v = parseSemVer(versionStr);
  if (!v) {
    // Handle ~0.8 format
    const match = versionStr.match(/^[vV]?(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
    if (match) {
      v = parseSemVer(`${match[1]}.${match[2]}.0`);
    }
  }
  if (!v) return [];

  const upperLimit: SemVer = {
    major: v.major,
    minor: v.minor + 1,
    patch: 0,
    prerelease: [],
    build: [],
    raw: `${v.major}.${v.minor + 1}.0`,
  };

  return [
    { operator: ">=", version: v, raw: `>=${formatSemVer(v)}` },
    { operator: "<", version: upperLimit, raw: `<${formatSemVer(upperLimit)}` },
  ];
}

/**
 * Expands wildcards (e.g. "0.8.x", "0.8.*", "*").
 */
function expandWildcard(token: string): ComparatorSet | null {
  const trimmed = token.trim();
  if (trimmed === "*" || trimmed === "x" || trimmed === "X" || trimmed === "") {
    return [{ operator: ">=", version: { major: 0, minor: 0, patch: 0, prerelease: [], build: [], raw: "0.0.0" }, raw: ">=0.0.0" }];
  }

  const majorWildcard = trimmed.match(/^[vV]?(0|[1-9]\d*)\.[xX*]$/);
  if (majorWildcard) {
    const major = parseInt(majorWildcard[1], 10);
    const lower: SemVer = { major, minor: 0, patch: 0, prerelease: [], build: [], raw: `${major}.0.0` };
    const upper: SemVer = { major: major + 1, minor: 0, patch: 0, prerelease: [], build: [], raw: `${major + 1}.0.0` };
    return [
      { operator: ">=", version: lower, raw: `>=${major}.0.0` },
      { operator: "<", version: upper, raw: `<${major + 1}.0.0` },
    ];
  }

  const minorWildcard = trimmed.match(/^[vV]?(0|[1-9]\d*)\.(0|[1-9]\d*)\.[xX*]$/);
  if (minorWildcard) {
    const major = parseInt(minorWildcard[1], 10);
    const minor = parseInt(minorWildcard[2], 10);
    const lower: SemVer = { major, minor, patch: 0, prerelease: [], build: [], raw: `${major}.${minor}.0` };
    const upper: SemVer = { major, minor: minor + 1, patch: 0, prerelease: [], build: [], raw: `${major}.${minor + 1}.0` };
    return [
      { operator: ">=", version: lower, raw: `>=${major}.${minor}.0` },
      { operator: "<", version: upper, raw: `<${major}.${minor + 1}.0` },
    ];
  }

  return null;
}

/**
 * Parses a single conjunction clause (e.g. ">=0.7.0 <0.9.0 !=0.8.13" or "^0.8.20").
 */
function parseConjunction(clause: string): ComparatorSet {
  const normalized = clause.trim();
  if (!normalized) return [];

  const tokens = normalized.split(/\s+/).filter(Boolean);
  const set: ComparatorSet = [];

  for (const token of tokens) {
    const wildcard = expandWildcard(token);
    if (wildcard) {
      set.push(...wildcard);
      continue;
    }

    if (token.startsWith("^")) {
      const expanded = expandCaret(token.slice(1));
      set.push(...expanded);
      continue;
    }

    if (token.startsWith("~")) {
      const expanded = expandTilde(token.slice(1));
      set.push(...expanded);
      continue;
    }

    const opMatch = token.match(/^([><=!]+)?(.+)$/);
    if (opMatch) {
      const rawOp = opMatch[1] || "=";
      const verPart = opMatch[2];
      const validOp: ComparatorOperator =
        rawOp === ">=" || rawOp === "<=" || rawOp === ">" || rawOp === "<" || rawOp === "!=" || rawOp === "="
          ? rawOp
          : "=";

      let parsed = parseSemVer(verPart);
      if (!parsed) {
        // partial version like 0.8 -> 0.8.0
        const partial = verPart.match(/^[vV]?(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
        if (partial) {
          parsed = parseSemVer(`${partial[1]}.${partial[2]}.0`);
        }
      }

      if (parsed) {
        set.push({
          operator: validOp,
          version: parsed,
          raw: `${validOp}${formatSemVer(parsed)}`,
        });
      }
    }
  }

  return set;
}

/**
 * Parses a complete SemVer range expression into a {@link SemVerRange}.
 */
export function parseSemVerRange(rangeStr: string): SemVerRange {
  if (typeof rangeStr !== "string") {
    return { raw: "", set: [] };
  }

  const normalized = normalizeHyphenRanges(rangeStr.trim());
  const disjunctions = normalized.split("||");
  const sets: ComparatorSet[] = [];

  for (const disj of disjunctions) {
    const compSet = parseConjunction(disj);
    if (compSet.length > 0) {
      sets.push(compSet);
    }
  }

  return {
    raw: rangeStr,
    set: sets,
  };
}

/**
 * Determines whether a version satisfies a range expression or parsed {@link SemVerRange}.
 */
export function satisfiesSemVer(version: SemVer | string, range: SemVerRange | string): boolean {
  const ver = typeof version === "string" ? parseSemVer(version) : version;
  if (!ver) return false;

  const rng = typeof range === "string" ? parseSemVerRange(range) : range;
  if (rng.set.length === 0) return true; // empty range satisfies all

  // OR across disjunctions
  for (const andSet of rng.set) {
    let andPass = true;
    for (const comp of andSet) {
      if (!testComparator(ver, comp)) {
        andPass = false;
        break;
      }
    }
    if (andPass) return true;
  }

  return false;
}

/**
 * Sorts an array of version strings in ascending or descending SemVer order.
 */
export function sortSemVerList(versions: string[], direction: "asc" | "desc" = "asc"): string[] {
  const valid = versions
    .map((v) => ({ raw: v, parsed: parseSemVer(v) }))
    .filter((entry): entry is { raw: string; parsed: SemVer } => entry.parsed !== null);

  valid.sort((a, b) => {
    const cmp = compareSemVer(a.parsed, b.parsed);
    return direction === "asc" ? cmp : -cmp;
  });

  return valid.map((entry) => entry.raw);
}

/**
 * Finds the highest version in a list satisfying a range.
 */
export function findMaxSatisfyingVersion(
  versions: string[],
  range: SemVerRange | string,
): string | null {
  const sorted = sortSemVerList(versions, "desc");
  for (const v of sorted) {
    if (satisfiesSemVer(v, range)) {
      return v;
    }
  }
  return null;
}

/**
 * Finds the lowest version in a list satisfying a range.
 */
export function findMinSatisfyingVersion(
  versions: string[],
  range: SemVerRange | string,
): string | null {
  const sorted = sortSemVerList(versions, "asc");
  for (const v of sorted) {
    if (satisfiesSemVer(v, range)) {
      return v;
    }
  }
  return null;
}

/**
 * Calculates the intersection of multiple SemVer ranges against a pool of supported versions.
 */
export function intersectSemVerRanges(
  ranges: (SemVerRange | string)[],
  supportedVersions: string[],
): {
  satisfiable: boolean;
  satisfyingVersions: string[];
  lowestVersion?: string;
  highestVersion?: string;
  effectiveRangeDescription: string;
} {
  const parsedRanges = ranges.map((r) => (typeof r === "string" ? parseSemVerRange(r) : r));

  const satisfying = supportedVersions.filter((v) => {
    for (const range of parsedRanges) {
      if (!satisfiesSemVer(v, range)) {
        return false;
      }
    }
    return true;
  });

  const sorted = sortSemVerList(satisfying, "asc");
  const satisfiable = sorted.length > 0;

  let description = "none";
  if (satisfiable) {
    if (sorted.length === 1) {
      description = `=${sorted[0]}`;
    } else {
      description = `>=${sorted[0]} <=${sorted[sorted.length - 1]}`;
    }
  }

  return {
    satisfiable,
    satisfyingVersions: sorted,
    lowestVersion: sorted[0],
    highestVersion: sorted[sorted.length - 1],
    effectiveRangeDescription: description,
  };
}
