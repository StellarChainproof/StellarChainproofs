/**
 * @packageDocumentation
 * @chainproof/core — Cross-Compiler Differential Comparison Engine (ABI, Storage, Bytecode & Findings)
 */

import type { Finding } from "../types";
import type {
  NormalizedCompilationResult,
  NormalizedContractArtifact,
  VersionComparisonResult,
  ABIDiffResult,
  StorageLayoutDiffResult,
  BytecodeDiffResult,
  DiagnosticDiffResult,
  FindingsDiffResult,
  StorageCollisionHazard,
} from "./types";
import {
  getBreakingChangesBetween,
  getHazardsForVersion,
} from "./matrix";

/**
 * Compares ABI entries between base and target compilations.
 */
export function diffABI(
  baseArtifact: NormalizedContractArtifact,
  targetArtifact: NormalizedContractArtifact,
): ABIDiffResult {
  const baseEntries = baseArtifact.abi || [];
  const targetEntries = targetArtifact.abi || [];

  const baseFuncMap = new Map(
    baseEntries
      .filter((e) => e.type === "function" && e.name)
      .map((e) => [e.name!, e]),
  );
  const targetFuncMap = new Map(
    targetEntries
      .filter((e) => e.type === "function" && e.name)
      .map((e) => [e.name!, e]),
  );

  const addedFunctions: string[] = [];
  const removedFunctions: string[] = [];
  const mutatedSignatures: { name: string; baseSignature: string; targetSignature: string }[] = [];
  const mutabilityChanges: { name: string; from: string; to: string }[] = [];

  for (const [name, targetFunc] of targetFuncMap.entries()) {
    if (!baseFuncMap.has(name)) {
      addedFunctions.push(targetFunc.signature || name);
    } else {
      const baseFunc = baseFuncMap.get(name)!;
      if (baseFunc.signature !== targetFunc.signature) {
        mutatedSignatures.push({
          name,
          baseSignature: baseFunc.signature || "",
          targetSignature: targetFunc.signature || "",
        });
      }
      if (baseFunc.stateMutability !== targetFunc.stateMutability) {
        mutabilityChanges.push({
          name,
          from: baseFunc.stateMutability || "nonpayable",
          to: targetFunc.stateMutability || "nonpayable",
        });
      }
    }
  }

  for (const [name, baseFunc] of baseFuncMap.entries()) {
    if (!targetFuncMap.has(name)) {
      removedFunctions.push(baseFunc.signature || name);
    }
  }

  // Events Diff
  const baseEvents = new Set(
    baseEntries.filter((e) => e.type === "event" && e.signature).map((e) => e.signature!),
  );
  const targetEvents = new Set(
    targetEntries.filter((e) => e.type === "event" && e.signature).map((e) => e.signature!),
  );

  const addedEvents = [...targetEvents].filter((e) => !baseEvents.has(e));
  const removedEvents = [...baseEvents].filter((e) => !targetEvents.has(e));

  // Errors Diff
  const baseErrors = new Set(
    baseEntries.filter((e) => e.type === "error" && e.signature).map((e) => e.signature!),
  );
  const targetErrors = new Set(
    targetEntries.filter((e) => e.type === "error" && e.signature).map((e) => e.signature!),
  );

  const addedErrors = [...targetErrors].filter((e) => !baseErrors.has(e));
  const removedErrors = [...baseErrors].filter((e) => !targetErrors.has(e));

  const identical =
    addedFunctions.length === 0 &&
    removedFunctions.length === 0 &&
    mutatedSignatures.length === 0 &&
    mutabilityChanges.length === 0 &&
    addedEvents.length === 0 &&
    removedEvents.length === 0 &&
    addedErrors.length === 0 &&
    removedErrors.length === 0;

  return {
    identical,
    addedFunctions,
    removedFunctions,
    mutatedSignatures,
    addedEvents,
    removedEvents,
    addedErrors,
    removedErrors,
    mutabilityChanges,
  };
}

/**
 * Compares Storage Layout between base and target compilations, identifying slot collisions and shifts.
 */
export function diffStorageLayout(
  baseArtifact: NormalizedContractArtifact,
  targetArtifact: NormalizedContractArtifact,
): StorageLayoutDiffResult {
  const baseItems = baseArtifact.storageLayout?.storage || [];
  const targetItems = targetArtifact.storageLayout?.storage || [];

  const baseVarMap = new Map(baseItems.map((item) => [item.label, item]));
  const targetVarMap = new Map(targetItems.map((item) => [item.label, item]));

  const addedVariables: string[] = [];
  const removedVariables: string[] = [];
  const shiftedSlots: { variable: string; oldSlot: number; newSlot: number }[] = [];
  const offsetChanges: { variable: string; oldOffset: number; newOffset: number }[] = [];
  const typeChanges: { variable: string; oldType: string; newType: string }[] = [];
  const slotCollisions: StorageCollisionHazard[] = [];

  for (const [name, targetVar] of targetVarMap.entries()) {
    if (!baseVarMap.has(name)) {
      addedVariables.push(`${name} (slot ${targetVar.slot}, offset ${targetVar.offset})`);
    } else {
      const baseVar = baseVarMap.get(name)!;

      if (baseVar.slot !== targetVar.slot) {
        shiftedSlots.push({ variable: name, oldSlot: baseVar.slot, newSlot: targetVar.slot });
        slotCollisions.push({
          variable: name,
          severity: "critical",
          reason: `Storage slot shifted from slot ${baseVar.slot} to slot ${targetVar.slot}. In upgradeable proxies, this will cause state corruption.`,
          oldSlot: baseVar.slot,
          newSlot: targetVar.slot,
          oldOffset: baseVar.offset,
          newOffset: targetVar.offset,
        });
      } else if (baseVar.offset !== targetVar.offset) {
        offsetChanges.push({ variable: name, oldOffset: baseVar.offset, newOffset: targetVar.offset });
        slotCollisions.push({
          variable: name,
          severity: "high",
          reason: `Storage byte offset changed from offset ${baseVar.offset} to offset ${targetVar.offset} in slot ${baseVar.slot}.`,
          oldSlot: baseVar.slot,
          newSlot: targetVar.slot,
          oldOffset: baseVar.offset,
          newOffset: targetVar.offset,
        });
      }

      if (baseVar.type !== targetVar.type) {
        typeChanges.push({ variable: name, oldType: baseVar.type, newType: targetVar.type });
      }
    }
  }

  for (const [name, baseVar] of baseVarMap.entries()) {
    if (!targetVarMap.has(name)) {
      removedVariables.push(`${name} (slot ${baseVar.slot}, offset ${baseVar.offset})`);
      slotCollisions.push({
        variable: name,
        severity: "critical",
        reason: `Storage variable "${name}" was removed or renamed from slot ${baseVar.slot}.`,
        oldSlot: baseVar.slot,
        newSlot: -1,
      });
    }
  }

  const identical =
    baseArtifact.storageLayout?.layoutHash === targetArtifact.storageLayout?.layoutHash &&
    slotCollisions.length === 0 &&
    addedVariables.length === 0 &&
    removedVariables.length === 0;

  return {
    identical,
    slotCollisions,
    addedVariables,
    removedVariables,
    shiftedSlots,
    offsetChanges,
    typeChanges,
  };
}

/**
 * Compares Bytecode between base and target compilations.
 */
export function diffBytecode(
  baseArtifact: NormalizedContractArtifact,
  targetArtifact: NormalizedContractArtifact,
): BytecodeDiffResult {
  const baseBC = baseArtifact.deployedBytecode || baseArtifact.bytecode;
  const targetBC = targetArtifact.deployedBytecode || targetArtifact.bytecode;

  const baseSizeBytes = baseBC?.lengthBytes ?? 0;
  const targetSizeBytes = targetBC?.lengthBytes ?? 0;

  const sizeDeltaBytes = targetSizeBytes - baseSizeBytes;
  const sizeDeltaPercent =
    baseSizeBytes > 0 ? Math.round(((targetSizeBytes - baseSizeBytes) / baseSizeBytes) * 10000) / 100 : 0;

  const baseHasPush0 = baseBC?.hasPush0 ?? false;
  const targetHasPush0 = targetBC?.hasPush0 ?? false;
  const push0Hazard = !baseHasPush0 && targetHasPush0;

  const baseHasTransient = baseBC?.hasTransientStorage ?? false;
  const targetHasTransient = targetBC?.hasTransientStorage ?? false;

  const metadataOnlyDifference =
    baseBC?.executableCodeHash === targetBC?.executableCodeHash &&
    baseBC?.metadataHash !== targetBC?.metadataHash;

  return {
    sizeDeltaBytes,
    sizeDeltaPercent,
    baseSizeBytes,
    targetSizeBytes,
    baseHasPush0,
    targetHasPush0,
    push0Hazard,
    baseHasTransient,
    targetHasTransient,
    metadataOnlyDifference,
  };
}

/**
 * Compares compiler diagnostics and warnings across versions.
 */
export function diffDiagnostics(
  baseResult: NormalizedCompilationResult,
  targetResult: NormalizedCompilationResult,
): DiagnosticDiffResult {
  const baseWarnMessages = new Set(
    baseResult.diagnostics.filter((d) => d.severity === "warning").map((d) => d.message),
  );
  const targetWarnMessages = new Set(
    targetResult.diagnostics.filter((d) => d.severity === "warning").map((d) => d.message),
  );

  const newWarnings = [...targetWarnMessages].filter((msg) => !baseWarnMessages.has(msg));
  const resolvedWarnings = [...baseWarnMessages].filter((msg) => !targetWarnMessages.has(msg));

  const newErrors = targetResult.diagnostics
    .filter((d) => d.severity === "error")
    .map((d) => d.message);

  return {
    newWarnings,
    resolvedWarnings,
    newErrors,
  };
}

/**
 * Compares ChainProof scanner findings across compiler versions.
 */
export function diffFindings(
  baseFindings: Finding[] = [],
  targetFindings: Finding[] = [],
): FindingsDiffResult {
  const baseIds = new Set(baseFindings.map((f) => `${f.id}:${f.line}`));
  const targetIds = new Set(targetFindings.map((f) => `${f.id}:${f.line}`));

  const introducedFindings = targetFindings.filter((f) => !baseIds.has(`${f.id}:${f.line}`));
  const resolvedFindings = baseFindings.filter((f) => !targetIds.has(`${f.id}:${f.line}`));

  const severityDelta = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    gas: 0,
  };

  for (const f of introducedFindings) {
    if (f.severity in severityDelta) severityDelta[f.severity]++;
  }
  for (const f of resolvedFindings) {
    if (f.severity in severityDelta) severityDelta[f.severity]--;
  }

  return {
    introducedFindings,
    resolvedFindings,
    severityDelta,
  };
}

/**
 * Performs a comprehensive differential comparison between two compiler versions for a contract.
 */
export function compareContractVersions(
  contractName: string,
  baseResult: NormalizedCompilationResult,
  targetResult: NormalizedCompilationResult,
  options?: {
    baseFindings?: Finding[];
    targetFindings?: Finding[];
    sourceFile?: string;
  },
): VersionComparisonResult {
  const baseArtifact = baseResult.contracts[contractName] || {
    contractName,
    sourcePath: options?.sourceFile || "",
    abi: [],
    storageLayout: { storage: [], types: {}, totalSlots: 0, hasPacking: false, layoutHash: "" },
    bytecode: { object: "0x", lengthBytes: 0, hasPush0: false, hasTransientStorage: false, executableCodeHash: "" },
    deployedBytecode: { object: "0x", lengthBytes: 0, hasPush0: false, hasTransientStorage: false, executableCodeHash: "" },
  };

  const targetArtifact = targetResult.contracts[contractName] || {
    contractName,
    sourcePath: options?.sourceFile || "",
    abi: [],
    storageLayout: { storage: [], types: {}, totalSlots: 0, hasPacking: false, layoutHash: "" },
    bytecode: { object: "0x", lengthBytes: 0, hasPush0: false, hasTransientStorage: false, executableCodeHash: "" },
    deployedBytecode: { object: "0x", lengthBytes: 0, hasPush0: false, hasTransientStorage: false, executableCodeHash: "" },
  };

  const abiDiff = diffABI(baseArtifact, targetArtifact);
  const storageLayoutDiff = diffStorageLayout(baseArtifact, targetArtifact);
  const bytecodeDiff = diffBytecode(baseArtifact, targetArtifact);
  const diagnosticDiff = diffDiagnostics(baseResult, targetResult);
  const findingsDiff = diffFindings(options?.baseFindings, options?.targetFindings);

  const breakingChanges = getBreakingChangesBetween(baseResult.version, targetResult.version).map(
    (b) => `[${b.fromFamily} -> ${b.toFamily}] ${b.summary}`,
  );

  const activeHazardsInBase = getHazardsForVersion(baseResult.version);
  const activeHazardsInTarget = getHazardsForVersion(targetResult.version);

  let compatibilityStatus: VersionComparisonResult["compatibilityStatus"] = "compatible";
  if (storageLayoutDiff.slotCollisions.length > 0 || !abiDiff.identical) {
    compatibilityStatus = "breaking_drift";
  } else if (
    activeHazardsInTarget.some((h) => h.severity === "critical" || h.severity === "high") ||
    bytecodeDiff.push0Hazard
  ) {
    compatibilityStatus = "hazard";
  } else if (diagnosticDiff.newWarnings.length > 0 || !storageLayoutDiff.identical) {
    compatibilityStatus = "warning";
  }

  return {
    contractName,
    sourceFile: baseArtifact.sourcePath || targetArtifact.sourcePath || options?.sourceFile || "",
    baseVersion: baseResult.version,
    targetVersion: targetResult.version,
    abiDiff,
    storageLayoutDiff,
    bytecodeDiff,
    diagnosticDiff,
    findingsDiff,
    breakingChanges,
    activeHazardsInBase,
    activeHazardsInTarget,
    compatibilityStatus,
  };
}
