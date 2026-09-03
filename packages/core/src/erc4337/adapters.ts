import type { ERC4337Version } from "./types";

export interface ERC4337Adapter {
  version: ERC4337Version;
  userOperationTypeNames: readonly string[];
  entryPointFunctionNames: readonly string[];
  paymasterFunctionNames: readonly string[];
  packedUserOperation: boolean;
  supportsAggregatedOperations: boolean;
  markers: readonly RegExp[];
}

const ADAPTERS: readonly ERC4337Adapter[] = [
  {
    version: "0.6",
    userOperationTypeNames: ["UserOperation"],
    entryPointFunctionNames: ["handleOps", "handleAggregatedOps", "getUserOpHash"],
    paymasterFunctionNames: ["validatePaymasterUserOp", "postOp"],
    packedUserOperation: false,
    supportsAggregatedOperations: true,
    markers: [/IEntryPoint/, /UserOperation\s+(?:calldata|memory)/],
  },
  {
    version: "0.7",
    userOperationTypeNames: ["PackedUserOperation"],
    entryPointFunctionNames: ["handleOps", "handleAggregatedOps", "getUserOpHash"],
    paymasterFunctionNames: ["validatePaymasterUserOp", "postOp"],
    packedUserOperation: true,
    supportsAggregatedOperations: true,
    markers: [/PackedUserOperation/, /IEntryPoint\s*\{/],
  },
  {
    version: "0.8",
    userOperationTypeNames: ["PackedUserOperation"],
    entryPointFunctionNames: ["handleOps", "handleAggregatedOps", "getUserOpHash"],
    paymasterFunctionNames: ["validatePaymasterUserOp", "postOp"],
    packedUserOperation: true,
    supportsAggregatedOperations: true,
    markers: [/PackedUserOperation/, /postOp\s*\(/, /validatePaymasterUserOp/],
  },
];

export function getERC4337Adapter(version: ERC4337Version): ERC4337Adapter {
  return ADAPTERS.find((adapter) => adapter.version === version) ?? ADAPTERS[1];
}

export function listERC4337Adapters(): readonly ERC4337Adapter[] {
  return ADAPTERS;
}

export function detectERC4337Version(source: string): ERC4337Version {
  const scored = ADAPTERS.map((adapter) => ({
    adapter,
    score: adapter.markers.filter((marker) => marker.test(source)).length,
  }));
  scored.sort((left, right) => right.score - left.score || left.adapter.version.localeCompare(right.adapter.version));
  return scored[0]?.score ? scored[0].adapter.version : "0.7";
}

export function adapterSupportsFunction(version: ERC4337Version, functionName: string): boolean {
  const adapter = getERC4337Adapter(version);
  return [...adapter.entryPointFunctionNames, ...adapter.paymasterFunctionNames].includes(functionName);
}

export function canonicalUserOperationFields(version: ERC4337Version): readonly string[] {
  if (version === "0.6") {
    return ["sender", "nonce", "initCode", "callData", "callGasLimit", "verificationGasLimit", "preVerificationGas", "maxFeePerGas", "maxPriorityFeePerGas", "paymasterAndData", "signature"];
  }
  return ["sender", "nonce", "initCode", "callData", "accountGasLimits", "preVerificationGas", "gasFees", "paymasterAndData", "signature"];
}
