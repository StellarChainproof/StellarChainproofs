/**
 * @packageDocumentation
 * @chainproof/core — Sandboxed Compiler Adapters & Offline Compiler Simulator
 */

import { execFile } from "child_process";
import { parseSolidity, visit } from "../ast/parser";
import type {
  CompilerSettings,
  CompilerSourceInput,
  NormalizedCompilationResult,
  NormalizedContractArtifact,
  NormalizedCompilerDiagnostic,
  NormalizedABIEntry,
  NormalizedStorageItem,
  NormalizedStorageType,
  CompilerVersionMetadata,
} from "./types";
import {
  getCompilerVersionMetadata,
  getHazardsForVersion,
} from "./matrix";
import {
  normalizeABI,
  normalizeStorageLayout,
  normalizeBytecode,
  normalizeCompilerDiagnostic,
  computeFunctionSelector,
  computeEventTopic,
  keccak256,
} from "./normalizer";
import {
  createIsolatedEnvironment,
  sanitizeCompilerOutput,
  DEFAULT_SANDBOX_OPTIONS,
} from "./sandbox";
import { verifyCompilerBinary } from "./checksums";
import { compareSemVer } from "./semver";

export interface CompilerAdapter {
  compile(
    sources: CompilerSourceInput[],
    settings?: Partial<CompilerSettings>,
    version?: string,
  ): Promise<NormalizedCompilationResult>;
  inspectVersion(version: string): CompilerVersionMetadata | null;
}

export interface CompilerAdapterOptions {
  mode?: "simulated" | "native" | "auto";
  nativeBinaryPath?: string;
  expectedBinaryChecksum?: string;
  timeoutMs?: number;
  maxBufferBytes?: number;
}

// ─── Simulated Offline Compiler Adapter ───────────────────────────────────────

/**
 * Calculates standard Solidity storage byte sizes for variable types.
 */
function getTypeByteSize(typeStr: string): number {
  const t = typeStr.trim();
  if (t === "bool") return 1;
  if (t === "address" || t === "address payable") return 20;

  const uintMatch = t.match(/^uint(\d+)$/);
  if (uintMatch) {
    return parseInt(uintMatch[1], 10) / 8;
  }
  const intMatch = t.match(/^int(\d+)$/);
  if (intMatch) {
    return parseInt(intMatch[1], 10) / 8;
  }
  const bytesMatch = t.match(/^bytes(\d+)$/);
  if (bytesMatch) {
    return parseInt(bytesMatch[1], 10);
  }

  // Dynamic types, mappings, arrays occupy full 32-byte slot
  return 32;
}

/**
 * AST-based offline simulated compiler that deterministically produces standard-compliant
 * ABIs, storage layouts, opcodes, and version diagnostics without external network or binaries.
 */
export class SimulatedCompilerAdapter implements CompilerAdapter {
  inspectVersion(version: string): CompilerVersionMetadata | null {
    return getCompilerVersionMetadata(version);
  }

  async compile(
    sources: CompilerSourceInput[],
    settings?: Partial<CompilerSettings>,
    version: string = "0.8.28",
  ): Promise<NormalizedCompilationResult> {
    const startTime = Date.now();
    const meta = getCompilerVersionMetadata(version);
    const evmVersion = settings?.evmVersion || meta?.defaultEvmVersion || "paris";
    const optimizer = {
      enabled: settings?.optimizer?.enabled ?? true,
      runs: settings?.optimizer?.runs ?? 200,
      viaIR: settings?.viaIR ?? false,
    };

    const contracts: Record<string, NormalizedContractArtifact> = {};
    const diagnostics: NormalizedCompilerDiagnostic[] = [];

    for (const src of sources) {
      let ast = src.ast;
      if (!ast) {
        const parsed = parseSolidity(src.content, src.file);
        if (!parsed.ast) {
          diagnostics.push({
            severity: "error",
            type: "ParserError",
            message: parsed.error || `Failed to parse ${src.file}`,
            formattedMessage: `ParserError: ${parsed.error || `Failed to parse ${src.file}`}`,
            sourceLocation: { file: src.file, start: 0, end: 0, line: 1 },
          });
          continue;
        }
        ast = parsed.ast;
      }

      // Extract contracts from AST
      visit(ast, {
        ContractDefinition: (contractNode: any) => {
          const contractName = contractNode.name;
          const abiEntries: NormalizedABIEntry[] = [];
          const storageItems: NormalizedStorageItem[] = [];
          const storageTypes: Record<string, NormalizedStorageType> = {};

          let currentSlot = 0;
          let currentOffset = 0;

          let hasAssembly = false;
          let hasUnchecked = false;
          let hasReceive = false;
          let hasFallback = false;
          let usesCustomErrors = false;
          let usesUserDefined = false;

          let contractFunctionCount = 0;

          // Walk sub-nodes of contract
          const subNodes = contractNode.subNodes || [];
          for (const subNode of subNodes) {
            if (subNode.type === "FunctionDefinition") {
              contractFunctionCount++;
              const isConstructor = subNode.isConstructor || subNode.name === contractName;
              const isReceive = subNode.isReceiveType || subNode.name === "receive";
              const isFallback = subNode.isFallback || subNode.name === "fallback" || (!subNode.name && !isConstructor);

              if (isReceive) hasReceive = true;
              if (isFallback) hasFallback = true;

              // Check 0.4 vs 0.5 constructor syntax
              if (subNode.name === contractName && compareSemVer(version, "0.5.0") >= 0) {
                diagnostics.push({
                  severity: "warning",
                  type: "DeclarationError",
                  message: `Defining constructors with contract name is deprecated and invalid in >=0.5.0. Use 'constructor(...)'.`,
                  formattedMessage: `Warning: Defining constructors with contract name is deprecated in >=0.5.0. Use 'constructor(...)'.`,
                  sourceLocation: { file: src.file, start: 0, end: 0, line: subNode.loc?.start?.line },
                });
              }

              // Check 0.6 virtual/override
              if (compareSemVer(version, "0.6.0") < 0 && (subNode.isVirtual || subNode.override)) {
                diagnostics.push({
                  severity: "error",
                  type: "ParserError",
                  message: `'virtual' and 'override' specifiers are not supported in Solidity <0.6.0.`,
                  formattedMessage: `Error: 'virtual' and 'override' specifiers are not supported in Solidity <0.6.0.`,
                  sourceLocation: { file: src.file, start: 0, end: 0, line: subNode.loc?.start?.line },
                });
              }

              const rawInputs = Array.isArray(subNode.parameters)
                ? subNode.parameters
                : subNode.parameters?.parameters || [];
              const inputs = rawInputs.map((p: any) => ({
                name: p.name || "",
                type: p.typeName?.name || p.typeName?.namePath || "bytes",
              }));

              const rawOutputs = Array.isArray(subNode.returnParameters)
                ? subNode.returnParameters
                : subNode.returnParameters?.parameters || [];
              const outputs = rawOutputs.map((p: any) => ({
                name: p.name || "",
                type: p.typeName?.name || p.typeName?.namePath || "bytes",
              }));

              const mutability = subNode.stateMutability || "nonpayable";

              const entryType = isConstructor
                ? "constructor"
                : isReceive
                ? "receive"
                : isFallback
                ? "fallback"
                : "function";

              const abiEntry: NormalizedABIEntry = {
                type: entryType,
                name: entryType === "function" ? subNode.name : undefined,
                inputs,
                outputs: outputs.length > 0 ? outputs : undefined,
                stateMutability: mutability,
              };

              const sig =
                entryType === "function"
                  ? `${subNode.name}(${inputs.map((i: any) => i.type).join(",")})`
                  : entryType === "constructor"
                  ? `constructor(${inputs.map((i: any) => i.type).join(",")})`
                  : `${entryType}()`;

              abiEntry.signature = sig;
              if (entryType === "function") {
                abiEntry.selector = computeFunctionSelector(sig);
              }

              abiEntries.push(abiEntry);
            } else if (subNode.type === "StateVariableDeclaration") {
              for (const v of subNode.variables || []) {
                const varName = v.name;
                const isConstant = v.isDeclaredConst || v.isImmutable;
                if (isConstant) continue; // constants and immutables do not take storage slots

                const typeName = v.typeName?.name || v.typeName?.namePath || "uint256";
                const byteSize = getTypeByteSize(typeName);

                // Slot packing algorithm
                if (currentOffset + byteSize > 32) {
                  currentSlot += 1;
                  currentOffset = 0;
                }

                const slot = currentSlot;
                const offset = currentOffset;

                if (byteSize >= 32) {
                  currentSlot += 1;
                  currentOffset = 0;
                } else {
                  currentOffset += byteSize;
                  if (currentOffset >= 32) {
                    currentSlot += 1;
                    currentOffset = 0;
                  }
                }

                storageItems.push({
                  contract: contractName,
                  label: varName,
                  offset,
                  slot,
                  type: typeName,
                  numberOfBytes: byteSize,
                });

                if (!storageTypes[typeName]) {
                  storageTypes[typeName] = {
                    encoding: "inplace",
                    label: typeName,
                    numberOfBytes: byteSize,
                  };
                }
              }
            } else if (subNode.type === "EventDefinition") {
              const rawInputs = Array.isArray(subNode.parameters)
                ? subNode.parameters
                : subNode.parameters?.parameters || [];
              const inputs = rawInputs.map((p: any) => ({
                name: p.name || "",
                type: p.typeName?.name || p.typeName?.namePath || "bytes",
                indexed: p.isIndexed ?? false,
              }));

              const sig = `${subNode.name}(${inputs.map((i: any) => i.type).join(",")})`;
              abiEntries.push({
                type: "event",
                name: subNode.name,
                inputs,
                anonymous: subNode.isAnonymous ?? false,
                signature: sig,
                selector: computeEventTopic(sig),
              });
            } else if (subNode.type === "CustomErrorDefinition") {
              usesCustomErrors = true;
              if (compareSemVer(version, "0.8.4") < 0) {
                diagnostics.push({
                  severity: "error",
                  type: "ParserError",
                  message: `Custom errors (error ${subNode.name}(...)) are only supported in Solidity >=0.8.4.`,
                  formattedMessage: `Error: Custom errors are only supported in Solidity >=0.8.4.`,
                  sourceLocation: { file: src.file, start: 0, end: 0, line: subNode.loc?.start?.line },
                });
              }

              const rawInputs = Array.isArray(subNode.parameters)
                ? subNode.parameters
                : subNode.parameters?.parameters || [];
              const inputs = rawInputs.map((p: any) => ({
                name: p.name || "",
                type: p.typeName?.name || p.typeName?.namePath || "bytes",
              }));

              const sig = `${subNode.name}(${inputs.map((i: any) => i.type).join(",")})`;
              abiEntries.push({
                type: "error",
                name: subNode.name,
                inputs,
                signature: sig,
                selector: computeFunctionSelector(sig),
              });
            }
          }

          // Check AST for assembly or unchecked blocks
          visit(contractNode, {
            InlineAssemblyStatement: () => {
              hasAssembly = true;
            },
            UncheckedStatement: () => {
              hasUnchecked = true;
            },
            UserDefinedTypeName: () => {
              usesUserDefined = true;
            },
          });

          // Check for active codegen hazards for this version
          const hazards = getHazardsForVersion(version, {
            hasTransientStorage: src.content.includes("tstore") || src.content.includes("tload"),
            hasInlineAssembly: hasAssembly,
            targetEvmLacksPush0: ["homestead", "byzantium", "petersburg", "istanbul", "berlin", "london", "paris"].includes(evmVersion),
          });

          for (const h of hazards) {
            diagnostics.push({
              severity: h.severity === "critical" || h.severity === "high" ? "warning" : "info",
              type: "SecurityHazard",
              message: `[${h.id}] ${h.name}: ${h.description}`,
              formattedMessage: `SecurityHazard [${h.id}]: ${h.description} Recommendation: ${h.recommendation}`,
              sourceLocation: { file: src.file, start: 0, end: 0, line: 1 },
              errorCode: h.id,
            });
          }

          // Build synthetic bytecode with accurate opcodes
          let bytecodeHex = "6080604052"; // standard compiler header PUSH1 0x80 PUSH1 0x40 MSTORE

          // Include PUSH0 opcode (0x5f) for Shanghai+ and 0.8.20+
          const emitsPush0 =
            compareSemVer(version, "0.8.20") >= 0 &&
            (evmVersion === "shanghai" || evmVersion === "cancun" || evmVersion === "prague");

          if (emitsPush0) {
            bytecodeHex += "5f"; // PUSH0 opcode
          }

          // Include TSTORE (0x5d) / TLOAD (0x5c) if transient storage used in 0.8.24+
          if (compareSemVer(version, "0.8.24") >= 0 && (src.content.includes("tstore") || src.content.includes("tload"))) {
            bytecodeHex += "5d5c";
          }

          // Append function dispatcher simulation
          for (const entry of abiEntries) {
            if (entry.selector && entry.type === "function") {
              const sel = entry.selector.replace(/^0x/, "");
              bytecodeHex += `63${sel}14`; // PUSH4 <sel> EQ
            }
          }

          // Append dummy runtime body
          bytecodeHex += "00fe";

          // Append standard CBOR metadata simulation: 0xa264697066735822...
          const metaPayload = `solc_${version}_${contractName}`;
          const metaHash = keccak256(metaPayload).slice(0, 68);
          bytecodeHex += `a264697066735822${metaHash}64736f6c6343${version.replace(/\./g, "")}0033`;

          const normalizedStorage = normalizeStorageLayout({
            storage: storageItems,
            types: storageTypes,
          });

          const normalizedBytecode = normalizeBytecode(bytecodeHex);

          contracts[contractName] = {
            contractName,
            sourcePath: src.file,
            abi: abiEntries,
            storageLayout: normalizedStorage,
            bytecode: normalizedBytecode,
            deployedBytecode: normalizedBytecode,
            astSummary: {
              contractCount: 1,
              functionCount: contractFunctionCount,
              hasAssembly,
              hasUncheckedBlocks: hasUnchecked,
              hasPayableFallback: hasFallback,
              hasReceiveFunction: hasReceive,
              usesCustomErrors,
              usesUserDefinedTypes: usesUserDefined,
            },
          };
        },
      });
    }

    const durationMs = Date.now() - startTime;
    const hasFatalErrors = diagnostics.some((d) => d.severity === "error");

    return {
      version,
      success: !hasFatalErrors,
      contracts,
      diagnostics,
      durationMs,
      evmVersion,
      optimizer,
      simulated: true,
    };
  }
}

// ─── Native Solc Process Adapter ──────────────────────────────────────────────

/**
 * Sandboxed process compiler adapter for executing locally verified native solc binaries.
 */
export class NativeSolcAdapter implements CompilerAdapter {
  private binaryPath: string;
  private expectedChecksum?: string;
  private timeoutMs: number;
  private maxBufferBytes: number;

  constructor(
    binaryPath: string,
    options?: { expectedChecksum?: string; timeoutMs?: number; maxBufferBytes?: number },
  ) {
    this.binaryPath = binaryPath;
    this.expectedChecksum = options?.expectedChecksum;
    this.timeoutMs = options?.timeoutMs ?? DEFAULT_SANDBOX_OPTIONS.timeoutMs;
    this.maxBufferBytes = options?.maxBufferBytes ?? DEFAULT_SANDBOX_OPTIONS.maxBufferBytes;
  }

  inspectVersion(version: string): CompilerVersionMetadata | null {
    return getCompilerVersionMetadata(version);
  }

  async compile(
    sources: CompilerSourceInput[],
    settings?: Partial<CompilerSettings>,
    version?: string,
  ): Promise<NormalizedCompilationResult> {
    const startTime = Date.now();

    // Verify binary integrity before execution
    const verifyRes = verifyCompilerBinary(this.binaryPath, {
      expectedSha256: this.expectedChecksum,
      version,
    });
    if (!verifyRes.valid) {
      throw new Error(
        `Compiler binary integrity check failed for ${this.binaryPath}: ${verifyRes.error || "Checksum mismatch"}`,
      );
    }

    // Build Standard JSON Input
    const standardInputSources: Record<string, { content: string }> = {};
    for (const src of sources) {
      standardInputSources[src.file] = { content: src.content };
    }

    const standardInput = {
      language: "Solidity",
      sources: standardInputSources,
      settings: {
        optimizer: settings?.optimizer ?? { enabled: true, runs: 200 },
        evmVersion: settings?.evmVersion,
        outputSelection: {
          "*": {
            "*": ["abi", "evm.bytecode", "evm.deployedBytecode", "storageLayout"],
            "": ["ast"],
          },
        },
      },
    };

    const cleanEnv = createIsolatedEnvironment();

    return new Promise((resolve, reject) => {
      const child = execFile(
        this.binaryPath,
        ["--standard-json"],
        {
          env: cleanEnv,
          timeout: this.timeoutMs,
          maxBuffer: this.maxBufferBytes,
        },
        (error, stdout, _stderr) => {
          const durationMs = Date.now() - startTime;
          if (error && !stdout) {
            const sanitizedMsg = sanitizeCompilerOutput(error.message);
            return reject(new Error(`Native compiler execution failed: ${sanitizedMsg}`));
          }

          let parsedOutput: any;
          try {
            parsedOutput = JSON.parse(stdout);
          } catch (jsonErr) {
            return reject(
              new Error(`Failed to parse standard-json compiler output: ${sanitizeCompilerOutput(stdout.slice(0, 300))}`),
            );
          }

          const diagnostics: NormalizedCompilerDiagnostic[] = (parsedOutput.errors || []).map(
            normalizeCompilerDiagnostic,
          );

          const contracts: Record<string, NormalizedContractArtifact> = {};
          if (parsedOutput.contracts) {
            for (const [sourcePath, fileContracts] of Object.entries<any>(parsedOutput.contracts)) {
              for (const [cName, cArtifact] of Object.entries<any>(fileContracts)) {
                contracts[cName] = {
                  contractName: cName,
                  sourcePath,
                  abi: normalizeABI(cArtifact.abi || []),
                  storageLayout: normalizeStorageLayout(cArtifact.storageLayout || {}),
                  bytecode: normalizeBytecode(cArtifact.evm?.bytecode?.object || ""),
                  deployedBytecode: normalizeBytecode(cArtifact.evm?.deployedBytecode?.object || ""),
                };
              }
            }
          }

          const hasFatal = diagnostics.some((d) => d.severity === "error");

          resolve({
            version: version || "native",
            success: !hasFatal,
            contracts,
            diagnostics,
            durationMs,
            evmVersion: settings?.evmVersion || "default",
            optimizer: {
              enabled: settings?.optimizer?.enabled ?? true,
              runs: settings?.optimizer?.runs ?? 200,
            },
            simulated: false,
          });
        },
      );

      if (child.stdin) {
        child.stdin.write(JSON.stringify(standardInput));
        child.stdin.end();
      }
    });
  }
}

/**
 * Factory that returns the appropriate compiler adapter.
 */
export function getCompilerAdapter(options?: CompilerAdapterOptions): CompilerAdapter {
  if (options?.mode === "native" && options.nativeBinaryPath) {
    return new NativeSolcAdapter(options.nativeBinaryPath, {
      expectedChecksum: options.expectedBinaryChecksum,
      timeoutMs: options.timeoutMs,
      maxBufferBytes: options.maxBufferBytes,
    });
  }

  // Default to offline simulated compiler adapter for deterministic CI/sandbox execution
  return new SimulatedCompilerAdapter();
}
