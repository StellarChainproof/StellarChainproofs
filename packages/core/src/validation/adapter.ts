/**
 * Abstract EVM adapter interface.
 *
 * Implementations wrap a process-isolated EVM backend (Anvil, Hardhat Network)
 * and expose a minimal JSON-RPC surface. Adapters are responsible for:
 *
 * - Spawning/managing the backend process with bounded resources
 * - Providing snapshot/restore for deterministic replay
 * - Translating JSON-RPC responses into {@link CallResult} objects
 * - Cleaning up processes and temp files on dispose
 *
 * @remarks
 * The interface is intentionally minimal. It exposes the EVM primitives
 * (deploy, call, snapshot, restore) rather than high-level scenario execution.
 * The {@link ValidationRunner} composes these primitives.
 */

import type {
  AccountSpec,
  AdapterType,
  CallResult,
  CallSpec,
  ContractSpec,
  LogEntry,
  ResolvedResourceLimits,
  ScenarioResourceLimits,
  StorageDiff,
  ValidationCancellationSignal,
} from "./types";

export type { AdapterType };

// ─── Core adapter interface ───────────────────────────────────────────────────

/**
 * A process-isolated EVM adapter.
 *
 * Implementations must be safe to `start()` once and `dispose()` once.
 * Re-use after `dispose()` is not supported. All methods throw
 * {@link AdapterError} on failure rather than rejecting with generic errors.
 */
export interface EvmAdapter {
  /** Which backend this adapter wraps. */
  readonly type: AdapterType;
  /** Backend version string, populated after `start()`. */
  readonly version: string;
  /** JSON-RPC URL (e.g. `http://127.0.0.1:8545`), available after `start()`. */
  readonly rpcUrl: string;

  /**
   * Start the backend process and wait until it is accepting JSON-RPC requests.
   * Must be called before any other method.
   */
  start(limits?: Partial<ScenarioResourceLimits>): Promise<void>;

  /**
   * Gracefully stop the backend process and release all resources.
   * Safe to call multiple times; subsequent calls are no-ops.
   */
  dispose(): Promise<void>;

  /**
   * Fund an account and optionally configure its nonce and code.
   */
  setupAccount(account: AccountSpec): Promise<void>;

  /**
   * Deploy a contract and return the deployed address.
   */
  deployContract(spec: ContractSpec, deployerAddress: string): Promise<string>;

  /**
   * Execute a call and return the detailed result.
   */
  executeCall(
    spec: CallSpec,
    resolvedAddresses: Map<string, string>,
    limits: ResolvedResourceLimits,
    signal?: ValidationCancellationSignal,
  ): Promise<CallResult>;

  /**
   * Read a single storage slot.
   */
  getStorageAt(address: string, slot: string): Promise<string>;

  /**
   * Get the native balance of an address in wei (as decimal string).
   */
  getBalance(address: string): Promise<string>;

  /**
   * Get the current block number.
   */
  getBlockNumber(): Promise<number>;

  /**
   * Take a snapshot and return an opaque snapshot ID.
   */
  snapshot(): Promise<string>;

  /**
   * Restore to a previously taken snapshot.
   * The snapshot is preserved (can be restored multiple times).
   */
  revertToSnapshot(snapshotId: string): Promise<void>;

  /**
   * Set the next block timestamp (UNIX seconds).
   */
  setNextBlockTimestamp(timestamp: number): Promise<void>;

  /**
   * Mine an empty block to advance chain state.
   */
  mine(count?: number): Promise<void>;

  /**
   * Override a storage slot directly (for test setup).
   */
  setStorageAt(address: string, slot: string, value: string): Promise<void>;
}

// ─── JSON-RPC client (shared by all adapters) ────────────────────────────────

import * as http from "http";
import * as https from "https";
import { URL } from "url";
import {
  AdapterCrashError,
  ForkUnavailableError,
  ValidationError,
} from "./types";

/** @internal */
export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: number;
  method: string;
  params: unknown[];
}

/** @internal */
export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

let _rpcIdCounter = 1;

/**
 * Minimal JSON-RPC client using Node's built-in http/https modules.
 * Does not require axios or any external dependency.
 * @internal
 */
export async function jsonRpcCall(
  rpcUrl: string,
  method: string,
  params: unknown[],
  timeoutMs = 10_000,
): Promise<unknown> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: _rpcIdCounter++,
    method,
    params,
  } satisfies JsonRpcRequest);

  const parsed = new URL(rpcUrl);
  const isHttps = parsed.protocol === "https:";
  const transport = isHttps ? https : http;

  return new Promise<unknown>((resolve, reject) => {
    const options: http.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
    };

    const req = transport.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        try {
          const raw = Buffer.concat(chunks).toString("utf8");
          const response = JSON.parse(raw) as JsonRpcResponse;
          if (response.error) {
            reject(
              new ValidationError(
                `JSON-RPC error ${response.error.code}: ${response.error.message}`,
                "RPC_ERROR",
                { code: response.error.code, method },
              ),
            );
          } else {
            resolve(response.result);
          }
        } catch (parseError) {
          reject(
            new ValidationError(
              `Failed to parse JSON-RPC response for ${method}`,
              "RPC_ERROR",
            ),
          );
        }
      });
    });

    req.setTimeout(timeoutMs, () => {
      req.destroy();
      reject(new ValidationError(`JSON-RPC call ${method} timed out after ${timeoutMs}ms`, "TIMEOUT"));
    });

    req.on("error", (err) => {
      const message = err instanceof Error ? err.message : String(err);
      reject(
        new ForkUnavailableError(message),
      );
    });

    req.write(body);
    req.end();
  });
}

/**
 * Wait until the RPC endpoint accepts connections, with exponential backoff.
 * @internal
 */
export async function waitForRpc(
  rpcUrl: string,
  maxWaitMs = 15_000,
  intervalMs = 200,
): Promise<void> {
  const deadline = Date.now() + maxWaitMs;
  let attempts = 0;
  while (Date.now() < deadline) {
    try {
      await jsonRpcCall(rpcUrl, "eth_blockNumber", [], 2_000);
      return;
    } catch {
      attempts++;
      const wait = Math.min(intervalMs * Math.pow(1.5, Math.min(attempts, 8)), 2_000);
      await new Promise<void>((r) => setTimeout(r, wait));
    }
  }
  throw new AdapterCrashError("anvil", `RPC at ${rpcUrl} did not become ready within ${maxWaitMs}ms`);
}

// ─── ABI encoding utilities (no external deps) ───────────────────────────────

/**
 * Encode a function call using its signature and arguments.
 *
 * Supports: uint256, int256, address, bool, bytes, bytes32, string
 * (as value types only — no arrays/structs; for those pass raw calldata).
 *
 * @internal
 */
export function encodeFunctionCall(signature: string, args: unknown[]): string {
  const selector = keccak256Selector(signature);
  if (args.length === 0) return selector;

  const encoded = args.map((arg) => encodeArg(arg)).join("");
  return selector + encoded;
}

/**
 * Compute the first 4 bytes of keccak256(signature) as a hex string.
 * Uses a pure-JS keccak256 so we avoid adding ethers/web3 as a dep.
 * @internal
 */
export function keccak256Selector(signature: string): string {
  const hash = keccak256Pure(Buffer.from(signature, "utf8"));
  return "0x" + hash.slice(0, 8);
}

function encodeArg(value: unknown): string {
  if (typeof value === "bigint") {
    return value.toString(16).padStart(64, "0");
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error(`Unsafe integer: ${value}. Pass as a hex string or BigInt.`);
    }
    return BigInt(value).toString(16).padStart(64, "0");
  }
  if (typeof value === "boolean") {
    return (value ? 1n : 0n).toString(16).padStart(64, "0");
  }
  if (typeof value === "string") {
    if (/^0x[0-9a-f]*/i.test(value)) {
      // Hex value (address, bytes32, etc.)
      const stripped = value.slice(2).toLowerCase();
      return stripped.padStart(64, "0");
    }
    // Decimal string (uint256 etc.)
    return BigInt(value).toString(16).padStart(64, "0");
  }
  throw new Error(`Unsupported argument type: ${typeof value}`);
}

// ─── Keccak-256 ──────────────────────────────────────────────────────────────
// Delegates to js-sha3, which is already a project dependency and is verified
// correct for Ethereum's keccak256 (domain separation byte 0x01).

import { keccak256 as _keccak256 } from "js-sha3";

/**
 * Compute keccak256 of the given Buffer and return the 32-byte hex digest.
 * Uses js-sha3 for correctness (Ethereum-compatible domain separation).
 * @internal
 */
export function keccak256Pure(input: Buffer): string {
  return _keccak256(input);
}

// ─── Log decoding helpers ─────────────────────────────────────────────────────

/** @internal */
export function decodeLogEntries(rawLogs: unknown[]): LogEntry[] {
  if (!Array.isArray(rawLogs)) return [];
  return rawLogs.slice(0, 1000).map((raw) => {
    const log = raw as Record<string, unknown>;
    const topics = Array.isArray(log["topics"])
      ? (log["topics"] as string[]).map((t) => String(t))
      : [];
    return {
      address: typeof log["address"] === "string" ? log["address"].toLowerCase() : "0x0000000000000000000000000000000000000000",
      topics,
      data: typeof log["data"] === "string" ? log["data"] : "0x",
    };
  });
}

/** @internal */
export function hexToDecimalString(hex: string): string {
  if (!hex || hex === "0x") return "0";
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  return BigInt("0x" + clean).toString(10);
}

/** @internal */
export function normalizeHex(value: string): string {
  if (!value || value === "0x") return "0x0000000000000000000000000000000000000000000000000000000000000000";
  const clean = value.startsWith("0x") ? value.slice(2) : value;
  return "0x" + clean.toLowerCase().padStart(64, "0");
}
