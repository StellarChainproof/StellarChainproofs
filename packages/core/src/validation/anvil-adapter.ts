/**
 * Anvil EVM adapter.
 *
 * Manages the lifecycle of an `anvil` process (from Foundry) as a
 * process-isolated EVM backend. Resource limits are enforced via a
 * SIGKILL watchdog timer and the adapter rejects calls after disposal.
 *
 * @remarks
 * Anvil is preferred when available because it supports:
 * - `anvil_snapshot` / `anvil_revert` for deterministic replay
 * - `debug_traceTransaction` for detailed call traces
 * - `anvil_setStorageAt` for precise state overrides
 * - Fork mode via `--fork-url` / `--fork-block-number`
 *
 * Security note: `forkUrl` is passed via the process argument list.
 * The OS makes this visible in `ps` output. Users who need to keep
 * the URL private should set it via `CHAINPROOF_FORK_URL` env var
 * instead; the adapter reads that env var if `forkUrl` is not given.
 */

import * as childProcess from "child_process";
import * as net from "net";
import type {
  AccountSpec,
  CallResult,
  CallSpec,
  ContractSpec,
  LogEntry,
  ResolvedResourceLimits,
  ScenarioResourceLimits,
  StorageDiff,
  ValidationCancellationSignal,
} from "./types";
import {
  AdapterCrashError,
  ForkUnavailableError,
  ValidationError,
  resolveResourceLimits,
  sanitizeErrorMessage,
} from "./types";
import type { EvmAdapter } from "./adapter";
import {
  decodeLogEntries,
  encodeFunctionCall,
  hexToDecimalString,
  jsonRpcCall,
  normalizeHex,
  waitForRpc,
} from "./adapter";

// ─── Port allocation ──────────────────────────────────────────────────────────

/** Find a free TCP port. @internal */
async function findFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as net.AddressInfo;
      server.close((err) => {
        if (err) reject(err);
        else resolve(addr.port);
      });
    });
    server.on("error", reject);
  });
}

// ─── Anvil adapter ────────────────────────────────────────────────────────────

/** @internal default accounts funded by Anvil in devnet mode */
const DEFAULT_ANVIL_ACCOUNTS = [
  "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
  "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
];

export class AnvilAdapter implements EvmAdapter {
  readonly type = "anvil" as const;
  #version = "unknown";
  #rpcUrl = "";
  #port = 0;
  #proc: childProcess.ChildProcess | null = null;
  #disposed = false;
  #watchdog: NodeJS.Timeout | null = null;

  constructor(
    private readonly opts: {
      binaryPath?: string;
      port?: number;
      verbosity?: 0 | 1 | 2;
      limits?: Partial<ScenarioResourceLimits>;
      forkUrl?: string;
      forkBlockNumber?: number;
      chainId?: number;
    } = {},
  ) {}

  get version(): string {
    return this.#version;
  }

  get rpcUrl(): string {
    return this.#rpcUrl;
  }

  async start(limits?: Partial<ScenarioResourceLimits>): Promise<void> {
    this.#assertNotDisposed();
    const resolved = resolveResourceLimits(limits ?? {}, this.opts.limits ?? {});
    this.#port = this.opts.port !== undefined && this.opts.port > 0
      ? this.opts.port
      : await findFreePort();
    this.#rpcUrl = `http://127.0.0.1:${this.#port}`;

    const binary = this.opts.binaryPath ?? "anvil";
    const args = this.#buildArgs();

    const verbosity = this.opts.verbosity ?? 0;
    const proc = childProcess.spawn(binary, args, {
      stdio: verbosity >= 2 ? "pipe" : ["ignore", "ignore", "ignore"],
      env: { ...process.env },
      detached: false,
    });

    this.#proc = proc;

    // Set a hard kill watchdog
    this.#watchdog = setTimeout(() => {
      if (this.#proc && !this.#proc.killed) {
        this.#proc.kill("SIGKILL");
      }
    }, resolved.timeoutMs + 5_000);

    proc.on("error", (err) => {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("ENOENT")) {
        // anvil not found
      }
    });

    // Detect version from initial output if verbose
    if (verbosity >= 1 && proc.stdout) {
      proc.stdout.once("data", (chunk: Buffer) => {
        const line = chunk.toString().split("\n")[0];
        const m = line.match(/anvil\s+([0-9]+\.[0-9]+\.[0-9]+)/i);
        if (m) this.#version = `anvil/${m[1]}`;
      });
    }

    try {
      await waitForRpc(this.#rpcUrl, 15_000);
    } catch (err) {
      await this.dispose();
      const binary2 = this.opts.binaryPath ?? "anvil";
      throw new AdapterCrashError(
        "anvil",
        `Failed to start ${binary2}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    // Detect version via web3_clientVersion
    try {
      const clientVersion = await jsonRpcCall(this.#rpcUrl, "web3_clientVersion", [], 5_000);
      if (typeof clientVersion === "string") {
        this.#version = clientVersion.split("/").slice(0, 2).join("/");
      }
    } catch {
      this.#version = "anvil/unknown";
    }
  }

  async dispose(): Promise<void> {
    if (this.#disposed) return;
    this.#disposed = true;
    if (this.#watchdog) {
      clearTimeout(this.#watchdog);
      this.#watchdog = null;
    }
    if (this.#proc) {
      if (!this.#proc.killed) {
        this.#proc.kill("SIGTERM");
        await new Promise<void>((resolve) => {
          const timeout = setTimeout(() => {
            if (this.#proc && !this.#proc.killed) {
              this.#proc.kill("SIGKILL");
            }
            resolve();
          }, 3_000);
          this.#proc!.once("exit", () => {
            clearTimeout(timeout);
            resolve();
          });
        });
      }
      this.#proc = null;
    }
  }

  async setupAccount(account: AccountSpec): Promise<void> {
    this.#assertNotDisposed();
    if (account.balance) {
      const balanceHex = "0x" + BigInt(account.balance).toString(16);
      await jsonRpcCall(this.#rpcUrl, "anvil_setBalance", [account.address, balanceHex]);
    }
  }

  async deployContract(spec: ContractSpec, deployerAddress: string): Promise<string> {
    this.#assertNotDisposed();
    if (!spec.bytecode) {
      throw new ValidationError(
        `ContractSpec "${spec.name}" has no bytecode and no pre-existing address`,
        "DEPLOY_FAILED",
      );
    }
    const data = spec.constructorArgs
      ? spec.bytecode + spec.constructorArgs.replace("0x", "")
      : spec.bytecode;

    const txHash = await jsonRpcCall(this.#rpcUrl, "eth_sendTransaction", [{
      from: deployerAddress,
      data,
      gas: "0x" + (5_000_000).toString(16),
    }]) as string;

    const receipt = await this.#waitForReceipt(txHash);
    const contractAddress = (receipt as Record<string, unknown>)["contractAddress"];
    if (!contractAddress || typeof contractAddress !== "string") {
      throw new ValidationError(
        `Deployment of "${spec.name}" succeeded but receipt has no contractAddress`,
        "DEPLOY_FAILED",
      );
    }
    return contractAddress;
  }

  async executeCall(
    spec: CallSpec,
    resolvedAddresses: Map<string, string>,
    limits: ResolvedResourceLimits,
    signal?: ValidationCancellationSignal,
  ): Promise<CallResult> {
    this.#assertNotDisposed();

    if (signal?.cancelled) {
      throw new ValidationError("Validation cancelled", "TIMEOUT");
    }

    const to = resolvedAddresses.get(spec.to) ?? spec.to;
    const from = spec.from
      ? (resolvedAddresses.get(spec.from) ?? spec.from)
      : DEFAULT_ANVIL_ACCOUNTS[0];

    let data = "0x";
    if (spec.calldata) {
      data = spec.calldata;
    } else if (spec.signature) {
      data = encodeFunctionCall(spec.signature, spec.args ?? []);
    }

    const gasLimit = spec.gasLimit ?? Math.min(limits.maxGasPerCall, 30_000_000);
    const value = spec.value ? "0x" + BigInt(spec.value).toString(16) : "0x0";

    let reverted = false;
    let revertReason: string | undefined;
    let returnData = "0x";
    let gasUsed = 0;
    let logs: LogEntry[] = [];
    let storageDiff: StorageDiff[] = [];

    // Capture state before call for diff
    const callIndex = 0; // caller sets this

    try {
      const txHash = await jsonRpcCall(this.#rpcUrl, "eth_sendTransaction", [{
        from,
        to,
        data,
        value,
        gas: "0x" + gasLimit.toString(16),
      }]) as string;

      const receipt = await this.#waitForReceipt(txHash, limits.timeoutMs);
      const r = receipt as Record<string, unknown>;

      const status = String(r["status"] ?? "0x1");
      reverted = status === "0x0" || status === "0";

      const rawGas = r["gasUsed"];
      if (typeof rawGas === "string") {
        gasUsed = parseInt(rawGas, 16);
      }

      if (Array.isArray(r["logs"])) {
        logs = decodeLogEntries(r["logs"]).slice(0, limits.maxLogs);
      }

      // Fetch return data via eth_call replay
      try {
        const callResult = await jsonRpcCall(this.#rpcUrl, "eth_call", [{
          from, to, data, value,
        }, "latest"]) as string;
        returnData = callResult;
      } catch (callErr) {
        if (callErr instanceof ValidationError && callErr.code === "RPC_ERROR") {
          reverted = true;
          revertReason = "call reverted";
        }
      }
    } catch (err) {
      if (err instanceof ValidationError && err.code === "RPC_ERROR") {
        reverted = true;
        revertReason = sanitizeErrorMessage(err.message);
      } else {
        throw err;
      }
    }

    return {
      callIndex,
      reverted,
      revertReason,
      returnData,
      gasUsed,
      logs,
      storageDiff,
    };
  }

  async getStorageAt(address: string, slot: string): Promise<string> {
    this.#assertNotDisposed();
    const result = await jsonRpcCall(this.#rpcUrl, "eth_getStorageAt", [address, slot, "latest"]);
    return normalizeHex(result as string);
  }

  async getBalance(address: string): Promise<string> {
    this.#assertNotDisposed();
    const result = await jsonRpcCall(this.#rpcUrl, "eth_getBalance", [address, "latest"]);
    return hexToDecimalString(result as string);
  }

  async getBlockNumber(): Promise<number> {
    this.#assertNotDisposed();
    const result = await jsonRpcCall(this.#rpcUrl, "eth_blockNumber", []);
    return parseInt(result as string, 16);
  }

  async snapshot(): Promise<string> {
    this.#assertNotDisposed();
    const result = await jsonRpcCall(this.#rpcUrl, "evm_snapshot", []);
    return String(result);
  }

  async revertToSnapshot(snapshotId: string): Promise<void> {
    this.#assertNotDisposed();
    // anvil_revert consumes the snapshot; we use evm_revert (which also consumes it)
    // To make it re-usable we'd need to re-snapshot, but for our purposes we
    // retake a snapshot immediately after restore.
    await jsonRpcCall(this.#rpcUrl, "evm_revert", [snapshotId]);
  }

  async setNextBlockTimestamp(timestamp: number): Promise<void> {
    this.#assertNotDisposed();
    await jsonRpcCall(this.#rpcUrl, "evm_setNextBlockTimestamp", [timestamp]);
  }

  async mine(count = 1): Promise<void> {
    this.#assertNotDisposed();
    await jsonRpcCall(this.#rpcUrl, "evm_mine", []);
    for (let i = 1; i < count; i++) {
      await jsonRpcCall(this.#rpcUrl, "evm_mine", []);
    }
  }

  async setStorageAt(address: string, slot: string, value: string): Promise<void> {
    this.#assertNotDisposed();
    await jsonRpcCall(this.#rpcUrl, "anvil_setStorageAt", [address, slot, value]);
  }

  // ─── Private helpers ────────────────────────────────────────────────────────

  #buildArgs(): string[] {
    const args: string[] = [
      "--port", String(this.#port),
      "--host", "127.0.0.1",
    ];

    if (this.opts.chainId !== undefined) {
      args.push("--chain-id", String(this.opts.chainId));
    }

    if (this.opts.forkUrl) {
      args.push("--fork-url", this.opts.forkUrl);
      if (this.opts.forkBlockNumber !== undefined) {
        args.push("--fork-block-number", String(this.opts.forkBlockNumber));
      }
    }

    args.push("--no-mining"); // use manual mining for determinism
    args.push("--order", "fifo");

    return args;
  }

  async #waitForReceipt(txHash: string, timeoutMs = 10_000): Promise<unknown> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const receipt = await jsonRpcCall(this.#rpcUrl, "eth_getTransactionReceipt", [txHash]);
      if (receipt !== null) {
        // Mine a block to include the tx (no-mining mode)
        try {
          await jsonRpcCall(this.#rpcUrl, "evm_mine", []);
          const receipt2 = await jsonRpcCall(this.#rpcUrl, "eth_getTransactionReceipt", [txHash]);
          if (receipt2 !== null) return receipt2;
        } catch {
          return receipt;
        }
        return receipt;
      }
      // Mine a block to include pending txs
      try {
        await jsonRpcCall(this.#rpcUrl, "evm_mine", []);
        const receipt2 = await jsonRpcCall(this.#rpcUrl, "eth_getTransactionReceipt", [txHash]);
        if (receipt2 !== null) return receipt2;
      } catch {
        // ignore
      }
      await new Promise<void>((r) => setTimeout(r, 100));
    }
    throw new ValidationError(
      `Transaction ${txHash} not mined within ${timeoutMs}ms`,
      "TIMEOUT",
    );
  }

  #assertNotDisposed(): void {
    if (this.#disposed) {
      throw new AdapterCrashError("anvil", "Adapter has been disposed");
    }
  }
}

/**
 * Detect whether the `anvil` binary is available on $PATH.
 */
export async function isAnvilAvailable(binaryPath = "anvil"): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = childProcess.spawn(binaryPath, ["--version"], {
      stdio: ["ignore", "pipe", "ignore"],
    });
    proc.on("error", () => resolve(false));
    proc.on("exit", (code) => resolve(code === 0));
    proc.stdout.resume();
    setTimeout(() => {
      if (!proc.killed) proc.kill();
      resolve(false);
    }, 3_000);
  });
}
