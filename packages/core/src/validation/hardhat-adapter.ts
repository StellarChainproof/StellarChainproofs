/**
 * Hardhat Network EVM adapter.
 *
 * Manages an in-process or spawned `hardhat node` JSON-RPC server.
 * Hardhat Network supports:
 * - `evm_snapshot` / `evm_revert` for deterministic replay
 * - `hardhat_setStorageAt` for storage overrides
 * - `hardhat_setBalance` for balance manipulation
 * - Fork mode via `--fork` flag
 *
 * @remarks
 * The adapter spawns `npx hardhat node` in a temp directory with a
 * minimal `hardhat.config.js` so it works without any project setup.
 * This means Hardhat Network is available whenever `hardhat` is installed
 * globally or in the project's devDependencies.
 */

import * as childProcess from "child_process";
import * as fs from "fs";
import * as net from "net";
import * as os from "os";
import * as path from "path";
import type {
  AccountSpec,
  CallResult,
  CallSpec,
  ContractSpec,
  ResolvedResourceLimits,
  ScenarioResourceLimits,
  ValidationCancellationSignal,
} from "./types";
import {
  AdapterCrashError,
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

const DEFAULT_HH_ACCOUNTS = [
  "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
];

/** Minimal hardhat.config.js written to the temp dir. */
function buildHardhatConfig(port: number, forkUrl?: string, forkBlockNumber?: number): string {
  const forkSection = forkUrl
    ? `forking: { url: ${JSON.stringify(forkUrl)}${forkBlockNumber ? `, blockNumber: ${forkBlockNumber}` : ""} },`
    : "";
  return `
require("@nomicfoundation/hardhat-toolbox");
module.exports = {
  solidity: "0.8.24",
  networks: {
    hardhat: {
      ${forkSection}
      mining: { auto: true, interval: 0 },
    },
    localhost: {
      url: "http://127.0.0.1:${port}",
    },
  },
};
`.trim();
}

export class HardhatAdapter implements EvmAdapter {
  readonly type = "hardhat" as const;
  #version = "unknown";
  #rpcUrl = "";
  #port = 0;
  #proc: childProcess.ChildProcess | null = null;
  #disposed = false;
  #watchdog: NodeJS.Timeout | null = null;
  #tempDir: string | null = null;

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

    // Create temp workspace
    this.#tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "chainproof-hh-"));
    const configPath = path.join(this.#tempDir, "hardhat.config.js");
    fs.writeFileSync(
      configPath,
      buildHardhatConfig(this.#port, this.opts.forkUrl, this.opts.forkBlockNumber),
      "utf8",
    );

    const binary = this.opts.binaryPath ?? "npx";
    const args = binary === "npx"
      ? ["hardhat", "node", "--port", String(this.#port), "--hostname", "127.0.0.1"]
      : ["node", "--port", String(this.#port), "--hostname", "127.0.0.1"];

    const verbosity = this.opts.verbosity ?? 0;
    const proc = childProcess.spawn(binary, args, {
      cwd: this.#tempDir,
      stdio: verbosity >= 2 ? "pipe" : ["ignore", "ignore", "ignore"],
      env: { ...process.env },
      detached: false,
    });

    this.#proc = proc;

    this.#watchdog = setTimeout(() => {
      if (this.#proc && !this.#proc.killed) {
        this.#proc.kill("SIGKILL");
      }
    }, resolved.timeoutMs + 10_000);

    try {
      await waitForRpc(this.#rpcUrl, 30_000); // Hardhat is slower to start
    } catch (err) {
      await this.dispose();
      throw new AdapterCrashError(
        "hardhat",
        `Failed to start hardhat node: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    try {
      const clientVersion = await jsonRpcCall(this.#rpcUrl, "web3_clientVersion", [], 5_000);
      if (typeof clientVersion === "string") {
        this.#version = clientVersion.split("/").slice(0, 2).join("/");
      }
    } catch {
      this.#version = "hardhat/unknown";
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
            if (this.#proc && !this.#proc.killed) this.#proc.kill("SIGKILL");
            resolve();
          }, 5_000);
          this.#proc!.once("exit", () => {
            clearTimeout(timeout);
            resolve();
          });
        });
      }
      this.#proc = null;
    }
    if (this.#tempDir) {
      try {
        fs.rmSync(this.#tempDir, { recursive: true, force: true });
      } catch {
        // ignore cleanup errors
      }
      this.#tempDir = null;
    }
  }

  async setupAccount(account: AccountSpec): Promise<void> {
    this.#assertNotDisposed();
    if (account.balance) {
      const balanceHex = "0x" + BigInt(account.balance).toString(16);
      await jsonRpcCall(this.#rpcUrl, "hardhat_setBalance", [account.address, balanceHex]);
    }
  }

  async deployContract(spec: ContractSpec, deployerAddress: string): Promise<string> {
    this.#assertNotDisposed();
    if (!spec.bytecode) {
      throw new ValidationError(
        `ContractSpec "${spec.name}" has no bytecode`,
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
    const r = receipt as Record<string, unknown>;
    const contractAddress = r["contractAddress"];
    if (!contractAddress || typeof contractAddress !== "string") {
      throw new ValidationError(
        `Deployment of "${spec.name}" produced no contractAddress`,
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
      : DEFAULT_HH_ACCOUNTS[0];

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
    const logs: import("./types").LogEntry[] = [];

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
        const decoded = decodeLogEntries(r["logs"]);
        logs.push(...decoded.slice(0, limits.maxLogs));
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
      callIndex: 0,
      reverted,
      revertReason,
      returnData,
      gasUsed,
      logs,
      storageDiff: [],
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
    await jsonRpcCall(this.#rpcUrl, "evm_revert", [snapshotId]);
  }

  async setNextBlockTimestamp(timestamp: number): Promise<void> {
    this.#assertNotDisposed();
    await jsonRpcCall(this.#rpcUrl, "evm_setNextBlockTimestamp", [timestamp]);
  }

  async mine(count = 1): Promise<void> {
    this.#assertNotDisposed();
    for (let i = 0; i < count; i++) {
      await jsonRpcCall(this.#rpcUrl, "evm_mine", []);
    }
  }

  async setStorageAt(address: string, slot: string, value: string): Promise<void> {
    this.#assertNotDisposed();
    await jsonRpcCall(this.#rpcUrl, "hardhat_setStorageAt", [address, slot, value]);
  }

  async #waitForReceipt(txHash: string, timeoutMs = 15_000): Promise<unknown> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const receipt = await jsonRpcCall(this.#rpcUrl, "eth_getTransactionReceipt", [txHash]);
      if (receipt !== null) return receipt;
      await new Promise<void>((r) => setTimeout(r, 200));
    }
    throw new ValidationError(
      `Transaction ${txHash} not mined within ${timeoutMs}ms`,
      "TIMEOUT",
    );
  }

  #assertNotDisposed(): void {
    if (this.#disposed) {
      throw new AdapterCrashError("hardhat", "Adapter has been disposed");
    }
  }
}

/**
 * Detect whether `npx hardhat` is usable in the current environment.
 */
export async function isHardhatAvailable(binaryPath = "npx"): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = childProcess.spawn(binaryPath, ["hardhat", "--version"], {
      stdio: ["ignore", "pipe", "ignore"],
    });
    proc.on("error", () => resolve(false));
    proc.on("exit", (code) => resolve(code === 0));
    proc.stdout.resume();
    setTimeout(() => {
      if (!proc.killed) proc.kill();
      resolve(false);
    }, 5_000);
  });
}
