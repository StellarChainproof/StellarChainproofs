import { Command } from "commander";
import chalk from "chalk";
import { startLspDaemon, type LspDaemonOptions, type TransportType } from "@chainproof/core";

export function registerLspCommand(program: Command, printBanner: () => void) {
  program
    .command("lsp")
    .description("Start the ChainProof Language Server Protocol (LSP) Daemon")
    .option("--transport <type>", "Transport mode: stdio|ipc|tcp", "stdio")
    .option("--socket <path>", "Path to IPC domain socket (used when transport === 'ipc')")
    .option("--port <number>", "Port for TCP server (used when transport === 'tcp')", "8433")
    .option("--token <token>", "Authentication secret token for IPC or TCP sockets")
    .option("--max-queue <number>", "Maximum pending analysis queue depth", "50")
    .option("--max-concurrent <number>", "Maximum concurrent analysis tasks", "2")
    .option("--debounce <ms>", "Debounce delay for file edits in ms", "150")
    .action(
      (opts: {
        transport: string;
        socket?: string;
        port: string;
        token?: string;
        maxQueue: string;
        maxConcurrent: string;
        debounce: string;
      }) => {
        const transport = opts.transport as TransportType;
        if (!["stdio", "ipc", "tcp"].includes(transport)) {
          console.error(chalk.red("  ❌ Invalid transport mode. Use stdio, ipc, or tcp."));
          process.exit(1);
        }

        const port = parseInt(opts.port, 10);
        if (isNaN(port) || port < 1 || port > 65535) {
          console.error(chalk.red("  ❌ Invalid port number"));
          process.exit(1);
        }

        const maxQueueDepth = parseInt(opts.maxQueue, 10);
        const maxConcurrent = parseInt(opts.maxConcurrent, 10);
        const debounceMs = parseInt(opts.debounce, 10);

        if (transport !== "stdio") {
          printBanner();
          console.log(
            chalk.cyan(
              `  Starting ChainProof LSP Daemon...\n` +
                `  Transport  : ${transport.toUpperCase()}\n` +
                (transport === "ipc" ? `  Socket     : ${opts.socket ?? "default"}\n` : "") +
                (transport === "tcp" ? `  Port       : ${port}\n` : "") +
                `  Auth Token : ${opts.token ? chalk.green("enabled") : chalk.yellow("disabled (open)")}\n` +
                `  Max Queue  : ${maxQueueDepth}\n`
            )
          );
        }

        const daemonOptions: LspDaemonOptions = {
          transport,
          socketPath: opts.socket,
          port,
          authToken: opts.token ?? process.env.CHAINPROOF_LSP_TOKEN,
          maxQueueDepth,
          maxConcurrent,
          debounceMs,
          logger: (level, msg) => {
            if (transport !== "stdio") {
              const color = level === "error" ? chalk.red : level === "warn" ? chalk.yellow : chalk.gray;
              console.log(color(`[LSP ${level.toUpperCase()}] ${msg}`));
            }
          },
        };

        try {
          const daemon = startLspDaemon(daemonOptions);

          process.on("SIGINT", () => {
            if (transport !== "stdio") {
              console.log(chalk.yellow("\n  Shutting down LSP Daemon..."));
            }
            daemon.stop();
            process.exit(0);
          });

          process.on("SIGTERM", () => {
            daemon.stop();
            process.exit(0);
          });
        } catch (err) {
          console.error(chalk.red(`  ❌ Failed to start LSP Daemon: ${err}`));
          process.exit(1);
        }
      }
    );
}
