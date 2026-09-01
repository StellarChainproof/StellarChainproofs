import * as net from "net";
import * as fs from "fs";
import * as path from "path";
import type { Stream } from "stream";
import {
  StreamMessageReader,
  StreamMessageWriter,
  SocketMessageReader,
  SocketMessageWriter,
  type MessageReader,
  type MessageWriter,
} from "vscode-languageserver/node";
import type { LspDaemonOptions } from "./types";

export interface TransportConnection {
  reader: MessageReader;
  writer: MessageWriter;
  close: () => void;
}

export type ConnectionHandler = (connection: TransportConnection) => void;

/**
 * Transport abstraction supporting stdio streams and authenticated local IPC/TCP sockets.
 */
export class LspTransportListener {
  private readonly options: LspDaemonOptions;
  private netServer: net.Server | undefined;
  private isListening = false;

  constructor(options: LspDaemonOptions = {}) {
    this.options = options;
  }

  /**
   * Listen for incoming LSP client connections based on daemon options (stdio, IPC socket, or TCP port).
   */
  public listen(onConnection: ConnectionHandler): void {
    const transport = this.options.transport ?? "stdio";

    if (transport === "stdio") {
      const reader = new StreamMessageReader(process.stdin);
      const writer = new StreamMessageWriter(process.stdout);
      onConnection({
        reader,
        writer,
        close: () => {
          reader.dispose();
          writer.dispose();
        },
      });
      this.isListening = true;
      return;
    }

    this.netServer = net.createServer((socket: net.Socket) => {
      this.handleSocketConnection(socket, onConnection);
    });

    if (transport === "ipc") {
      const socketPath = this.options.socketPath ?? this.defaultIpcPath();
      // Remove stale socket file if it exists
      if (fs.existsSync(socketPath)) {
        try {
          fs.unlinkSync(socketPath);
        } catch {
          // Ignore
        }
      }

      // Ensure directory exists
      const dir = path.dirname(socketPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      this.netServer.listen(socketPath, () => {
        this.isListening = true;
        this.options.logger?.("info", `LSP IPC daemon listening on socket ${socketPath}`);
      });
    } else if (transport === "tcp") {
      const port = this.options.port ?? 8433;
      this.netServer.listen(port, "127.0.0.1", () => {
        this.isListening = true;
        this.options.logger?.("info", `LSP TCP daemon listening on 127.0.0.1:${port}`);
      });
    }
  }

  private handleSocketConnection(socket: net.Socket, onConnection: ConnectionHandler): void {
    // Socket authentication check if authToken is configured
    if (this.options.authToken) {
      let authenticated = false;
      const authTimeout = setTimeout(() => {
        if (!authenticated) {
          this.options.logger?.("warn", "Socket connection authentication timeout. Closing socket.");
          socket.destroy();
        }
      }, 5000);

      const onData = (data: Buffer) => {
        const line = data.toString("utf-8").trim();
        const authHeader = line.startsWith("AUTH ") ? line.slice(5) : line;

        if (authHeader === this.options.authToken) {
          authenticated = true;
          clearTimeout(authTimeout);
          socket.removeListener("data", onData);
          this.options.logger?.("info", "Socket client authenticated successfully.");
          this.bindSocketReaderWriter(socket, onConnection);
        } else {
          clearTimeout(authTimeout);
          this.options.logger?.("warn", "Socket authentication failed: invalid token.");
          socket.write("AUTH_FAILED\n");
          socket.destroy();
        }
      };

      socket.on("data", onData);
    } else {
      this.bindSocketReaderWriter(socket, onConnection);
    }
  }

  private bindSocketReaderWriter(socket: net.Socket, onConnection: ConnectionHandler): void {
    const reader = new SocketMessageReader(socket);
    const writer = new SocketMessageWriter(socket);

    const connection: TransportConnection = {
      reader,
      writer,
      close: () => {
        reader.dispose();
        writer.dispose();
        socket.destroy();
      },
    };

    onConnection(connection);
  }

  private defaultIpcPath(): string {
    if (process.platform === "win32") {
      return "\\\\.\\pipe\\chainproof-lsp";
    }
    return path.join(process.env.TMPDIR || "/tmp", "chainproof-lsp.sock");
  }

  /** Close transport listener server */
  public close(): void {
    if (this.netServer && this.isListening) {
      this.netServer.close();
      this.isListening = false;
    }
  }
}
