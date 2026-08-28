# Language Server Protocol (LSP) Daemon

The ChainProof Language Server Protocol (LSP) Daemon delivers real-time Solidity security feedback, vulnerability detection, and gas optimization directly inside text editors and IDEs (VS Code, Neovim, Emacs, JetBrains).

---

## Architecture Overview

```
 ┌────────────────┐       JSON-RPC 2.0 over Stdio/Socket      ┌───────────────────────────────────┐
 │                │ ────────────────────────────────────────> │  @chainproof/core LSP Daemon      │
 │  Editor Client │                                           │  - DocumentStore (In-memory AST)  │
 │  (VS Code, etc)│ <──────────────────────────────────────── │  - AnalysisService (Debounced)    │
 └────────────────┘   Diagnostics, Hovers, QuickFixes, TM    └───────────────────────────────────┘
```

The LSP Daemon decouples scan orchestration from individual editor extensions by providing an incremental, cancellable, transport-neutral service:

- **Document Store (`DocumentStore`)**: Manages in-memory document overlays for active editor buffers, handling text edits, position/offset conversions, version tracking, AST LRU caching, and import-graph dependency tracking.
- **Analysis Service (`AnalysisService`)**: Schedules debounced, cancellable incremental security scans using bounded queues and load shedding. Reuses ASTs and import graphs across open overlays and on-disk files.
- **Transports (`LspTransportListener`)**: Supports standard input/output streams (`stdio`), authenticated local Unix/IPC domain sockets (`ipc`), and TCP socket listeners (`tcp`).
- **Language Intelligence Providers**:
  - **Diagnostics**: Real-time error and warning highlights for SWC vulnerabilities and gas optimization hints.
  - **Quick Fixes & Code Actions**: Deterministic remediations (e.g., replacing `tx.origin` with `msg.sender`, checking call return values), inline comment suppression insertion (`// chainproof-disable-next-line`), rule documentation links, and evidence path navigation.
  - **Hover**: Rich Markdown hover cards detailing vulnerability mechanisms, confidence ratings, and recommendations.
  - **Document Symbols**: Hierarchical symbols for contracts, interfaces, functions, state variables, and events.
  - **Call Hierarchy**: Incoming and outgoing call hierarchy based on function calls.
  - **References**: Evidence trail location resolution across workspace files.

---

## Running the LSP Daemon

### CLI Usage

Start the LSP daemon using the `chainproof lsp` command:

```bash
# Stdio mode (default, for editor child processes)
chainproof lsp --transport stdio

# Authenticated local IPC socket mode
chainproof lsp --transport ipc --socket /tmp/chainproof-lsp.sock --token MY_SECRET_TOKEN

# Authenticated TCP socket mode
chainproof lsp --transport tcp --port 8433 --token MY_SECRET_TOKEN
```

### CLI Options

| Flag | Description | Default |
| --- | --- | --- |
| `--transport <type>` | Transport protocol: `stdio`, `ipc`, or `tcp` | `stdio` |
| `--socket <path>` | Domain socket file path (IPC mode) | `/tmp/chainproof-lsp.sock` |
| `--port <number>` | TCP port (TCP mode) | `8433` |
| `--token <token>` | Shared authentication secret token | `env.CHAINPROOF_LSP_TOKEN` |
| `--max-queue <n>` | Maximum pending request queue depth | `50` |
| `--max-concurrent <n>`| Maximum concurrent background scan tasks | `2` |
| `--debounce <ms>` | Debounce delay for document edits in ms | `150` |

---

## Socket Security & Authentication Model

When running over IPC or TCP sockets, local security boundaries are enforced:

1. **Localhost Binding**: TCP socket listeners strictly bind to `127.0.0.1` to prevent external network exposure.
2. **Token Authentication**: When `--token <token>` or `CHAINPROOF_LSP_TOKEN` is configured, clients must send an initial handshake line upon connection:
   ```text
   AUTH <MY_SECRET_TOKEN>
   ```
   If authentication fails or times out (5 seconds), the daemon responds with `AUTH_FAILED` and immediately closes the connection.
3. **Bounded Resources & Load Shedding**: Analysis queues are bounded by depth (`maxQueueDepth`). When capacity is exceeded, oldest pending analysis jobs are safely rejected to prevent memory exhaustion or editor freeze during rapid typing.

---

## Protocol Extensions (Custom JSON-RPC Requests)

The ChainProof LSP Daemon extends standard LSP with custom JSON-RPC request endpoints:

### `chainproof/threatModel`
Generates a comprehensive STRIDE/DeFi threat model for open or workspace contracts.

- **Params**:
  ```json
  {
    "uri": "file:///path/to/Contract.sol",
    "minSeverity": "low"
  }
  ```
- **Response**:
  ```json
  {
    "threatModel": { ... },
    "markdown": "# Threat Model Report...",
    "json": "{ ... }"
  }
  ```

### `chainproof/scanReport`
Generates a full workspace audit report formatted as Markdown, JSON, or ASCII Table.

- **Params**:
  ```json
  {
    "format": "markdown",
    "minSeverity": "low"
  }
  ```
- **Response**:
  ```json
  {
    "format": "markdown",
    "content": "# Audit Report...",
    "summary": { "critical": 0, "high": 1, "total": 3 }
  }
  ```

### `chainproof/clearCache`
Clears internal AST caches and resets incremental watch state.

- **Response**:
  ```json
  {
    "cleared": true,
    "message": "AST cache and watch state cleared successfully."
  }
  ```

### `chainproof/status`
Returns daemon operational statistics, queue depth, active analyses, and cache hit/miss counts.

- **Response**:
  ```json
  {
    "openDocumentsCount": 2,
    "queueDepth": 0,
    "activeAnalyses": 0,
    "cacheStats": { "hits": 42, "misses": 5, "entries": 47 },
    "uptimeSeconds": 120,
    "workspaceFolders": ["/path/to/project"]
  }
  ```

---

## Troubleshooting

- **No diagnostics displayed**: Ensure the active file is a `.sol` file and contains valid Solidity syntax. Check output logs via `--transport stdio` or output channel.
- **High CPU / Memory Usage**: Adjust `--debounce` (e.g. `--debounce 300`) or reduce `--max-concurrent` (e.g. `--max-concurrent 1`).
- **Socket Auth Failures**: Confirm `--token` supplied to CLI matches the secret header sent by client connection socket scripts.
