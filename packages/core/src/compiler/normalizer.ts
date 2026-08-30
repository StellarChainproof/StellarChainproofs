/**
 * @packageDocumentation
 * @chainproof/core — Normalizer for ABI, Storage Layout, Bytecode & Diagnostics
 */

import { createHash } from "crypto";
import type {
  NormalizedABIEntry,
  NormalizedABIParam,
  NormalizedStorageLayout,
  NormalizedStorageItem,
  NormalizedStorageType,
  NormalizedBytecode,
  NormalizedCompilerDiagnostic,
} from "./types";

// ─── Keccak-256 Pure Implementation ──────────────────────────────────────────

const [SHA3_PI, SHA3_ROTL, _SHA3_IOTA] = [[], [], []] as [number[], number[], bigint[]];
const _0n = 0n, _1n = 1n, _2n = 2n, _7n = 7n, _256n = 256n, _0x71n = 0x71n;
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  SHA3_ROTL.push((((round + 1) * (round + 2)) / 2) % 64);
  let t = _0n;
  for (let j = 0; j < 7; j++) {
    R = ((R << _1n) ^ ((R >> _7n) * _0x71n)) % _256n;
    if (R & _2n) t ^= _1n << ((_1n << BigInt(j)) - _1n);
  }
  _SHA3_IOTA.push(t);
}

const SHA3_IOTA_H = new Uint32Array(24);
const SHA3_IOTA_L = new Uint32Array(24);
for (let i = 0; i < 24; i++) {
  SHA3_IOTA_H[i] = Number(_SHA3_IOTA[i] & 0xffffffffn);
  SHA3_IOTA_L[i] = Number((_SHA3_IOTA[i] >> 32n) & 0xffffffffn);
}

const rotlSH = (h: number, l: number, s: number) => (h << s) | (l >>> (32 - s));
const rotlSL = (h: number, l: number, s: number) => (l << s) | (h >>> (32 - s));
const rotlBH = (h: number, l: number, s: number) => (l << (s - 32)) | (h >>> (64 - s));
const rotlBL = (h: number, l: number, s: number) => (h << (s - 32)) | (l >>> (64 - s));
const rotlH = (h: number, l: number, s: number) => (s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s));
const rotlL = (h: number, l: number, s: number) => (s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s));

function keccakP(s: Uint32Array): void {
  const B = new Uint32Array(10);
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 10; x++) {
      B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    }
    for (let x = 0; x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0; y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    let curH = s[2];
    let curL = s[3];
    for (let t = 0; t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    for (let y = 0; y < 50; y += 10) {
      for (let x = 0; x < 10; x++) {
        B[x] = s[y + x];
      }
      for (let x = 0; x < 10; x++) {
        s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
      }
    }
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
}

/**
 * Computes Keccak-256 hash of a string or buffer (standard Ethereum hashing).
 */
export function keccak256(data: string | Buffer): string {
  const bytes = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
  const blockLen = 136;
  const state = new Uint8Array(200);
  const state32 = new Uint32Array(state.buffer);

  let pos = 0;
  for (let i = 0; i < bytes.length; i++) {
    state[pos++] ^= bytes[i];
    if (pos === blockLen) {
      keccakP(state32);
      pos = 0;
    }
  }

  state[pos] ^= 0x01;
  state[blockLen - 1] ^= 0x80;
  keccakP(state32);

  return Buffer.from(state.buffer, 0, 32).toString("hex");
}

/**
 * Computes standard 4-byte selector from function signature (e.g. "0xa9059cbb").
 */
export function computeFunctionSelector(signature: string): string {
  const hash = keccak256(signature);
  return "0x" + hash.slice(0, 8);
}

/**
 * Computes 32-byte event topic hash (e.g. "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef").
 */
export function computeEventTopic(signature: string): string {
  return "0x" + keccak256(signature);
}

// ─── ABI Normalization ────────────────────────────────────────────────────────

function buildParamCanonicalType(param: NormalizedABIParam): string {
  if (param.type.startsWith("tuple")) {
    const components = (param.components || []).map(buildParamCanonicalType).join(",");
    const suffix = param.type.slice(5); // handles tuple[] or tuple[2]
    return `(${components})${suffix}`;
  }
  return param.type;
}

export function buildEntrySignature(entry: NormalizedABIEntry): string {
  if (entry.type === "constructor") {
    const params = entry.inputs.map(buildParamCanonicalType).join(",");
    return `constructor(${params})`;
  }
  if (entry.type === "fallback") return "fallback()";
  if (entry.type === "receive") return "receive()";
  const name = entry.name ?? "";
  const params = entry.inputs.map(buildParamCanonicalType).join(",");
  return `${name}(${params})`;
}

export function normalizeABIEntry(raw: any): NormalizedABIEntry {
  const type = raw.type || "function";
  const inputs = (raw.inputs || []).map((inp: any) => ({
    name: inp.name || "",
    type: inp.type || "",
    internalType: inp.internalType,
    indexed: inp.indexed,
    components: inp.components ? inp.components.map(normalizeABIEntry) : undefined,
  }));

  const outputs = raw.outputs
    ? (raw.outputs as any[]).map((out: any) => ({
        name: out.name || "",
        type: out.type || "",
        internalType: out.internalType,
        components: out.components ? out.components.map(normalizeABIEntry) : undefined,
      }))
    : undefined;

  const entry: NormalizedABIEntry = {
    type,
    name: raw.name,
    inputs,
    outputs,
    stateMutability: raw.stateMutability || (raw.constant ? "view" : raw.payable ? "payable" : "nonpayable"),
    anonymous: raw.anonymous,
  };

  const signature = buildEntrySignature(entry);
  entry.signature = signature;

  if (type === "function" || type === "error") {
    entry.selector = computeFunctionSelector(signature);
  } else if (type === "event") {
    entry.selector = computeEventTopic(signature);
  }

  return entry;
}

export function normalizeABI(rawAbi: any[]): NormalizedABIEntry[] {
  if (!Array.isArray(rawAbi)) return [];
  return rawAbi.map(normalizeABIEntry);
}

// ─── Storage Layout Normalization ─────────────────────────────────────────────

export function normalizeStorageLayout(rawStorage: any): NormalizedStorageLayout {
  const items: NormalizedStorageItem[] = [];
  const types: Record<string, NormalizedStorageType> = {};

  const rawItems = Array.isArray(rawStorage?.storage) ? rawStorage.storage : [];
  const rawTypes = rawStorage?.types && typeof rawStorage.types === "object" ? rawStorage.types : {};

  let maxSlot = 0;
  let hasPacking = false;
  const slotOffsets = new Map<number, number[]>();

  for (const item of rawItems) {
    const slot = Number(item.slot ?? 0);
    const offset = Number(item.offset ?? 0);
    if (slot > maxSlot) maxSlot = slot;

    const offsets = slotOffsets.get(slot) ?? [];
    offsets.push(offset);
    slotOffsets.set(slot, offsets);
    if (offsets.length > 1) {
      hasPacking = true;
    }

    items.push({
      astId: item.astId,
      contract: String(item.contract ?? ""),
      label: String(item.label ?? ""),
      offset,
      slot,
      type: String(item.type ?? ""),
    });
  }

  for (const [typeKey, typeVal] of Object.entries(rawTypes)) {
    const tv = typeVal as any;
    types[typeKey] = {
      encoding: String(tv.encoding ?? "inplace"),
      label: String(tv.label ?? typeKey),
      numberOfBytes: Number(tv.numberOfBytes ?? 32),
      key: tv.key ? String(tv.key) : undefined,
      value: tv.value ? String(tv.value) : undefined,
      members: Array.isArray(tv.members)
        ? tv.members.map((m: any) => ({
            contract: String(m.contract ?? ""),
            label: String(m.label ?? ""),
            offset: Number(m.offset ?? 0),
            slot: Number(m.slot ?? 0),
            type: String(m.type ?? ""),
          }))
        : undefined,
    };
  }

  // Compute deterministic layout hash
  const canonicalItems = items.map((i) => `${i.slot}:${i.offset}:${i.label}:${i.type}`).join("|");
  const layoutHash = createHash("sha256").update(canonicalItems).digest("hex");

  return {
    storage: items,
    types,
    totalSlots: items.length > 0 ? maxSlot + 1 : 0,
    hasPacking,
    layoutHash,
  };
}

// ─── Bytecode Normalization ───────────────────────────────────────────────────

/**
 * Inspects hex bytecode, extracts metadata, and detects critical opcodes (PUSH0, TSTORE, TLOAD).
 */
export function normalizeBytecode(rawBytecode: string): NormalizedBytecode {
  const cleaned = (rawBytecode || "").replace(/^0x/, "").toLowerCase();
  const lengthBytes = Math.floor(cleaned.length / 2);

  // Check for PUSH0 opcode: 0x5f
  let hasPush0 = false;
  let hasTransient = false;

  const hexBytes: number[] = [];
  for (let i = 0; i < cleaned.length; i += 2) {
    hexBytes.push(parseInt(cleaned.slice(i, i + 2), 16));
  }

  // Parse opcodes skipping push data bytes
  for (let i = 0; i < hexBytes.length; i++) {
    const op = hexBytes[i];
    if (op === 0x5f) {
      hasPush0 = true;
    } else if (op === 0x5c || op === 0x5d) {
      // 0x5c = TLOAD, 0x5d = TSTORE (EIP-1153)
      hasTransient = true;
    } else if (op >= 0x60 && op <= 0x7f) {
      // PUSH1 through PUSH32 — skip push payload bytes
      const pushSize = op - 0x5f;
      i += pushSize;
    }
  }

  // Check CBOR metadata section at end of bytecode
  // Solidity metadata usually starts with 0xa26469706673 (IPFS) or 0xa265627a7a72 (bzzr)
  let metadataHash: string | undefined;
  let executableCode = cleaned;

  const ipfsMatch = cleaned.search(/a26469706673/);
  const bzzrMatch = cleaned.search(/a265627a7a72/);
  const metaStart = ipfsMatch !== -1 ? ipfsMatch : bzzrMatch;

  if (metaStart !== -1 && metaStart > cleaned.length - 200) {
    metadataHash = cleaned.slice(metaStart);
    executableCode = cleaned.slice(0, metaStart);
  }

  const executableCodeHash = createHash("sha256").update(executableCode).digest("hex");

  return {
    object: cleaned.length > 0 ? `0x${cleaned}` : "0x",
    lengthBytes,
    hasPush0,
    hasTransientStorage: hasTransient,
    metadataHash,
    executableCodeHash,
  };
}

// ─── Diagnostic Normalization ─────────────────────────────────────────────────

export function normalizeCompilerDiagnostic(raw: any): NormalizedCompilerDiagnostic {
  let severity: NormalizedCompilerDiagnostic["severity"] = "error";
  const rawSev = String(raw.severity || raw.type || "").toLowerCase();
  if (rawSev.includes("warn")) {
    severity = "warning";
  } else if (rawSev.includes("info")) {
    severity = "info";
  }

  const message = String(raw.message || raw.formattedMessage || "");
  const formattedMessage = String(raw.formattedMessage || message);

  let sourceLocation: NormalizedCompilerDiagnostic["sourceLocation"];
  if (raw.sourceLocation) {
    sourceLocation = {
      file: String(raw.sourceLocation.file || ""),
      start: Number(raw.sourceLocation.start ?? 0),
      end: Number(raw.sourceLocation.end ?? 0),
      line: raw.sourceLocation.line ? Number(raw.sourceLocation.line) : undefined,
      column: raw.sourceLocation.column ? Number(raw.sourceLocation.column) : undefined,
    };
  }

  return {
    severity,
    type: String(raw.type || severity),
    message,
    formattedMessage,
    sourceLocation,
    errorCode: raw.errorCode ? String(raw.errorCode) : undefined,
  };
}
