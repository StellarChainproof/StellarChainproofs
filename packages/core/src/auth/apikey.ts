import * as crypto from "crypto";
import { ApiKeyRecord, CreateApiKeyOptions, Principal, RotateApiKeyOptions } from "./types";
import { createPrincipal } from "./principal";

export class ApiKeyManager {
  private keysById: Map<string, ApiKeyRecord> = new Map();
  private keysByHash: Map<string, ApiKeyRecord> = new Map();

  constructor(initialKeys: ApiKeyRecord[] = []) {
    for (const key of initialKeys) {
      this.registerKeyRecord(key);
    }
  }

  public static hashKey(rawKey: string): string {
    return crypto.createHash("sha256").update(rawKey).digest("hex");
  }

  public static generateRawKey(prefix = "cp_live_"): string {
    const bytes = crypto.randomBytes(24).toString("hex");
    return `${prefix}${bytes}`;
  }

  private registerKeyRecord(record: ApiKeyRecord): void {
    this.keysById.set(record.id, record);
    this.keysByHash.set(record.keyHash, record);
  }

  public createApiKey(options: CreateApiKeyOptions): { rawKey: string; record: ApiKeyRecord } {
    const rawKey = ApiKeyManager.generateRawKey();
    const keyHash = ApiKeyManager.hashKey(rawKey);
    const id = `key_${crypto.randomBytes(8).toString("hex")}`;
    const prefix = rawKey.slice(0, 12);

    const record: ApiKeyRecord = {
      id,
      tenantId: options.tenantId,
      projectId: options.projectId,
      name: options.name,
      keyHash,
      prefix,
      roles: options.roles ?? ["operator"],
      scopes: options.scopes ?? [],
      createdAt: Date.now(),
      expiresAt: options.expiresInMs ? Date.now() + options.expiresInMs : undefined,
      rateLimitTier: options.rateLimitTier ?? "standard",
    };

    this.registerKeyRecord(record);
    return { rawKey, record };
  }

  public authenticateApiKey(rawKey: string): { principal?: Principal; error?: string } {
    if (!rawKey || typeof rawKey !== "string") {
      return { error: "API key is required" };
    }

    const keyHash = ApiKeyManager.hashKey(rawKey);
    const record = this.keysByHash.get(keyHash);

    if (!record) {
      return { error: "Invalid API key" };
    }

    const now = Date.now();

    if (record.revokedAt) {
      return { error: `API key revoked: ${record.revocationReason ?? "No reason given"}` };
    }

    if (record.expiresAt && record.expiresAt < now) {
      if (record.gracePeriodExpiresAt && record.gracePeriodExpiresAt >= now) {
        // Valid during grace period
      } else {
        return { error: "API key expired" };
      }
    }

    record.lastUsedAt = now;

    const principal = createPrincipal({
      id: `usr_${record.tenantId}_${record.id}`,
      tenantId: record.tenantId,
      projectId: record.projectId,
      roles: record.roles,
      scopes: record.scopes,
      authMethod: "api-key",
      keyId: record.id,
      rateLimitTier: record.rateLimitTier,
      metadata: { keyName: record.name },
    });

    return { principal };
  }

  public rotateKey(options: RotateApiKeyOptions): { newRawKey: string; newRecord: ApiKeyRecord; oldRecord: ApiKeyRecord } {
    const oldRecord = this.keysById.get(options.keyId);
    if (!oldRecord) {
      throw new Error(`API key not found: ${options.keyId}`);
    }

    const gracePeriodMs = options.gracePeriodMs ?? 86400000;
    const now = Date.now();

    oldRecord.gracePeriodExpiresAt = now + gracePeriodMs;
    oldRecord.expiresAt = now;

    const { rawKey: newRawKey, record: newRecord } = this.createApiKey({
      tenantId: oldRecord.tenantId,
      projectId: oldRecord.projectId,
      name: `${oldRecord.name} (Rotated)`,
      roles: [...oldRecord.roles],
      scopes: [...oldRecord.scopes],
      rateLimitTier: oldRecord.rateLimitTier,
    });

    return { newRawKey, newRecord, oldRecord };
  }

  public revokeKey(keyId: string, reason?: string): ApiKeyRecord {
    const record = this.keysById.get(keyId);
    if (!record) {
      throw new Error(`API key not found: ${keyId}`);
    }

    record.revokedAt = Date.now();
    record.revocationReason = reason ?? "Revoked by administrator";
    return record;
  }

  public getKey(keyId: string): ApiKeyRecord | undefined {
    return this.keysById.get(keyId);
  }

  public listKeysForTenant(tenantId: string): ApiKeyRecord[] {
    const results: ApiKeyRecord[] = [];
    for (const key of this.keysById.values()) {
      if (key.tenantId === tenantId) {
        results.push(key);
      }
    }
    return results;
  }
}
