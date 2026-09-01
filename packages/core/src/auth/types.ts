export type Role = "admin" | "tenant-admin" | "operator" | "viewer";

export type Scope =
  | "scan:create"
  | "scan:read"
  | "scan:cancel"
  | "scan:delete"
  | "jobs:manage"
  | "metrics:read"
  | "audit:read"
  | "tenant:manage"
  | "keys:manage";

export type AuthMethod = "api-key" | "oidc-claim" | "bearer-token" | "system";

export interface Principal {
  id: string;
  tenantId: string;
  projectId?: string;
  roles: Role[];
  scopes: Scope[];
  authMethod: AuthMethod;
  keyId?: string;
  metadata?: Record<string, unknown>;
  rateLimitTier?: "free" | "standard" | "enterprise";
}

export interface ApiKeyRecord {
  id: string;
  tenantId: string;
  projectId?: string;
  name: string;
  keyHash: string;
  prefix: string;
  roles: Role[];
  scopes: Scope[];
  createdAt: number;
  expiresAt?: number;
  lastUsedAt?: number;
  revokedAt?: number;
  revocationReason?: string;
  rateLimitTier?: "free" | "standard" | "enterprise";
  gracePeriodExpiresAt?: number;
}

export interface CreateApiKeyOptions {
  tenantId: string;
  projectId?: string;
  name: string;
  roles?: Role[];
  scopes?: Scope[];
  expiresInMs?: number;
  rateLimitTier?: "free" | "standard" | "enterprise";
}

export interface RotateApiKeyOptions {
  keyId: string;
  gracePeriodMs?: number;
}

export interface OIDCClaimMapping {
  subClaim?: string;
  tenantClaim?: string;
  projectClaim?: string;
  rolesClaim?: string;
  scopesClaim?: string;
}

export interface OIDCConfig {
  issuer: string;
  audience: string;
  jwksUri?: string;
  claimMapping?: OIDCClaimMapping;
  allowUnverifiedInDev?: boolean;
}

export interface OIDCPayload {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  nbf?: number;
  iat?: number;
  tenant_id?: string;
  project_id?: string;
  roles?: string[];
  scopes?: string[];
  [key: string]: unknown;
}
