import { Principal, Role, Scope } from "./types";

export const DEFAULT_ROLE_SCOPES: Record<Role, Scope[]> = {
  admin: [
    "scan:create",
    "scan:read",
    "scan:cancel",
    "scan:delete",
    "jobs:manage",
    "metrics:read",
    "audit:read",
    "tenant:manage",
    "keys:manage",
  ],
  "tenant-admin": [
    "scan:create",
    "scan:read",
    "scan:cancel",
    "scan:delete",
    "jobs:manage",
    "metrics:read",
    "audit:read",
    "keys:manage",
  ],
  operator: ["scan:create", "scan:read", "scan:cancel", "metrics:read"],
  viewer: ["scan:read", "metrics:read"],
};

export const SYSTEM_PRINCIPAL: Principal = {
  id: "system-internal",
  tenantId: "system",
  roles: ["admin"],
  scopes: DEFAULT_ROLE_SCOPES.admin,
  authMethod: "system",
};

export function createPrincipal(params: {
  id: string;
  tenantId: string;
  projectId?: string;
  roles?: Role[];
  scopes?: Scope[];
  authMethod: Principal["authMethod"];
  keyId?: string;
  rateLimitTier?: Principal["rateLimitTier"];
  metadata?: Record<string, unknown>;
}): Principal {
  const roles = params.roles ?? ["operator"];
  const scopeSet = new Set<Scope>(params.scopes ?? []);

  for (const role of roles) {
    const defaultScopes = DEFAULT_ROLE_SCOPES[role] ?? [];
    for (const scope of defaultScopes) {
      scopeSet.add(scope);
    }
  }

  return {
    id: params.id,
    tenantId: params.tenantId,
    projectId: params.projectId,
    roles,
    scopes: Array.from(scopeSet),
    authMethod: params.authMethod,
    keyId: params.keyId,
    rateLimitTier: params.rateLimitTier ?? "standard",
    metadata: params.metadata,
  };
}

export function hasScope(principal: Principal, scope: Scope): boolean {
  if (principal.scopes.includes(scope)) return true;
  if (principal.roles.includes("admin")) return true;
  return false;
}

export function hasRole(principal: Principal, role: Role): boolean {
  if (principal.roles.includes("admin")) return true;
  return principal.roles.includes(role);
}

export function canAccessTenant(principal: Principal, tenantId: string): boolean {
  if (principal.roles.includes("admin")) return true;
  return principal.tenantId === tenantId;
}

export function canAccessProject(principal: Principal, tenantId: string, projectId?: string): boolean {
  if (!canAccessTenant(principal, tenantId)) return false;
  if (!principal.projectId || !projectId) return true;
  return principal.projectId === projectId;
}
