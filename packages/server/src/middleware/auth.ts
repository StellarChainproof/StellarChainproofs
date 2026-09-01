import { Request, Response, NextFunction } from "express";
import {
  ApiKeyManager,
  OIDCVerifier,
  Principal,
  Scope,
  createPrincipal,
  hasScope,
  canAccessTenant,
} from "@chainproof/core";

export interface AuthenticatedRequest extends Request {
  principal?: Principal;
}

export function createAuthMiddleware(options: {
  apiKeyManager?: ApiKeyManager;
  oidcVerifier?: OIDCVerifier;
  bearerToken?: string;
  enableMultiTenant?: boolean;
}) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (req.path === "/health" || req.path === "/health/live" || req.path === "/health/ready") {
      req.principal = createPrincipal({
        id: "public-anonymous",
        tenantId: "public",
        roles: ["viewer"],
        scopes: ["metrics:read"],
        authMethod: "bearer-token",
      });
      return next();
    }

    const authHeader = req.headers["authorization"] ?? "";
    const apiKeyHeader = (req.headers["x-api-key"] as string) ?? "";

    if (options.bearerToken && authHeader === `Bearer ${options.bearerToken}`) {
      req.principal = createPrincipal({
        id: "legacy-bearer-user",
        tenantId: (req.headers["x-tenant-id"] as string) ?? "default-tenant",
        roles: ["admin"],
        scopes: [
          "scan:create",
          "scan:read",
          "scan:cancel",
          "scan:delete",
          "jobs:manage",
          "metrics:read",
          "audit:read",
          "keys:manage",
        ],
        authMethod: "bearer-token",
      });
      return next();
    }

    if (apiKeyHeader || (authHeader && authHeader.startsWith("Bearer cp_live_"))) {
      const rawKey = apiKeyHeader || authHeader.slice(7);
      if (options.apiKeyManager) {
        const { principal, error } = options.apiKeyManager.authenticateApiKey(rawKey);
        if (error || !principal) {
          res.status(401).json({ error: error ?? "Unauthorized API key" });
          return;
        }
        req.principal = principal;
        return next();
      }
    }

    if (authHeader && authHeader.startsWith("Bearer ey")) {
      const jwtToken = authHeader.slice(7);
      if (options.oidcVerifier) {
        const { principal, error } = options.oidcVerifier.authenticateToken(jwtToken);
        if (error || !principal) {
          res.status(401).json({ error: error ?? "Unauthorized OIDC token" });
          return;
        }
        req.principal = principal;
        return next();
      }
    }

    if (!options.bearerToken && !options.enableMultiTenant) {
      req.principal = createPrincipal({
        id: "anonymous-default",
        tenantId: (req.headers["x-tenant-id"] as string) ?? "default-tenant",
        roles: ["admin"],
        authMethod: "bearer-token",
      });
      return next();
    }

    res.status(401).json({ error: "Unauthorized. Valid API key or Bearer token required." });
  };
}

export function requireScope(scope: Scope) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.principal) {
      res.status(401).json({ error: "Unauthenticated" });
      return;
    }

    if (!hasScope(req.principal, scope)) {
      res.status(403).json({ error: `Forbidden. Required scope: '${scope}'` });
      return;
    }

    next();
  };
}

export function requireTenantAccess(getTenantId: (req: AuthenticatedRequest) => string) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.principal) {
      res.status(401).json({ error: "Unauthenticated" });
      return;
    }

    const targetTenantId = getTenantId(req);
    if (!canAccessTenant(req.principal, targetTenantId)) {
      res.status(403).json({ error: `Forbidden. Tenant access denied for '${targetTenantId}'` });
      return;
    }

    next();
  };
}
