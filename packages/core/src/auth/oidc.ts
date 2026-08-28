import { OIDCConfig, OIDCPayload, Principal, Role, Scope } from "./types";
import { createPrincipal } from "./principal";

export class OIDCVerifier {
  private config: OIDCConfig;

  constructor(config: OIDCConfig) {
    this.config = config;
  }

  public static parseUnverifiedToken(jwtToken: string): { header: Record<string, unknown>; payload: OIDCPayload } {
    const parts = jwtToken.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid JWT token structure: expected 3 header.payload.signature parts");
    }

    try {
      const headerJson = Buffer.from(parts[0], "base64url").toString("utf-8");
      const payloadJson = Buffer.from(parts[1], "base64url").toString("utf-8");
      return {
        header: JSON.parse(headerJson),
        payload: JSON.parse(payloadJson),
      };
    } catch {
      throw new Error("Failed to decode JWT base64url payload");
    }
  }

  public verifyClaims(payload: OIDCPayload): { principal?: Principal; error?: string } {
    const nowSec = Math.floor(Date.now() / 1000);

    if (payload.exp && payload.exp < nowSec) {
      return { error: "OIDC token has expired" };
    }

    if (payload.nbf && payload.nbf > nowSec) {
      return { error: "OIDC token is not valid yet (nbf)" };
    }

    if (this.config.issuer && payload.iss !== this.config.issuer) {
      return { error: `Invalid OIDC token issuer: expected ${this.config.issuer}, got ${payload.iss}` };
    }

    if (this.config.audience) {
      const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!auds.includes(this.config.audience)) {
        return { error: `Invalid OIDC token audience: expected ${this.config.audience}` };
      }
    }

    const mapping = this.config.claimMapping ?? {};

    const tenantId = (mapping.tenantClaim ? payload[mapping.tenantClaim] : payload.tenant_id) as string ?? "default-tenant";
    const projectId = (mapping.projectClaim ? payload[mapping.projectClaim] : payload.project_id) as string | undefined;
    const rawRoles = (mapping.rolesClaim ? payload[mapping.rolesClaim] : payload.roles) as string[] | undefined;
    const rawScopes = (mapping.scopesClaim ? payload[mapping.scopesClaim] : payload.scopes) as string[] | undefined;

    const roles: Role[] = (rawRoles ?? ["operator"]).filter(
      (r): r is Role => ["admin", "tenant-admin", "operator", "viewer"].includes(r)
    );

    const validScopes: Scope[] = [
      "scan:create",
      "scan:read",
      "scan:cancel",
      "scan:delete",
      "jobs:manage",
      "metrics:read",
      "audit:read",
      "tenant:manage",
      "keys:manage",
    ];

    const scopes: Scope[] = (rawScopes ?? []).filter((s): s is Scope => validScopes.includes(s as Scope));

    const principal = createPrincipal({
      id: `oidc_${payload.sub}`,
      tenantId,
      projectId,
      roles: roles.length > 0 ? roles : ["operator"],
      scopes,
      authMethod: "oidc-claim",
      metadata: { issuer: payload.iss, sub: payload.sub },
    });

    return { principal };
  }

  public authenticateToken(jwtToken: string): { principal?: Principal; error?: string } {
    try {
      const { payload } = OIDCVerifier.parseUnverifiedToken(jwtToken);
      return this.verifyClaims(payload);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { error: `OIDC authentication failed: ${message}` };
    }
  }
}
