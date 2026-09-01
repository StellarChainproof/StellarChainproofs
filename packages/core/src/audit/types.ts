export type AuditEventType =
  | "auth.login_success"
  | "auth.login_failure"
  | "auth.key_created"
  | "auth.key_rotated"
  | "auth.key_revoked"
  | "job.submitted"
  | "job.started"
  | "job.completed"
  | "job.failed"
  | "job.cancelled"
  | "job.deleted"
  | "quota.exceeded"
  | "policy.violation"
  | "system.startup"
  | "system.shutdown";

export interface AuditEvent {
  id: string;
  timestamp: number;
  type: AuditEventType;
  tenantId: string;
  projectId?: string;
  principalId: string;
  ipAddress?: string;
  action: string;
  status: "success" | "failure" | "denied";
  details?: Record<string, unknown>;
}

export interface AuditFilter {
  tenantId?: string;
  projectId?: string;
  principalId?: string;
  type?: AuditEventType | AuditEventType[];
  status?: "success" | "failure" | "denied";
  sinceTimestamp?: number;
  untilTimestamp?: number;
  limit?: number;
  offset?: number;
}
