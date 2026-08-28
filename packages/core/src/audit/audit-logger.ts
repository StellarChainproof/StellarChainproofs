import * as crypto from "crypto";
import { AuditEvent, AuditEventType, AuditFilter } from "./types";
import { ErrorSanitizer } from "../isolation/sanitizer";

export class AuditLogger {
  private events: AuditEvent[] = [];
  private maxMemoryEvents: number;

  constructor(maxMemoryEvents = 10000) {
    this.maxMemoryEvents = maxMemoryEvents;
  }

  public record(params: {
    type: AuditEventType;
    tenantId: string;
    projectId?: string;
    principalId: string;
    action: string;
    status: AuditEvent["status"];
    ipAddress?: string;
    details?: Record<string, unknown>;
  }): AuditEvent {
    const id = `evt_${crypto.randomBytes(8).toString("hex")}`;
    const timestamp = Date.now();

    let sanitizedDetails: Record<string, unknown> | undefined;
    if (params.details) {
      sanitizedDetails = JSON.parse(
        ErrorSanitizer.sanitizePath(JSON.stringify(params.details))
      );
    }

    const event: AuditEvent = {
      id,
      timestamp,
      type: params.type,
      tenantId: params.tenantId,
      projectId: params.projectId,
      principalId: params.principalId,
      action: params.action,
      status: params.status,
      ipAddress: params.ipAddress,
      details: sanitizedDetails,
    };

    this.events.push(event);

    if (this.events.length > this.maxMemoryEvents) {
      this.events.shift();
    }

    return event;
  }

  public query(filter: AuditFilter = {}): { events: AuditEvent[]; total: number; offset: number; limit: number } {
    let filtered = [...this.events];

    if (filter.tenantId) {
      filtered = filtered.filter((e) => e.tenantId === filter.tenantId);
    }

    if (filter.projectId) {
      filtered = filtered.filter((e) => e.projectId === filter.projectId);
    }

    if (filter.principalId) {
      filtered = filtered.filter((e) => e.principalId === filter.principalId);
    }

    if (filter.type) {
      const types = Array.isArray(filter.type) ? filter.type : [filter.type];
      filtered = filtered.filter((e) => types.includes(e.type));
    }

    if (filter.status) {
      filtered = filtered.filter((e) => e.status === filter.status);
    }

    if (filter.sinceTimestamp) {
      filtered = filtered.filter((e) => e.timestamp >= filter.sinceTimestamp!);
    }

    if (filter.untilTimestamp) {
      filtered = filtered.filter((e) => e.timestamp <= filter.untilTimestamp!);
    }

    filtered.sort((a, b) => b.timestamp - a.timestamp);

    const total = filtered.length;
    const offset = filter.offset ?? 0;
    const limit = filter.limit ?? 100;
    const page = filtered.slice(offset, offset + limit);

    return { events: page, total, offset, limit };
  }

  public clear(): void {
    this.events = [];
  }
}
