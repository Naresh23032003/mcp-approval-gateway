import type Database from "better-sqlite3";

export const AUDIT_EVENT_TYPES = [
  "client_registered",
  "consent_granted",
  "auth_failed",
  "token_issued",
  "token_revoked",
  "tool_call_served",
  "write_held",
  "write_approved",
  "write_denied",
  "write_expired"
] as const;

export type AuditEventType = (typeof AUDIT_EVENT_TYPES)[number];

export const AUDIT_DECIDED_BY = ["owner", "timeout", "gateway"] as const;

export type AuditDecidedBy = (typeof AUDIT_DECIDED_BY)[number];

export interface AuditEventInput {
  readonly event: AuditEventType;
  readonly clientId?: string;
  readonly tool?: string;
  readonly requestId?: number;
  readonly decidedBy?: AuditDecidedBy;
}

export interface AuditEventRow {
  readonly id: number;
  readonly at: number;
  readonly event: AuditEventType;
  readonly client_id: string | null;
  readonly tool: string | null;
  readonly request_id: number | null;
  readonly decided_by: AuditDecidedBy | null;
}

export function recordEvent(db: Database.Database, input: AuditEventInput): number {
  const now = Math.floor(Date.now() / 1000);
  const stmt = db.prepare(
    "INSERT INTO audit_events (at, event, client_id, tool, request_id, decided_by) VALUES (?, ?, ?, ?, ?, ?)"
  );
  const result = stmt.run(
    now,
    input.event,
    input.clientId ?? null,
    input.tool ?? null,
    input.requestId ?? null,
    input.decidedBy ?? null
  );
  return Number(result.lastInsertRowid);
}

export function listAuditEvents(db: Database.Database): AuditEventRow[] {
  const stmt = db.prepare(
    "SELECT id, at, event, client_id, tool, request_id, decided_by FROM audit_events ORDER BY id ASC"
  );
  return stmt.all() as AuditEventRow[];
}
