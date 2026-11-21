import crypto from "node:crypto";
import type Database from "better-sqlite3";

export interface StoredGrant {
  readonly grantId: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
  readonly resource: string;
  readonly createdAt: number;
  readonly revokedAt: number | null;
}

export interface NewGrantInput {
  readonly grantId?: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
  readonly resource: string;
  readonly createdAt?: number;
}

interface GrantDbRow {
  readonly grant_id: string;
  readonly client_id: string;
  readonly scopes: string;
  readonly resource: string;
  readonly created_at: number;
  readonly revoked_at: number | null;
}

function rowToStoredGrant(row: GrantDbRow): StoredGrant {
  const scopes = row.scopes
    .split(" ")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  return {
    grantId: row.grant_id,
    clientId: row.client_id,
    scopes,
    resource: row.resource,
    createdAt: row.created_at,
    revokedAt: row.revoked_at
  };
}

export function insertGrant(db: Database.Database, input: NewGrantInput): StoredGrant {
  const grantId = input.grantId ?? crypto.randomUUID();
  const createdAt = input.createdAt ?? Math.floor(Date.now() / 1000);
  const scopesList = [...input.scopes];
  const scopesText = scopesList.join(" ");

  const stmt = db.prepare(
    "INSERT INTO grants (grant_id, client_id, scopes, resource, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, NULL)"
  );
  stmt.run(grantId, input.clientId, scopesText, input.resource, createdAt);

  return {
    grantId,
    clientId: input.clientId,
    scopes: scopesList,
    resource: input.resource,
    createdAt,
    revokedAt: null
  };
}

export function getGrantById(db: Database.Database, grantId: string): StoredGrant | undefined {
  const stmt = db.prepare(
    "SELECT grant_id, client_id, scopes, resource, created_at, revoked_at FROM grants WHERE grant_id = ?"
  );
  const row = stmt.get(grantId) as GrantDbRow | undefined;
  if (row === undefined) {
    return undefined;
  }
  return rowToStoredGrant(row);
}

export function listGrantsForClient(db: Database.Database, clientId: string): StoredGrant[] {
  const stmt = db.prepare(
    "SELECT grant_id, client_id, scopes, resource, created_at, revoked_at FROM grants WHERE client_id = ? ORDER BY created_at ASC"
  );
  const rows = stmt.all(clientId) as GrantDbRow[];
  return rows.map(rowToStoredGrant);
}
