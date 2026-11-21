import type Database from "better-sqlite3";
import { z } from "zod";
import { recordEvent } from "./audit.js";

const RedirectUrisJsonSchema = z.array(z.string());

export interface StoredClient {
  readonly clientId: string;
  readonly clientName: string;
  readonly redirectUris: readonly string[];
  readonly createdAt: number;
  readonly lastUsedAt: number | null;
}

export interface NewClientRecord {
  readonly clientId: string;
  readonly clientName: string;
  readonly redirectUris: readonly string[];
  readonly createdAt: number;
}

interface ClientDbRow {
  readonly client_id: string;
  readonly client_name: string;
  readonly redirect_uris: string;
  readonly created_at: number;
  readonly last_used_at: number | null;
}

function rowToStoredClient(row: ClientDbRow): StoredClient {
  const redirectUris = RedirectUrisJsonSchema.parse(JSON.parse(row.redirect_uris));
  return {
    clientId: row.client_id,
    clientName: row.client_name,
    redirectUris,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at
  };
}

export function insertClient(db: Database.Database, client: NewClientRecord): StoredClient {
  const writeTransaction = db.transaction(() => {
    const stmt = db.prepare(
      "INSERT INTO clients (client_id, client_name, redirect_uris, created_at, last_used_at) VALUES (?, ?, ?, ?, NULL)"
    );
    stmt.run(
      client.clientId,
      client.clientName,
      JSON.stringify(client.redirectUris),
      client.createdAt
    );
    recordEvent(db, {
      event: "client_registered",
      clientId: client.clientId
    });
  });

  writeTransaction();

  return {
    clientId: client.clientId,
    clientName: client.clientName,
    redirectUris: [...client.redirectUris],
    createdAt: client.createdAt,
    lastUsedAt: null
  };
}

export function getClientById(db: Database.Database, clientId: string): StoredClient | undefined {
  const stmt = db.prepare(
    "SELECT client_id, client_name, redirect_uris, created_at, last_used_at FROM clients WHERE client_id = ?"
  );
  const row = stmt.get(clientId) as ClientDbRow | undefined;
  if (row === undefined) {
    return undefined;
  }
  return rowToStoredClient(row);
}
