import type Database from "better-sqlite3";
import { z } from "zod";
import { recordEvent } from "./audit.js";

const RedirectUrisJsonSchema = z.array(z.string());

export const MAX_CLIENTS = 1000;
export const UNUSED_CLIENT_PRUNE_AGE_SECONDS = 24 * 60 * 60;

export class ClientCapReachedError extends Error {
  readonly maxClients: number;

  constructor(maxClients: number = MAX_CLIENTS) {
    super(`Client registration limit (${maxClients}) reached.`);
    this.name = "ClientCapReachedError";
    this.maxClients = maxClients;
  }
}

export interface InsertClientOptions {
  readonly maxClients?: number;
  readonly now?: number;
  readonly pruneAgeSeconds?: number;
}

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

export function countClients(db: Database.Database): number {
  const stmt = db.prepare("SELECT COUNT(*) AS total FROM clients");
  const row = stmt.get() as { total: number };
  return row.total;
}

export function pruneStaleUnusedClients(
  db: Database.Database,
  cutoffEpochSeconds: number
): number {
  const stmt = db.prepare("DELETE FROM clients WHERE last_used_at IS NULL AND created_at < ?");
  const result = stmt.run(cutoffEpochSeconds);
  return result.changes;
}

export function insertClient(
  db: Database.Database,
  client: NewClientRecord,
  options: InsertClientOptions = {}
): StoredClient {
  const maxClients = options.maxClients ?? MAX_CLIENTS;
  if (!Number.isSafeInteger(maxClients) || maxClients < 1) {
    throw new RangeError(`maxClients must be a positive safe integer, got ${String(maxClients)}`);
  }
  const pruneAgeSeconds = options.pruneAgeSeconds ?? UNUSED_CLIENT_PRUNE_AGE_SECONDS;
  if (!Number.isSafeInteger(pruneAgeSeconds) || pruneAgeSeconds < 0) {
    throw new RangeError(
      `pruneAgeSeconds must be a non-negative safe integer, got ${String(pruneAgeSeconds)}`
    );
  }
  const now = options.now ?? Math.floor(Date.now() / 1000);

  const writeTransaction = db.transaction(() => {
    let currentCount = countClients(db);
    if (currentCount >= maxClients) {
      const cutoff = now - pruneAgeSeconds;
      pruneStaleUnusedClients(db, cutoff);
      currentCount = countClients(db);
      if (currentCount >= maxClients) {
        throw new ClientCapReachedError(maxClients);
      }
    }

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

  writeTransaction.immediate();

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
