import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type Database from "better-sqlite3";
import { ESLint } from "eslint";
import { afterEach, describe, expect, it } from "vitest";
import { listAuditEvents, recordEvent } from "../src/store/audit.js";
import {
  ClientCapReachedError,
  MAX_CLIENTS,
  UNUSED_CLIENT_PRUNE_AGE_SECONDS,
  countClients,
  getClientById,
  insertClient
} from "../src/store/clients.js";
import {
  DB_FILENAME,
  applyMigrations,
  listMigrationFiles,
  openDb,
  setUserVersion
} from "../src/store/db.js";

const openDbs: Database.Database[] = [];
const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpgw-store-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (openDbs.length > 0) {
    const db = openDbs.pop();
    if (db && db.open) {
      db.close();
    }
  }
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe("SQLite store and migrations", () => {
  it("opens database with WAL, foreign_keys, busy_timeout, mode 0600 and idempotent migrations", () => {
    const dir = makeTempDir();
    const migrationCount = listMigrationFiles().length;
    expect(migrationCount).toBeGreaterThanOrEqual(1);

    const db1 = openDb(dir);
    openDbs.push(db1);

    const dbPath = path.join(dir, DB_FILENAME);
    expect(fs.existsSync(dbPath)).toBe(true);
    if (process.platform !== "win32") {
      expect(fs.statSync(dbPath).mode & 0o777).toBe(0o600);
    }

    expect(String(db1.pragma("journal_mode", { simple: true })).toLowerCase()).toBe("wal");
    expect(Number(db1.pragma("foreign_keys", { simple: true }))).toBe(1);
    expect(Number(db1.pragma("busy_timeout", { simple: true }))).toBe(5000);
    expect(Number(db1.pragma("user_version", { simple: true }))).toBe(migrationCount);

    // Calling applyMigrations again applies zero migrations.
    expect(applyMigrations(db1)).toBe(0);

    // Insert a client before reopening to verify reopening preserves data and applies no migration.
    insertClient(db1, {
      clientId: "11111111-1111-4111-8111-111111111111",
      clientName: "Test Client",
      redirectUris: ["https://client.example/callback"],
      createdAt: 1700000000
    });
    db1.close();

    const db2 = openDb(dir);
    openDbs.push(db2);

    expect(applyMigrations(db2)).toBe(0);
    expect(Number(db2.pragma("user_version", { simple: true }))).toBe(migrationCount);
    expect(String(db2.pragma("journal_mode", { simple: true })).toLowerCase()).toBe("wal");
    expect(Number(db2.pragma("foreign_keys", { simple: true }))).toBe(1);
    if (process.platform !== "win32") {
      expect(fs.statSync(dbPath).mode & 0o777).toBe(0o600);
    }

    const stored = getClientById(db2, "11111111-1111-4111-8111-111111111111");
    expect(stored).toEqual({
      clientId: "11111111-1111-4111-8111-111111111111",
      clientName: "Test Client",
      redirectUris: ["https://client.example/callback"],
      createdAt: 1700000000,
      lastUsedAt: null
    });
  });

  it("records structured audit events and enforces schema CHECK constraints", () => {
    const dir = makeTempDir();
    const db = openDb(dir);
    openDbs.push(db);

    const rowId = recordEvent(db, {
      event: "write_approved",
      clientId: "client-1",
      tool: "notes.append_note",
      requestId: 42,
      decidedBy: "owner"
    });
    expect(rowId).toBeGreaterThan(0);

    const events = listAuditEvents(db);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      id: rowId,
      event: "write_approved",
      client_id: "client-1",
      tool: "notes.append_note",
      request_id: 42,
      decided_by: "owner"
    });
    expect(typeof events[0]?.at).toBe("number");

    const badEventStmt = db.prepare(
      "INSERT INTO audit_events (at, event) VALUES (?, ?)"
    );
    expect(() => badEventStmt.run(1700000000, "not_a_real_event")).toThrow();

    const badDecidedByStmt = db.prepare(
      "INSERT INTO audit_events (at, event, decided_by) VALUES (?, ?, ?)"
    );
    expect(() => badDecidedByStmt.run(1700000000, "write_denied", "attacker")).toThrow();
  });

  it("validates user_version as a safe 32-bit integer before setting the pragma", () => {
    const dir = makeTempDir();
    const db = openDb(dir);
    openDbs.push(db);

    const initialVersion = Number(db.pragma("user_version", { simple: true }));
    for (const invalid of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 0x80000000]) {
      expect(() => setUserVersion(db, invalid)).toThrow(RangeError);
    }
    expect(Number(db.pragma("user_version", { simple: true }))).toBe(initialVersion);

    setUserVersion(db, initialVersion + 1);
    expect(Number(db.pragma("user_version", { simple: true }))).toBe(initialVersion + 1);
  });

  it("caps the clients table and prunes unused clients older than 24 hours only when the cap is reached", () => {
    expect(MAX_CLIENTS).toBe(1000);
    expect(UNUSED_CLIENT_PRUNE_AGE_SECONDS).toBe(24 * 60 * 60);

    const dir = makeTempDir();
    const db = openDb(dir);
    openDbs.push(db);

    const now = 1_700_100_000;
    const cap = 3;

    // Below the cap, stale unused rows are kept without pruning.
    insertClient(
      db,
      {
        clientId: "client-boundary",
        clientName: "Boundary Client",
        redirectUris: ["https://client.example/cb"],
        createdAt: now - UNUSED_CLIENT_PRUNE_AGE_SECONDS
      },
      { maxClients: cap, now }
    );
    insertClient(
      db,
      {
        clientId: "client-old-used",
        clientName: "Old Used Client",
        redirectUris: ["https://client.example/cb"],
        createdAt: now - UNUSED_CLIENT_PRUNE_AGE_SECONDS - 10_000
      },
      { maxClients: cap, now }
    );
    const markUsedStmt = db.prepare("UPDATE clients SET last_used_at = ? WHERE client_id = ?");
    const usedAt = now - 3600;
    markUsedStmt.run(usedAt, "client-old-used");

    insertClient(
      db,
      {
        clientId: "client-recent",
        clientName: "Recent Client",
        redirectUris: ["https://client.example/cb"],
        createdAt: now - 60
      },
      { maxClients: cap, now }
    );

    expect(countClients(db)).toBe(3);
    expect(listAuditEvents(db)).toHaveLength(3);

    // At the cap with no client strictly older than 24h and unused, insert is refused.
    expect(() =>
      insertClient(
        db,
        {
          clientId: "client-refused",
          clientName: "Refused Client",
          redirectUris: ["https://client.example/cb"],
          createdAt: now
        },
        { maxClients: cap, now }
      )
    ).toThrow(ClientCapReachedError);
    expect(countClients(db)).toBe(3);
    expect(getClientById(db, "client-refused")).toBeUndefined();
    expect(listAuditEvents(db)).toHaveLength(3);

    // Advance clock by 1 second so client-boundary is now older than 24h with last_used_at IS NULL.
    const oneSecondLater = now + 1;
    const inserted = insertClient(
      db,
      {
        clientId: "client-accepted",
        clientName: "Accepted Client",
        redirectUris: ["https://client.example/cb"],
        createdAt: oneSecondLater
      },
      { maxClients: cap, now: oneSecondLater }
    );

    expect(inserted.clientId).toBe("client-accepted");
    expect(countClients(db)).toBe(3);
    expect(getClientById(db, "client-boundary")).toBeUndefined();
    expect(getClientById(db, "client-old-used")).toBeDefined();
    expect(getClientById(db, "client-recent")).toBeDefined();
    expect(getClientById(db, "client-accepted")).toBeDefined();
    expect(listAuditEvents(db)).toHaveLength(4);
    expect(listAuditEvents(db)[3]?.client_id).toBe("client-accepted");
  });

  it("fails ESLint on interpolated or concatenated SQL passed to prepare, exec, pragma, run, get or all (V1.2.4)", async () => {
    const eslint = new ESLint({
      overrideConfigFile: path.resolve("eslint.config.js")
    });

    const unsafeCases: Array<{ label: string; code: string }> = [
      {
        label: "prepare template interpolation",
        code: [
          "import type Database from 'better-sqlite3';",
          "export function unsafe(db: Database.Database, id: string) {",
          "  return db.prepare(`SELECT * FROM clients WHERE client_id = '${id}'`).get();",
          "}"
        ].join("\n")
      },
      {
        label: "prepare string concatenation",
        code: [
          "import type Database from 'better-sqlite3';",
          "export function unsafeConcat(db: Database.Database, id: string) {",
          "  return db.prepare('SELECT * FROM clients WHERE client_id = ' + id).get();",
          "}"
        ].join("\n")
      },
      {
        label: "exec template interpolation",
        code: [
          "import type Database from 'better-sqlite3';",
          "export function unsafeExec(db: Database.Database, table: string) {",
          "  db.exec(`DROP TABLE ${table}`);",
          "}"
        ].join("\n")
      },
      {
        label: "pragma template interpolation",
        code: [
          "import type Database from 'better-sqlite3';",
          "export function unsafePragma(db: Database.Database, version: string) {",
          "  db.pragma(`user_version = ${version}`);",
          "}"
        ].join("\n")
      },
      {
        label: "pragma string concatenation",
        code: [
          "import type Database from 'better-sqlite3';",
          "export function unsafePragmaConcat(db: Database.Database, mode: string) {",
          "  db.pragma('journal_mode = ' + mode);",
          "}"
        ].join("\n")
      },
      {
        label: "run template interpolation",
        code: [
          "import type Database from 'better-sqlite3';",
          "export function unsafeRun(stmt: Database.Statement, id: string) {",
          "  stmt.run(`DELETE FROM clients WHERE client_id = '${id}'`);",
          "}"
        ].join("\n")
      },
      {
        label: "run string concatenation",
        code: [
          "import type Database from 'better-sqlite3';",
          "export function unsafeRunConcat(stmt: Database.Statement, id: string) {",
          "  stmt.run('DELETE FROM clients WHERE client_id = ' + id);",
          "}"
        ].join("\n")
      },
      {
        label: "get template interpolation",
        code: [
          "import type Database from 'better-sqlite3';",
          "export function unsafeGet(stmt: Database.Statement, id: string) {",
          "  return stmt.get(`SELECT * FROM clients WHERE client_id = '${id}'`);",
          "}"
        ].join("\n")
      },
      {
        label: "get string concatenation",
        code: [
          "import type Database from 'better-sqlite3';",
          "export function unsafeGetConcat(stmt: Database.Statement, id: string) {",
          "  return stmt.get('SELECT * FROM clients WHERE client_id = ' + id);",
          "}"
        ].join("\n")
      },
      {
        label: "all template interpolation",
        code: [
          "import type Database from 'better-sqlite3';",
          "export function unsafeAll(stmt: Database.Statement, id: string) {",
          "  return stmt.all(`SELECT * FROM clients WHERE client_id = '${id}'`);",
          "}"
        ].join("\n")
      },
      {
        label: "all string concatenation",
        code: [
          "import type Database from 'better-sqlite3';",
          "export function unsafeAllConcat(stmt: Database.Statement, id: string) {",
          "  return stmt.all('SELECT * FROM clients WHERE client_id = ' + id);",
          "}"
        ].join("\n")
      }
    ];

    for (const testCase of unsafeCases) {
      const results = await eslint.lintText(testCase.code, {
        filePath: path.resolve("src/store/clients.ts")
      });
      expect(
        results[0]?.messages.some(
          (m) => m.ruleId === "no-restricted-syntax" && m.message.includes("ASVS V1.2.4")
        ),
        testCase.label
      ).toBe(true);
    }

    const parameterised = await eslint.lintText(
      [
        "import type Database from 'better-sqlite3';",
        "export function safe(db: Database.Database, id: string) {",
        "  db.pragma('foreign_keys = ON');",
        "  return db.prepare('SELECT * FROM clients WHERE client_id = ?').get(id);",
        "}"
      ].join("\n"),
      { filePath: path.resolve("src/store/clients.ts") }
    );
    expect(
      parameterised[0]?.messages.some((m) => m.ruleId === "no-restricted-syntax")
    ).toBe(false);
  }, 15000);
});
