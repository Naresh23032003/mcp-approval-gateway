import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type Database from "better-sqlite3";
import { ESLint } from "eslint";
import { afterEach, describe, expect, it } from "vitest";
import { listAuditEvents, recordEvent } from "../src/store/audit.js";
import { getClientById, insertClient } from "../src/store/clients.js";
import {
  DB_FILENAME,
  applyMigrations,
  listMigrationFiles,
  openDb
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

  it("fails ESLint on interpolated or concatenated SQL passed to prepare or exec (V1.2.4)", async () => {
    const eslint = new ESLint({
      overrideConfigFile: path.resolve("eslint.config.js")
    });

    const templateInterpolation = await eslint.lintText(
      [
        "import type Database from 'better-sqlite3';",
        "export function unsafe(db: Database.Database, id: string) {",
        "  return db.prepare(`SELECT * FROM clients WHERE client_id = '${id}'`).get();",
        "}"
      ].join("\n"),
      { filePath: path.resolve("src/store/clients.ts") }
    );
    expect(
      templateInterpolation[0]?.messages.some(
        (m) => m.ruleId === "no-restricted-syntax" && m.message.includes("ASVS V1.2.4")
      )
    ).toBe(true);

    const stringConcat = await eslint.lintText(
      [
        "import type Database from 'better-sqlite3';",
        "export function unsafeConcat(db: Database.Database, id: string) {",
        "  return db.prepare('SELECT * FROM clients WHERE client_id = ' + id).get();",
        "}"
      ].join("\n"),
      { filePath: path.resolve("src/store/clients.ts") }
    );
    expect(
      stringConcat[0]?.messages.some(
        (m) => m.ruleId === "no-restricted-syntax" && m.message.includes("ASVS V1.2.4")
      )
    ).toBe(true);

    const execInterpolation = await eslint.lintText(
      [
        "import type Database from 'better-sqlite3';",
        "export function unsafeExec(db: Database.Database, table: string) {",
        "  db.exec(`DROP TABLE ${table}`);",
        "}"
      ].join("\n"),
      { filePath: path.resolve("src/store/clients.ts") }
    );
    expect(
      execInterpolation[0]?.messages.some(
        (m) => m.ruleId === "no-restricted-syntax" && m.message.includes("ASVS V1.2.4")
      )
    ).toBe(true);

    const parameterised = await eslint.lintText(
      [
        "import type Database from 'better-sqlite3';",
        "export function safe(db: Database.Database, id: string) {",
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
