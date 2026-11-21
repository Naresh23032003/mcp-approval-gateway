import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";

export const DB_FILENAME = "gateway.db";
export const DB_FILE_MODE = 0o600;
export const DB_DIR_MODE = 0o700;

const MIGRATION_FILE_PATTERN = /^(\d{4})_[a-z0-9_]+\.sql$/;

export interface MigrationFile {
  readonly version: number;
  readonly filename: string;
  readonly filePath: string;
}

export function getMigrationsDir(): string {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), "migrations");
}

export function listMigrationFiles(migrationsDir: string = getMigrationsDir()): MigrationFile[] {
  const entries = fs.readdirSync(migrationsDir, { withFileTypes: true });
  const migrations: MigrationFile[] = [];

  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(".sql")) {
      continue;
    }
    const match = MIGRATION_FILE_PATTERN.exec(entry.name);
    if (!match || match[1] === undefined) {
      throw new Error(`Invalid migration filename: ${entry.name}`);
    }
    const version = Number.parseInt(match[1], 10);
    if (!Number.isSafeInteger(version) || version < 1) {
      throw new Error(`Invalid migration version in filename: ${entry.name}`);
    }
    migrations.push({
      version,
      filename: entry.name,
      filePath: path.join(migrationsDir, entry.name)
    });
  }

  migrations.sort((a, b) => a.version - b.version);

  for (let i = 0; i < migrations.length; i++) {
    const migration = migrations[i];
    if (migration !== undefined && migration.version !== i + 1) {
      throw new Error(
        `Migration sequence error: expected version ${i + 1} but found ${migration.filename}`
      );
    }
  }

  return migrations;
}

const MAX_SQLITE_USER_VERSION = 0x7fffffff;

export function setUserVersion(db: Database.Database, version: number): void {
  if (!Number.isSafeInteger(version) || version < 0 || version > MAX_SQLITE_USER_VERSION) {
    throw new RangeError(`Invalid SQLite user_version: ${String(version)}`);
  }
  // SQLite PRAGMA user_version does not accept bound parameters; version is validated as a 32-bit integer above.
  // eslint-disable-next-line no-restricted-syntax
  db.pragma(`user_version = ${version}`);
}

export function applyMigrations(
  db: Database.Database,
  migrationsDir: string = getMigrationsDir()
): number {
  const migrations = listMigrationFiles(migrationsDir);
  const currentVersion = Number(db.pragma("user_version", { simple: true }));
  let applied = 0;

  for (const migration of migrations) {
    if (migration.version <= currentVersion) {
      continue;
    }
    const sql = fs.readFileSync(migration.filePath, "utf8");
    const runOne = db.transaction(() => {
      db.exec(sql);
      setUserVersion(db, migration.version);
    });
    runOne();
    applied += 1;
  }

  return applied;
}

function setRestrictiveUmask(): void {
  if (typeof process.umask === "function") {
    try {
      process.umask(0o077);
    } catch {
      // Worker threads do not support process.umask; explicit file modes still apply below.
    }
  }
}

function tightenFilePermissions(filePath: string): void {
  if (fs.existsSync(filePath)) {
    fs.chmodSync(filePath, DB_FILE_MODE);
  }
}

export function openDb(dir: string): Database.Database {
  setRestrictiveUmask();
  fs.mkdirSync(dir, { recursive: true, mode: DB_DIR_MODE });

  const dbPath = path.join(dir, DB_FILENAME);
  const fd = fs.openSync(dbPath, fs.constants.O_CREAT | fs.constants.O_RDWR, DB_FILE_MODE);
  fs.closeSync(fd);
  tightenFilePermissions(dbPath);

  const db = new Database(dbPath);
  try {
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    db.pragma("busy_timeout = 5000");

    applyMigrations(db);

    tightenFilePermissions(dbPath);
    tightenFilePermissions(`${dbPath}-wal`);
    tightenFilePermissions(`${dbPath}-shm`);
  } catch (err) {
    db.close();
    throw err;
  }

  return db;
}
