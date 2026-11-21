import crypto from "node:crypto";
import type Database from "better-sqlite3";

export const AUTH_CODE_TTL_SECONDS = 60;

export interface StoredAuthCode {
  readonly codeHash: string;
  readonly grantId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly expiresAt: number;
  readonly usedAt: number | null;
}

export interface NewAuthCodeInput {
  readonly codeHash: string;
  readonly grantId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly expiresAt: number;
}

interface AuthCodeDbRow {
  readonly code_hash: string;
  readonly grant_id: string;
  readonly redirect_uri: string;
  readonly code_challenge: string;
  readonly expires_at: number;
  readonly used_at: number | null;
}

function rowToStoredAuthCode(row: AuthCodeDbRow): StoredAuthCode {
  return {
    codeHash: row.code_hash,
    grantId: row.grant_id,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge,
    expiresAt: row.expires_at,
    usedAt: row.used_at
  };
}

export function generateAuthCode(): string {
  return crypto.randomBytes(32).toString("base64url");
}

export function hashAuthCode(code: string): string {
  return crypto.createHash("sha256").update(code, "utf8").digest("hex");
}

export function insertAuthCode(db: Database.Database, input: NewAuthCodeInput): StoredAuthCode {
  const stmt = db.prepare(
    "INSERT INTO auth_codes (code_hash, grant_id, redirect_uri, code_challenge, expires_at, used_at) VALUES (?, ?, ?, ?, ?, NULL)"
  );
  stmt.run(
    input.codeHash,
    input.grantId,
    input.redirectUri,
    input.codeChallenge,
    input.expiresAt
  );

  return {
    codeHash: input.codeHash,
    grantId: input.grantId,
    redirectUri: input.redirectUri,
    codeChallenge: input.codeChallenge,
    expiresAt: input.expiresAt,
    usedAt: null
  };
}

export function getAuthCodeByHash(
  db: Database.Database,
  codeHash: string
): StoredAuthCode | undefined {
  const stmt = db.prepare(
    "SELECT code_hash, grant_id, redirect_uri, code_challenge, expires_at, used_at FROM auth_codes WHERE code_hash = ?"
  );
  const row = stmt.get(codeHash) as AuthCodeDbRow | undefined;
  if (row === undefined) {
    return undefined;
  }
  return rowToStoredAuthCode(row);
}
