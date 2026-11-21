import type Database from "better-sqlite3";

export const CONSENT_LISTENER = "consent";
export const LOCKOUT_MAX_FAILURES = 5;
export const LOCKOUT_WINDOW_SECONDS = 600;
export const LOCKOUT_DURATION_SECONDS = 900;
export const FAILURE_RETENTION_SECONDS = 24 * 60 * 60;

export interface LockoutStatus {
  readonly locked: boolean;
  readonly retryAfterSeconds: number;
  readonly recentFailures: number;
}

interface FailureAtRow {
  readonly at: number;
}

export function recordAuthFailure(
  db: Database.Database,
  listener: string,
  source: string,
  nowSeconds: number = Math.floor(Date.now() / 1000)
): void {
  const pruneCutoff = nowSeconds - FAILURE_RETENTION_SECONDS;
  const writeTransaction = db.transaction(() => {
    db.prepare("DELETE FROM auth_failures WHERE at < ?").run(pruneCutoff);
    db.prepare("INSERT INTO auth_failures (listener, source, at) VALUES (?, ?, ?)").run(
      listener,
      source,
      nowSeconds
    );
  });
  writeTransaction();
}

export function getLockoutStatus(
  db: Database.Database,
  listener: string,
  source: string,
  nowSeconds: number = Math.floor(Date.now() / 1000)
): LockoutStatus {
  const lookbackCutoff = nowSeconds - (LOCKOUT_WINDOW_SECONDS + LOCKOUT_DURATION_SECONDS);
  const rows = db
    .prepare(
      "SELECT at FROM auth_failures WHERE listener = ? AND source = ? AND at >= ? ORDER BY at DESC"
    )
    .all(listener, source, lookbackCutoff) as FailureAtRow[];

  const windowCutoff = nowSeconds - LOCKOUT_WINDOW_SECONDS;
  let recentFailures = 0;
  for (const row of rows) {
    if (row.at >= windowCutoff) {
      recentFailures += 1;
    } else {
      break;
    }
  }

  for (let i = 0; i <= rows.length - LOCKOUT_MAX_FAILURES; i++) {
    const latest = rows[i];
    const fifth = rows[i + LOCKOUT_MAX_FAILURES - 1];
    if (latest === undefined || fifth === undefined) {
      break;
    }
    const lockExpiresAt = latest.at + LOCKOUT_DURATION_SECONDS;
    if (lockExpiresAt <= nowSeconds) {
      break;
    }
    if (latest.at - fifth.at <= LOCKOUT_WINDOW_SECONDS) {
      return {
        locked: true,
        retryAfterSeconds: Math.max(1, lockExpiresAt - nowSeconds),
        recentFailures
      };
    }
  }

  return {
    locked: false,
    retryAfterSeconds: 0,
    recentFailures
  };
}
