CREATE TABLE clients (
  client_id TEXT PRIMARY KEY,
  client_name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);

CREATE TABLE audit_events (
  id INTEGER PRIMARY KEY,
  at INTEGER NOT NULL,
  event TEXT NOT NULL CHECK (event IN (
    'client_registered',
    'consent_granted',
    'auth_failed',
    'token_issued',
    'token_revoked',
    'tool_call_served',
    'write_held',
    'write_approved',
    'write_denied',
    'write_expired'
  )),
  client_id TEXT,
  tool TEXT,
  request_id INTEGER,
  decided_by TEXT CHECK (decided_by IN ('owner', 'timeout', 'gateway') OR decided_by IS NULL)
);
