CREATE TABLE grants (
  grant_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(client_id),
  scopes TEXT NOT NULL,
  resource TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE INDEX idx_grants_client_id ON grants (client_id);

CREATE TABLE auth_codes (
  code_hash TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES grants(grant_id),
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);

CREATE INDEX idx_auth_codes_grant_id ON auth_codes (grant_id);

CREATE TABLE auth_failures (
  id INTEGER PRIMARY KEY,
  listener TEXT NOT NULL,
  source TEXT NOT NULL,
  at INTEGER NOT NULL
);

CREATE INDEX idx_auth_failures_listener_source_at ON auth_failures (listener, source, at);
