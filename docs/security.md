# Security architecture and controls

This document records the security controls implemented by `mcp-approval-gateway` and maps them to OWASP ASVS 5.0 requirements.

## SQLite store and query safety

- The gateway stores its state in a single SQLite file (`gateway.db`) inside `DATA_DIR` (default `/data`), opened through `better-sqlite3`.
- Before creating files, `openDb` sets a restrictive `umask` (`0o077`), creates the directory with mode `0700` and creates `gateway.db` with mode `0600`. Permissions are tightened to `0600` on `gateway.db`, `gateway.db-wal` and `gateway.db-shm` after enabling WAL mode.
- The connection enables `PRAGMA journal_mode = WAL`, `PRAGMA foreign_keys = ON` and `PRAGMA busy_timeout = 5000`.
- Numbered SQL migrations in `src/store/migrations/` run in order inside transactions and are tracked with `PRAGMA user_version` (validated as a safe 32-bit integer before setting the pragma).
- All queries use prepared statements with bound parameters (ASVS V1.2.4). An ESLint `no-restricted-syntax` rule fails the build if a template literal with expressions or a binary concatenation expression is passed to `.prepare(...)`, `.exec(...)`, `.pragma(...)`, `.run(...)`, `.get(...)` or `.all(...)`.
- The `clients` table is capped at `1000` rows. When the cap is reached, `insertClient` first prunes clients whose `last_used_at` is `NULL` and that are older than 24 hours; if the table is still at the cap, registration is refused with `429` `temporarily_unavailable`.
- The `audit_events` table stores only fixed metadata columns (`id`, `at`, `event`, `client_id`, `tool`, `request_id`, `decided_by`) checked by SQL `CHECK` constraints and TypeScript types. It never stores tool output, tool arguments, tokens, authorization codes or passphrases.

## OAuth 2.1 profile and discovery

- Public clients only (`token_endpoint_auth_method = "none"`). Dynamic client registration never issues a `client_secret`.
- `client_name` is stored raw in SQLite (up to 100 characters) and must be HTML-escaped wherever it is rendered (for example on the consent page in mcpgw-006).
- PKCE `S256` only (`code_challenge_methods_supported: ["S256"]`).
- Only `authorization_code` and `refresh_token` grant types are advertised (ASVS V10.4.4). No `implicit`, `password` or `client_credentials` grants are supported or advertised.
- No OAuth token revocation endpoint is exposed or advertised (`revokeToken` is not defined on the provider). Token revocation is an owner action on the private approve listener.
- Discovery documents (`/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp`) and `/register` responses return only the required allow-listed fields (ASVS V15.3.1).

## Rate limits (ASVS V6.1.1)

The public listener enforces rate limits on the OAuth endpoints through the MCP SDK router:

| Endpoint | Limit | Window | Notes |
| --- | --- | --- | --- |
| `POST /register` | `10` requests | `1` hour per source | Returns `429` `too_many_requests` when exceeded |
| `POST /token` | `30` requests | `1` minute per source | Returns `429` `too_many_requests` when exceeded |
| `GET` and `POST /authorize` | `100` requests | `15` minutes per source | MCP SDK default |

The public Express app keeps `trust proxy` set to `false`. Whether Tailscale Funnel preserves the original client address is unverified until mcpgw-010, so rate limits may act globally across all requests arriving through the Funnel proxy until proxy behaviour is verified.

## CORS behaviour (ASVS V3.4.2)

The `@modelcontextprotocol/sdk` OAuth handlers have been reviewed for CORS behaviour:

- `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/.well-known/oauth-protected-resource/mcp`, `POST /register` and `POST /token` use the SDK's default `cors()` middleware, which sends `Access-Control-Allow-Origin: *` and handles `OPTIONS` preflight requests without credentials.
- `Access-Control-Allow-Credentials` is never sent on any route.
- `/authorize`, `/mcp`, unknown routes (404) and every route on the private approve listener send no CORS headers.
- All security headers from `src/server/headers.ts` (`Strict-Transport-Security`, `X-Content-Type-Options`, `Content-Security-Policy`, `Referrer-Policy`, `Cache-Control: no-store` and omitted `X-Powered-By`) continue to apply to every response, including discovery, registration and error responses.
