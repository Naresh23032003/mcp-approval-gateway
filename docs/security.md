# Security architecture and controls

This document records the security controls implemented by `mcp-approval-gateway` and maps them to OWASP ASVS 5.0 requirements.

## SQLite store and query safety

- The gateway stores its state in a single SQLite file (`gateway.db`) inside `DATA_DIR` (default `/data`), opened through `better-sqlite3`.
- Before creating files, `openDb` sets a restrictive `umask` (`0o077`), creates the directory with mode `0700` and creates `gateway.db` with mode `0600`. Permissions are tightened to `0600` on `gateway.db`, `gateway.db-wal` and `gateway.db-shm` after enabling WAL mode.
- The connection enables `PRAGMA journal_mode = WAL`, `PRAGMA foreign_keys = ON` and `PRAGMA busy_timeout = 5000`.
- Numbered SQL migrations in `src/store/migrations/` run in order inside transactions and are tracked with `PRAGMA user_version`.
- All queries use prepared statements with bound parameters (ASVS V1.2.4). An ESLint `no-restricted-syntax` rule fails the build if a template literal with expressions or a binary concatenation expression is passed to `.prepare(...)` or `.exec(...)`.
- The `audit_events` table stores only fixed metadata columns (`id`, `at`, `event`, `client_id`, `tool`, `request_id`, `decided_by`) checked by SQL `CHECK` constraints and TypeScript types. It never stores tool output, tool arguments, tokens, authorization codes or passphrases.

## OAuth 2.1 profile and discovery

- Public clients only (`token_endpoint_auth_method = "none"`). Dynamic client registration never issues a `client_secret`.
- PKCE `S256` only (`code_challenge_methods_supported: ["S256"]`).
- Only `authorization_code` and `refresh_token` grant types are advertised (ASVS V10.4.4). No `implicit`, `password` or `client_credentials` grants are supported or advertised.
- No OAuth token revocation endpoint is exposed or advertised (`revokeToken` is not defined on the provider). Token revocation is an owner action on the private approve listener.
- Discovery documents (`/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp`) and `/register` responses return only the required allow-listed fields (ASVS V15.3.1).

## Rate limits and lockout (ASVS V6.1.1, V6.3.1)

The public listener enforces rate limits and passphrase lockout on the OAuth endpoints:

| Endpoint or control | Limit | Window or lock | Notes |
| --- | --- | --- | --- |
| Consent passphrase (`POST /authorize`) | `5` failed tries in `10` minutes (`600` seconds) per source | `15` minute (`900` seconds) lock from the latest failure | Stored in `auth_failures` (`listener = "consent"`, `source = req.ip`). Returns `429` with `Retry-After` and renders no form; Argon2id verify is not called while locked. Rows older than 24 hours are deleted on each insert. Each failure writes an `auth_failed` audit event with `client_id` only |
| `POST /register` | `10` requests | `1` hour per source | Enforced by the MCP SDK router. Returns `429` `too_many_requests` when exceeded |
| `POST /token` | `30` requests | `1` minute per source | Enforced by the MCP SDK router. Returns `429` `too_many_requests` when exceeded |

The public Express app keeps `trust proxy` set to `false`. Whether Tailscale Funnel preserves the original client address is unverified until mcpgw-010, so rate limits and consent lockout may act globally across all requests arriving through the Funnel proxy until proxy behaviour is verified.

## Consent page, CSRF and CSP (ASVS V1.2.1, V1.2.2, V1.2.3, V2.3.1, V3.5.1, V6.2.6, V6.2.7, V6.2.8, V10.4.1, V14.2.1)

- `GET /authorize` and `POST /authorize` are mounted on the public listener before the MCP SDK router so the SDK authorization handler never runs. Any other HTTP method on `/authorize` returns the plain `404 Not found.` response.
- Every HTML value passes through the single `html` tagged template helper in `src/ui/html.ts`, which escapes `&`, `<`, `>`, `"` and `'` and rejects data interpolations inside `<script>` tags. Client names also pass through `visibleEscape` (`src/ui/visible.ts`) so control characters, zero-width characters and bidirectional overrides appear literally as `\uXXXX`.
- The consent page never links to the approve page and never reveals the approve page address, port or path.
- `GET /authorize` sets a 32-byte random CSRF token in `__Host-consent_csrf` (`Path=/; Secure; HttpOnly; SameSite=Strict`) and puts the same value in a hidden form field. `POST /authorize` verifies constant-time equality between the cookie and form field and checks that `Origin` equals the origin of `public_base_url` (or `Sec-Fetch-Site: same-origin` when `Origin` is absent). Failures return `403` without verifying the passphrase or recording an `auth_failures` row.
- All OAuth parameters (`client_id`, exact string match on registered `redirect_uri`, `response_type = "code"`, PKCE `S256` 43-character base64url `code_challenge`, canonical `resource`) are re-validated against SQLite and `gateway.toml` on every `POST /authorize`.
- The owner passphrase is submitted only in the `POST /authorize` body (`type="password"`, `autocomplete="current-password"`, paste and password managers allowed, Show toggle button). It is rejected without hashing if longer than 1024 Unicode code points, verified with Argon2id exactly as typed (no trimming or case folding), and never logged or stored.
- On owner approval, the gateway writes a `grants` row, generates a 32-byte random authorization code, stores only its SHA-256 hex digest in `auth_codes` (valid for 60 seconds, bound to `redirect_uri` and `code_challenge`), records a `consent_granted` audit event, and builds the `302` redirect URL with `new URL(...)` and `searchParams.set(...)`. The raw authorization code is never written to SQLite or logs.
- Inline CSS (`src/ui/style.ts`) and the small inline consent script (`src/ui/consent-page.ts`) are hashed with SHA-256 at startup. The consent page replaces the default CSP via `setCsp`:
  `default-src 'none'; style-src 'sha256-<style-hash>'; script-src 'sha256-<script-hash>'; form-action 'self' <redirect-origin>; frame-ancestors 'none'; base-uri 'none'`
  No `unsafe-inline` is used, and no external assets, fonts or routes are added. For custom-scheme `redirect_uri` values, `<redirect-origin>` is `<scheme>:`.
- Chrome enforces `form-action` on redirects following a form POST; headless unit tests can only verify the CSP header string, so mcpgw-010 must verify the consent form redirect in a real browser.
- Invalid-request (`400` and `403`) and locked (`429`) pages use `script-src 'none'; form-action 'none'` with the style SHA-256 hash.

## CORS behaviour (ASVS V3.4.2)

The `@modelcontextprotocol/sdk` OAuth handlers have been reviewed for CORS behaviour:

- `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/.well-known/oauth-protected-resource/mcp`, `POST /register` and `POST /token` use the SDK's default `cors()` middleware, which sends `Access-Control-Allow-Origin: *` and handles `OPTIONS` preflight requests without credentials.
- `Access-Control-Allow-Credentials` is never sent on any route.
- `/authorize`, `/mcp`, unknown routes (404) and every route on the private approve listener send no CORS headers.
- All security headers from `src/server/headers.ts` (`Strict-Transport-Security`, `X-Content-Type-Options`, `Content-Security-Policy`, `Referrer-Policy`, `Cache-Control: no-store` and omitted `X-Powered-By`) continue to apply to every response, including discovery, registration and error responses.
