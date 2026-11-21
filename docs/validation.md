# Validation rules

This document lists the input validation rules enforced by `mcp-approval-gateway` (OWASP ASVS 5.0 V2.1.1).

## Configuration keys (`gateway.toml`)

All tables use strict schema validation. Unknown keys are rejected with a line number when found and a suggestion when a known key is within edit distance 2.

| Key | Type | Allowed range or pattern | Default | Failure message |
| --- | --- | --- | --- | --- |
| `public_base_url` | string (required) | Valid `https` URL with no path, trailing slash, query or fragment (`http` allowed only for `localhost`, `127.0.0.1` or `[::1]`) | none | `gateway.toml: public_base_url is missing. Set it to the https address clients use.` / `gateway.toml: public_base_url must use https (http is only allowed for localhost, 127.0.0.1 or [::1]).` / `gateway.toml: public_base_url must not contain a path, trailing slash, query or fragment.` |
| `upstream_url` | string (required) | Valid `http` or `https` URL | none | `gateway.toml: upstream_url is missing. Set it to the http or https URL of the upstream MCP server.` / `gateway.toml: upstream_url must be a valid http or https URL.` |
| `owner_passphrase_hash` | string (required) | Non-empty Argon2id encoded hash starting with `$argon2id$` | none | `gateway.toml: owner_passphrase_hash is empty. Run hash-passphrase and paste the result.` / `gateway.toml: owner_passphrase_hash must start with "$argon2id$". Run hash-passphrase and paste the result.` |
| `listen.public_port` | integer (optional) | `1024` to `65535` | `8080` | `gateway.toml: listen.public_port must be between 1024 and 65535.` |
| `listen.approve_port` | integer (optional) | `1024` to `65535`, must differ from `listen.public_port` | `8081` | `gateway.toml: listen.approve_port must be between 1024 and 65535.` / `gateway.toml: listen.approve_port must differ from listen.public_port.` |
| `queue.ttl_minutes` | integer (optional) | `1` to `1440` | `15` | `gateway.toml: queue.ttl_minutes must be between 1 and 1440.` |
| `queue.max_pending` | integer (optional) | `1` to `500` | `50` | `gateway.toml: queue.max_pending must be between 1 and 500.` |
| `queue.purge_days` | integer (optional) | `1` to `365` | `7` | `gateway.toml: queue.purge_days must be between 1 and 365.` |
| `notify.ntfy_url` | string (optional) | Valid `http` or `https` URL | unset | `gateway.toml: notify.ntfy_url must be a valid http or https URL.` |
| `tools` | array of tables (required) | At least 1 entry | none | `gateway.toml: tools is missing. Configure at least one [[tools]] entry.` / `gateway.toml: tools must contain at least one tool entry.` |
| `tools[].name` | string (required) | `^[a-z][a-z0-9_.-]{0,63}$`, unique across `tools`, never `approval_status` | none | `gateway.toml: tools.name must match ^[a-z][a-z0-9_.-]{0,63}$.` / `gateway.toml: tools.name cannot be "approval_status" (reserved by the gateway).` / `gateway.toml: tools.name "<name>" is duplicated. Tool names must be unique.` |
| `tools[].class` | string (required) | `"read"` or `"write"` | none | `gateway.toml: tools.class must be "read" or "write".` |
| `tools[].group` | string (optional, read tools only) | `^[a-z][a-z0-9_-]{0,31}$` (no colon); disallowed when `class = "write"` | `"read"` (for read tools) | `gateway.toml: tools.group must match ^[a-z][a-z0-9_-]{0,31}$ (no colon).` / `gateway.toml: tools.group is not allowed on write tool "<name>". Only read tools may set a group.` |

## Owner passphrase (`hash-passphrase`)

| Rule | Requirement | Failure message |
| --- | --- | --- |
| Minimum length | At least 15 Unicode code points (`Array.from(pw).length >= 15`), checked exactly as typed | `Use at least 15 characters. Four random words work well.` |
| Maximum length | At most 1024 Unicode code points (`Array.from(pw).length <= 1024`) | `Use at most 1024 characters.` |
| Common password list | Neither the exact string nor its lower-cased form appears in the bundled 10,000 common password list | `That passphrase is on a list of commonly used passwords. Choose another.` |
| Confirmation match | Second entry matches the first entry character for character | `The two entries differ. Nothing was written. Run the command again.` |
| Current passphrase on change | When `GATEWAY_CONFIG` exists and has a non-empty `owner_passphrase_hash`, the current passphrase must verify against that hash | `The current passphrase did not match. Nothing was written.` |

## HTTP request validation

These rules apply at the HTTP boundary (OWASP ASVS 5.0 V3.2.1, V3.4.1, V3.4.2, V3.5.3, V4.1.1, V5.2.1).

| Rule | Scope | Requirement | Failure response |
| --- | --- | --- | --- |
| Request `Content-Type` | Both listeners, `POST`, `PUT`, `PATCH`, `DELETE` requests carrying a body (`Content-Length` > 0 or `Transfer-Encoding`) | Media type must be `application/json` or `application/x-www-form-urlencoded` (parameters such as `charset` are allowed) | `415` `application/json; charset=utf-8` with `{"error":"unsupported_media_type"}` |
| Body size limit | Public listener JSON and form-urlencoded bodies | At most `64 KB` | `413` `application/json; charset=utf-8` with `{"error":"payload_too_large"}` (no stack trace) |
| Malformed JSON | Public listener JSON bodies | Valid JSON syntax | `400` `application/json; charset=utf-8` with `{"error":"invalid_request"}` (no parser error text or stack trace) |
| Method safety | Route table (`src/server/routes.ts`) | State changes happen only on `POST`; every `GET` route has `mutates: false` | Enforced by automated route-table tests |
| Unknown routes and methods | Both listeners | Unmatched paths or unsupported methods return a plain 404 without revealing route shapes | `404` `text/plain; charset=utf-8` with `Not found.` |

## Dynamic client registration (`POST /register`)

These allow-list rules are enforced by a Zod schema before any client row is written (OWASP ASVS 5.0 V2.1.1, V2.2.1, V5.2.1, V6.1.1, V10.4.4, V15.3.1). Registration creates a public client record only and grants no scopes or tool access until the owner consents.

| Field or rule | Requirement | Failure response |
| --- | --- | --- |
| Request `Content-Type` and size | `application/json` (optional parameters such as `charset`), body at most `64 KB` | `415` `unsupported_media_type`, `413` `payload_too_large`, or `400` `invalid_request` on malformed JSON |
| Rate limit | At most `10` requests per hour per source | `429` `too_many_requests` |
| `redirect_uris` | Required array of `1` to `5` strings, each at most `2048` characters. Each must be an absolute URL with no `#` fragment and no embedded credentials (`user:pass@` or `@`). Allowed schemes: `https:`, `http:` only for `localhost`, `127.0.0.1` or `[::1]`, or a custom scheme matching `^[a-z][a-z0-9+.-]*$` that contains at least one `.` or `-` (for example `com.example.app:/callback`). Rejects `javascript:`, `data:`, `file:` and `vbscript:` | `400` `invalid_client_metadata` |
| `client_name` | Optional string, at most `100` characters; stored as sent (escaped when rendered in HTML); defaults to `Unnamed client` when omitted or empty | `400` `invalid_client_metadata` |
| `token_endpoint_auth_method` | Optional; if present must equal `"none"`. Public clients only, no client secret is issued | `400` `invalid_client_metadata` |
| `grant_types` | Optional non-empty array whose entries are a subset of `"authorization_code"` and `"refresh_token"`. Defaults to `["authorization_code", "refresh_token"]` | `400` `invalid_client_metadata` |
| `response_types` | Optional; if present must equal `["code"]`. Defaults to `["code"]` | `400` `invalid_client_metadata` |
| Unknown extra fields | Ignored by the allow-list schema, never stored in SQLite and never echoed back | Ignored |
| `client_id` and audit | Random UUID v4 (122 bits of entropy); successful registration writes one `client_registered` row in `audit_events` | `201` on success |
| Response fields (V15.3.1) | Returns only `client_id`, `client_id_issued_at`, `client_name`, `redirect_uris`, `token_endpoint_auth_method` (`"none"`), `grant_types` and `response_types` | No `client_secret` or internal fields |

## Authorization request (`GET /authorize` and `POST /authorize`)

Every authorization request is validated with Zod schemas against the `clients` table and `gateway.toml` before rendering the consent page or checking the owner passphrase (OWASP ASVS 5.0 V2.1.1, V2.3.1, V10.4.1). Hidden form fields are treated as untrusted and every check below is repeated on `POST /authorize`. Failed validation returns an HTML error page with a fixed reason string, never echoes request parameters and never redirects.

| Parameter | Requirement | Failure status and fixed reason |
| --- | --- | --- |
| HTTP method | Only `GET` and `POST` are accepted on `/authorize` | `404` `text/plain; charset=utf-8` with `Not found.` |
| `client_id` | Non-empty string (at most 256 characters) matching a row in `clients` | `400` HTML page with `unknown client` |
| `redirect_uri` | Non-empty string (at most 2048 characters) equal by exact string comparison (no normalisation) to one of the client's registered `redirect_uris` | `400` HTML page with `redirect address not registered` |
| `response_type` | Must equal `"code"` | `400` HTML page with `request type not supported` |
| `code_challenge_method` and `code_challenge` | `code_challenge_method` must equal `"S256"`; `code_challenge` must match `^[A-Za-z0-9_-]{43}$` (43 base64url characters) | `400` HTML page with `PKCE S256 missing` |
| `resource` | Optional string; when present must exactly equal `<public_base_url>/mcp`; when omitted defaults to `<public_base_url>/mcp` | `400` HTML page with `resource not recognised` |
| `scope` | Optional string (at most 2048 characters), space-separated. `read` is always granted. Non-default read groups configured in `gateway.toml` (`class = "read"`) are offered as unticked checkboxes only when requested. `write:<tool>` and unknown scopes are ignored and never offered or granted | `400` HTML page with `request not accepted` if malformed (for example repeated parameter or over length limit) |
| `state` | Optional string (at most 2048 characters), preserved and URL-encoded via `URL.searchParams` on redirect | `400` HTML page with `request not accepted` if malformed |

## Consent form submission (`POST /authorize`)

These rules run on `POST /authorize` before any grant or authorization code is issued (OWASP ASVS 5.0 V3.5.1, V6.1.1, V6.2.8, V6.3.1, V14.2.1).

| Field or check | Requirement | Failure response |
| --- | --- | --- |
| `Origin` and `Sec-Fetch-Site` | `Origin` must equal the origin of `public_base_url`; if `Origin` is absent, `Sec-Fetch-Site` must equal `"same-origin"` | `403` HTML page with `request not accepted` (no passphrase verify, no lockout row) |
| CSRF synchronizer token | Cookie `__Host-consent_csrf` and hidden form field `csrf_token` must both be present, non-empty and match via constant-time comparison (`crypto.timingSafeEqual`) | `403` HTML page with `request not accepted` (no passphrase verify, no lockout row) |
| `decision` | Must be `"allow"` or `"cancel"`. `"cancel"` redirects to the validated `redirect_uri` with `error=access_denied` (and `state` when present) without creating a grant | `400` HTML page with `request not accepted` |
| Lockout check (`decision = "allow"`) | Fewer than `5` failed tries from `req.ip` within `600` seconds, and outside any active `900`-second lock from a 5-failure burst | `429` HTML page with `Retry-After` header and no form rendered (no passphrase verify) |
| `passphrase` (`decision = "allow"`) | Non-empty string in POST body, at most `1024` Unicode code points (`Array.from(pw).length <= 1024`), verified with Argon2id against `owner_passphrase_hash` exactly as typed (no trimming or case changes) | Records `auth_failures` and `auth_failed` audit event; returns `401` consent page with remaining tries, or `429` once the 5th failure locks the source |
| `granted_scopes` (`decision = "allow"`) | Optional checkbox values; intersected with configured non-default read groups that were requested in `scope`. `read` is always included; tampered `write:*` or unknown scopes are ignored | Ignored; never granted |


