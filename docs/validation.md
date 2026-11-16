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
