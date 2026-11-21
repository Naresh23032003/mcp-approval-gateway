# Third-party software and data

## Bundled data

### SecLists `10k-most-common.txt`
- **File in this repository:** `src/data/common-passwords.ts`
- **Source:** [danielmiessler/SecLists `Passwords/Common-Credentials/10k-most-common.txt`](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt)
- **Licence:** MIT License (Copyright (c) 2018 Daniel Miessler)
- **Date bundled:** 2026-11-16
- **Purpose:** Reject commonly used passphrases during `hash-passphrase` validation (OWASP ASVS 5.0 V6.2.4).

## Runtime dependencies

| Package | Licence | Purpose |
| --- | --- | --- |
| `@modelcontextprotocol/sdk` | MIT | Official MCP server and client implementation for the demo upstream and gateway. |
| `@node-rs/argon2` | MIT | Argon2id hashing and verification for the owner passphrase (ASVS V11.4.1). |
| `better-sqlite3` | MIT | Embedded store with no separate database service (synchronous SQLite driver with prebuilt binaries for amd64 and arm64). |
| `express` | MIT | HTTP server for the public and approve listeners (also a direct dependency of the MCP SDK). |
| `smol-toml` | MIT | Parsing `gateway.toml` configuration files. |
| `zod` | MIT | Strict schema validation for `gateway.toml` configuration. |

No third-party UUID package is used: dynamic client registration generates each `client_id` as a UUID v4 via Node.js's built-in `crypto.randomUUID()`.
