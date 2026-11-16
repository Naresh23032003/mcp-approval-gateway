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
| `@node-rs/argon2` | MIT | Argon2id hashing and verification for the owner passphrase (ASVS V11.4.1). |
| `smol-toml` | MIT | Parsing `gateway.toml` configuration files. |
| `zod` | MIT | Strict schema validation for `gateway.toml` configuration. |
