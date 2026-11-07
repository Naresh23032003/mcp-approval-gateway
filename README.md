# mcp-approval-gateway

Self-hosted MCP gateway: Claude and ChatGPT read your tailnet apps over OAuth 2.1, and every write waits for your approval on a tailnet-only page.

**Status: under construction.** The design is done and the build is in progress. Nothing here is ready to run yet.

## What it will do
- One self-hosted Docker container next to your apps, reachable by Claude and ChatGPT over OAuth 2.1.
- Read-only by default. Every write is held until you approve it on a page that only your tailnet can reach, behind a passphrase.
- Per-tool scoped tokens, instant revoke, an audit log.

## Licence
MIT. See [LICENSE](LICENSE).
