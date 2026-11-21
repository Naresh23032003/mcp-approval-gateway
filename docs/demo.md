# Demo upstream MCP server

The bundled demo server is a small in-memory MCP server that ships in the same image as `mcp-approval-gateway`. It lets you test the gateway without connecting another application.

## Security warning

Never publish the demo server port to the host or the internet.

The demo server has no authentication on purpose. Its safety comes from network isolation:
- For local development, leave `DEMO_HOST` at the default `127.0.0.1`.
- In Docker Compose, keep the demo service on an internal container network with no published host ports, so only the gateway container can reach `http://demo:9000/mcp`.

## Tools

The server exposes two tools over MCP Streamable HTTP (stateless mode, JSON responses) at `POST /mcp`:

### `notes.search`

Searches the in-memory notes list using a case-insensitive substring match.

- **Input:** `{ "query": "<string>" }` (1 to 200 characters, unknown keys rejected).
- **Annotations:** `readOnlyHint: true`.
- **Output:** Up to 20 matching notes formatted one per line as `<id>: <text>`, or `No notes match.` when nothing matches.

### `notes.append_note`

Appends a new note to the in-memory notes list.

- **Input:** `{ "text": "<string>" }` (1 to 1000 characters, unknown keys rejected).
- **Annotations:** `readOnlyHint: false`, `destructiveHint: false`.
- **Output:** `Added note <id>.`

## In-memory store

Notes are stored in memory only and nothing is written to disk. On startup, the store is seeded with three notes:

1. `Water the plants on Sunday`
2. `Renew the passport in March`
3. `Router admin page is on the second shelf`

Appended notes receive sequential IDs starting at `4`. The store holds at most 1000 notes; once full, appending a new note drops the oldest non-seed note.

## How to run

Build the project and start the demo server locally:

```sh
npm run build
node dist/cli.js demo
```

### Configuration

The demo server does not read `gateway.toml`. It reads two optional environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DEMO_HOST` | `127.0.0.1` | Host address to bind. Set to `0.0.0.0` only on an isolated container network. |
| `DEMO_PORT` | `9000` | TCP port to listen on (0 to 65535). |

### Docker

To run the demo command from the container image on a private Docker network:

```sh
docker run --rm -e DEMO_HOST=0.0.0.0 mcp-approval-gateway:dev demo
```

If you need a temporary local smoke test from your machine, bind only to loopback (never `0.0.0.0` on the host):

```sh
docker run --rm -e DEMO_HOST=0.0.0.0 -p 127.0.0.1:19000:9000 mcp-approval-gateway:dev demo
```

## HTTP behavior

- `POST /mcp`: handles MCP Streamable HTTP JSON-RPC requests. JSON request bodies are limited to `64 KB` (larger bodies return `413`).
- `GET /mcp` and `DELETE /mcp`: return `405` with header `Allow: POST`.
- All other paths and methods: return `404`.
