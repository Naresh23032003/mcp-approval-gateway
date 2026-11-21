import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import type Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import type { Config } from "../src/config/schema.js";
import { createOAuthRouter } from "../src/oauth/router.js";
import { DEFAULT_CSP } from "../src/server/headers.js";
import { LISTEN_HOST } from "../src/server/listen.js";
import { createPublicApp } from "../src/server/public-app.js";
import { listAuditEvents } from "../src/store/audit.js";
import { getClientById } from "../src/store/clients.js";
import { openDb } from "../src/store/db.js";

const TEST_CONFIG: Pick<Config, "public_base_url" | "tools"> = {
  public_base_url: "https://gw.example.ts.net",
  tools: [{ name: "notes.search", class: "read", group: "read" }]
};

const ALLOWED_RESPONSE_KEYS = [
  "client_id",
  "client_id_issued_at",
  "client_name",
  "grant_types",
  "redirect_uris",
  "response_types",
  "token_endpoint_auth_method"
];

const servers: http.Server[] = [];
const dbs: Database.Database[] = [];
const tempDirs: string[] = [];

async function startDcrServer() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpgw-dcr-"));
  tempDirs.push(dir);
  const db = openDb(dir);
  dbs.push(db);
  const app = createPublicApp({
    oauthRouter: createOAuthRouter({ config: TEST_CONFIG, db })
  });
  const server = http.createServer(app);
  servers.push(server);
  const addr = await new Promise<AddressInfo>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, LISTEN_HOST, () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("Missing TCP address"));
        return;
      }
      resolve(address);
    });
  });
  return {
    baseUrl: `http://${addr.address}:${addr.port}`,
    db
  };
}

function expectRegisterHeaders(res: Response): void {
  expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  expect(res.headers.get("strict-transport-security")).toBe("max-age=31536000");
  expect(res.headers.get("referrer-policy")).toBe("no-referrer");
  expect(res.headers.get("cache-control")).toBe("no-store");
  expect(res.headers.get("content-security-policy")).toBe(DEFAULT_CSP);
  expect(res.headers.get("x-powered-by")).toBeNull();
  expect(res.headers.get("access-control-allow-credentials")).toBeNull();
}

function countClients(db: Database.Database): number {
  const row = db.prepare("SELECT COUNT(*) AS total FROM clients").get() as { total: number };
  return row.total;
}

afterEach(async () => {
  while (servers.length > 0) {
    const server = servers.pop();
    if (server && server.listening) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }
  }
  while (dbs.length > 0) {
    const db = dbs.pop();
    if (db && db.open) {
      db.close();
    }
  }
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe("Dynamic client registration (POST /register)", () => {
  it("registers a public client with loopback http redirect URI, writes audit event and returns only allow-listed fields (V15.3.1)", async () => {
    const { baseUrl, db } = await startDcrServer();

    const res = await fetch(`${baseUrl}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: [
          "http://127.0.0.1:4321/callback",
          "http://localhost:4321/callback",
          "http://[::1]:4321/callback",
          "https://client.example/cb",
          "com.example.app:/callback"
        ],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        extra_ignored_field: "must not be stored",
        client_uri: "https://client.example"
      })
    });

    expect(res.status).toBe(201);
    expectRegisterHeaders(res);

    const body = (await res.json()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(ALLOWED_RESPONSE_KEYS);
    expect(body).not.toHaveProperty("client_secret");
    expect(body).not.toHaveProperty("client_secret_expires_at");
    expect(body).not.toHaveProperty("extra_ignored_field");
    expect(body).not.toHaveProperty("client_uri");

    expect(typeof body.client_id).toBe("string");
    // UUID v4 has 122 bits of randomness.
    expect(String(body.client_id)).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
    expect(typeof body.client_id_issued_at).toBe("number");
    expect(body.client_name).toBe("Unnamed client");
    expect(body.token_endpoint_auth_method).toBe("none");
    expect(body.grant_types).toEqual(["authorization_code"]);
    expect(body.response_types).toEqual(["code"]);
    expect(body.redirect_uris).toEqual([
      "http://127.0.0.1:4321/callback",
      "http://localhost:4321/callback",
      "http://[::1]:4321/callback",
      "https://client.example/cb",
      "com.example.app:/callback"
    ]);

    const stored = getClientById(db, String(body.client_id));
    expect(stored).toBeDefined();
    expect(stored?.clientName).toBe("Unnamed client");
    expect(stored?.redirectUris).toEqual(body.redirect_uris);

    const events = listAuditEvents(db);
    expect(events).toHaveLength(1);
    expect(events[0]?.event).toBe("client_registered");
    expect(events[0]?.client_id).toBe(body.client_id);
  });

  it("omits client_secret even when token_endpoint_auth_method is omitted and stores literal script text in client_name", async () => {
    const { baseUrl, db } = await startDcrServer();
    const xssName = "<script>alert(1)</script>";

    const res = await fetch(`${baseUrl}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
        client_name: xssName
      })
    });

    expect(res.status).toBe(201);
    expectRegisterHeaders(res);

    const body = (await res.json()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(ALLOWED_RESPONSE_KEYS);
    expect(body).not.toHaveProperty("client_secret");
    expect(body.token_endpoint_auth_method).toBe("none");
    expect(body.client_name).toBe(xssName);

    const stored = getClientById(db, String(body.client_id));
    expect(stored?.clientName).toBe(xssName);
  });

  it("rejects invalid client metadata with 400 invalid_client_metadata and stores no rows", async () => {
    const invalidPayloads: Array<{ label: string; payload: Record<string, unknown> }> = [
      {
        label: "client_secret_basic auth method",
        payload: {
          redirect_uris: ["https://client.example/cb"],
          token_endpoint_auth_method: "client_secret_basic"
        }
      },
      {
        label: "javascript redirect URI",
        payload: {
          redirect_uris: ["javascript:alert(1)"]
        }
      },
      {
        label: "data redirect URI",
        payload: {
          redirect_uris: ["data:text/html,hello"]
        }
      },
      {
        label: "file redirect URI",
        payload: {
          redirect_uris: ["file:///etc/passwd"]
        }
      },
      {
        label: "vbscript redirect URI",
        payload: {
          redirect_uris: ["vbscript:msgbox(1)"]
        }
      },
      {
        label: "6 redirect URIs",
        payload: {
          redirect_uris: [
            "https://client.example/1",
            "https://client.example/2",
            "https://client.example/3",
            "https://client.example/4",
            "https://client.example/5",
            "https://client.example/6"
          ]
        }
      },
      {
        label: "empty redirect_uris",
        payload: {
          redirect_uris: []
        }
      },
      {
        label: "fragment in redirect URI",
        payload: {
          redirect_uris: ["https://client.example/cb#frag"]
        }
      },
      {
        label: "empty trailing fragment in redirect URI",
        payload: {
          redirect_uris: ["https://client.example/cb#"]
        }
      },
      {
        label: "non-loopback http redirect URI",
        payload: {
          redirect_uris: ["http://evil.example/cb"]
        }
      },
      {
        label: "credentials in redirect URI",
        payload: {
          redirect_uris: ["https://user:pass@client.example/cb"]
        }
      },
      {
        label: "empty credentials in redirect URI",
        payload: {
          redirect_uris: ["https://@client.example/cb"]
        }
      },
      {
        label: "custom scheme without dot or dash",
        payload: {
          redirect_uris: ["myapp:/callback"]
        }
      },
      {
        label: "redirect URI longer than 2048 chars",
        payload: {
          redirect_uris: [`https://client.example/${"a".repeat(2040)}`]
        }
      },
      {
        label: "client_name longer than 100 chars",
        payload: {
          redirect_uris: ["https://client.example/cb"],
          client_name: "x".repeat(101)
        }
      },
      {
        label: "unsupported grant_type",
        payload: {
          redirect_uris: ["https://client.example/cb"],
          grant_types: ["client_credentials"]
        }
      },
      {
        label: "unsupported response_type",
        payload: {
          redirect_uris: ["https://client.example/cb"],
          response_types: ["token"]
        }
      },
      {
        label: "multiple response_types",
        payload: {
          redirect_uris: ["https://client.example/cb"],
          response_types: ["code", "token"]
        }
      }
    ];

    // Run in batches of 8 per server instance so the 10/hour rate limit does not interfere.
    for (let start = 0; start < invalidPayloads.length; start += 8) {
      const { baseUrl, db } = await startDcrServer();
      const batch = invalidPayloads.slice(start, start + 8);

      for (const testCase of batch) {
        const res = await fetch(`${baseUrl}/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(testCase.payload)
        });
        expect(res.status, testCase.label).toBe(400);
        expectRegisterHeaders(res);
        const body = (await res.json()) as Record<string, unknown>;
        expect(body.error, testCase.label).toBe("invalid_client_metadata");
      }

      expect(countClients(db)).toBe(0);
      expect(listAuditEvents(db)).toHaveLength(0);
    }
  });

  it("rejects non-JSON Content-Type on POST /register with 415", async () => {
    const { baseUrl, db } = await startDcrServer();

    const res = await fetch(`${baseUrl}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "redirect_uris=https%3A%2F%2Fclient.example%2Fcb"
    });
    expect(res.status).toBe(415);
    expectRegisterHeaders(res);
    expect(await res.json()).toEqual({ error: "unsupported_media_type" });
    expect(countClients(db)).toBe(0);
  });

  it("rate limits POST /register to 10 requests per hour per source (V6.1.1)", async () => {
    const { baseUrl, db } = await startDcrServer();

    for (let i = 1; i <= 10; i++) {
      const res = await fetch(`${baseUrl}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          redirect_uris: ["http://127.0.0.1:8080/callback"],
          client_name: `Client ${i}`
        })
      });
      expect(res.status, `registration ${i}`).toBe(201);
      expectRegisterHeaders(res);
    }

    const eleventh = await fetch(`${baseUrl}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: ["http://127.0.0.1:8080/callback"],
        client_name: "Client 11"
      })
    });
    expect(eleventh.status).toBe(429);
    expectRegisterHeaders(eleventh);
    const body = (await eleventh.json()) as Record<string, unknown>;
    expect(body.error).toBe("too_many_requests");

    expect(countClients(db)).toBe(10);
    expect(listAuditEvents(db)).toHaveLength(10);
  });
});
