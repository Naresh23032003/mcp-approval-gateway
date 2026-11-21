import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import type Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { ServerError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { Config } from "../src/config/schema.js";
import { SqliteOAuthProvider } from "../src/oauth/provider.js";
import { createOAuthRouter } from "../src/oauth/router.js";
import { DEFAULT_CSP } from "../src/server/headers.js";
import { LISTEN_HOST } from "../src/server/listen.js";
import { createPublicApp } from "../src/server/public-app.js";
import { listAuditEvents } from "../src/store/audit.js";
import { openDb } from "../src/store/db.js";

const PUBLIC_BASE_URL = "https://gw.example.ts.net";

const TEST_CONFIG: Pick<Config, "public_base_url" | "tools"> = {
  public_base_url: PUBLIC_BASE_URL,
  tools: [
    { name: "notes.search", class: "read", group: "read" },
    { name: "mail.list", class: "read", group: "mail" },
    { name: "notes.append_note", class: "write" }
  ]
};

const servers: http.Server[] = [];
const dbs: Database.Database[] = [];
const tempDirs: string[] = [];

async function startPublicTestServer(config: Pick<Config, "public_base_url" | "tools"> = TEST_CONFIG) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpgw-meta-"));
  tempDirs.push(dir);
  const db = openDb(dir);
  dbs.push(db);
  const provider = new SqliteOAuthProvider(db);
  const app = createPublicApp({
    oauthRouter: createOAuthRouter({ config, db, provider })
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
    db,
    provider
  };
}

function expectSecurityHeadersWithoutCredentialedCors(res: Response): void {
  expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  expect(res.headers.get("strict-transport-security")).toBe("max-age=31536000");
  expect(res.headers.get("referrer-policy")).toBe("no-referrer");
  expect(res.headers.get("cache-control")).toBe("no-store");
  expect(res.headers.get("content-security-policy")).toBe(DEFAULT_CSP);
  expect(res.headers.get("x-powered-by")).toBeNull();
  expect(res.headers.get("access-control-allow-credentials")).toBeNull();
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

describe("OAuth metadata discovery documents (S1, V10.4.4, V3.4.2)", () => {
  it("serves authorization server metadata with exact issuer, endpoints, PKCE S256 and public-only grants", async () => {
    const { baseUrl } = await startPublicTestServer();

    const res = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
    expect(res.status).toBe(200);
    expectSecurityHeadersWithoutCredentialedCors(res);

    const rawText = await res.text();
    const doc = JSON.parse(rawText) as Record<string, unknown>;

    expect(doc.issuer).toBe(PUBLIC_BASE_URL);
    expect(String(doc.issuer).startsWith(PUBLIC_BASE_URL)).toBe(true);
    expect(doc.authorization_endpoint).toBe(`${PUBLIC_BASE_URL}/authorize`);
    expect(doc.token_endpoint).toBe(`${PUBLIC_BASE_URL}/token`);
    expect(doc.registration_endpoint).toBe(`${PUBLIC_BASE_URL}/register`);
    expect(doc.response_types_supported).toEqual(["code"]);
    expect(doc.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
    expect(doc.token_endpoint_auth_methods_supported).toEqual(["none"]);
    expect(doc.code_challenge_methods_supported).toEqual(["S256"]);
    expect(doc.scopes_supported).toEqual(["read", "mail", "write:notes.append_note"]);

    expect(doc).not.toHaveProperty("revocation_endpoint");
    expect(rawText).not.toContain("revocation_endpoint");
    expect(rawText).not.toContain("implicit");
    expect(rawText).not.toContain("client_credentials");
    expect(rawText).not.toContain("password");
  });

  it("serves identical protected resource metadata at both root and /mcp path-suffixed URLs", async () => {
    const { baseUrl } = await startPublicTestServer();

    const rootRes = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`);
    expect(rootRes.status).toBe(200);
    expectSecurityHeadersWithoutCredentialedCors(rootRes);
    const rootDoc = (await rootRes.json()) as Record<string, unknown>;

    const suffixedRes = await fetch(`${baseUrl}/.well-known/oauth-protected-resource/mcp`);
    expect(suffixedRes.status).toBe(200);
    expectSecurityHeadersWithoutCredentialedCors(suffixedRes);
    const suffixedDoc = (await suffixedRes.json()) as Record<string, unknown>;

    expect(rootDoc).toEqual({
      resource: `${PUBLIC_BASE_URL}/mcp`,
      authorization_servers: [PUBLIC_BASE_URL],
      scopes_supported: ["read", "mail", "write:notes.append_note"],
      resource_name: "mcp-approval-gateway"
    });
    expect(suffixedDoc).toEqual(rootDoc);

    // Unknown subpath does not match and sends no CORS headers.
    const unknownRes = await fetch(`${baseUrl}/.well-known/oauth-protected-resource/other`);
    expect(unknownRes.status).toBe(404);
    expect(unknownRes.headers.get("access-control-allow-origin")).toBeNull();
  });
});

describe("Unimplemented /authorize and /token endpoints in mcpgw-005", () => {
  it("returns OAuth error JSON with no stack trace and no DB side effects on GET /authorize and POST /token", async () => {
    const { baseUrl, db, provider } = await startPublicTestServer();

    const authRes = await fetch(`${baseUrl}/authorize`);
    const authText = await authRes.text();
    expect(authRes.status).toBe(400);
    expectSecurityHeadersWithoutCredentialedCors(authRes);
    expect(authRes.headers.get("access-control-allow-origin")).toBeNull();
    const authJson = JSON.parse(authText) as Record<string, unknown>;
    expect(typeof authJson.error).toBe("string");
    expect(authText).not.toContain("at ");

    const tokenRes = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code"
    });
    const tokenText = await tokenRes.text();
    expect(tokenRes.status).toBe(400);
    expectSecurityHeadersWithoutCredentialedCors(tokenRes);
    const tokenJson = JSON.parse(tokenText) as Record<string, unknown>;
    expect(typeof tokenJson.error).toBe("string");
    expect(tokenText).not.toContain("at ");

    expect(listAuditEvents(db)).toHaveLength(0);

    // Register a client and call POST /token to exercise the provider rejection path.
    const regRes = await fetch(`${baseUrl}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: ["http://127.0.0.1:8080/callback"],
        client_name: "Token Probe"
      })
    });
    expect(regRes.status).toBe(201);
    const registered = (await regRes.json()) as { client_id: string };
    expect(listAuditEvents(db)).toHaveLength(1);

    const tokenStubRes = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: registered.client_id,
        code: "fake-code",
        code_verifier: "fake-verifier"
      }).toString()
    });
    const tokenStubText = await tokenStubRes.text();
    expect(tokenStubRes.status).toBe(500);
    expectSecurityHeadersWithoutCredentialedCors(tokenStubRes);
    expect(JSON.parse(tokenStubText)).toEqual({
      error: "server_error",
      error_description: "not implemented yet"
    });
    expect(tokenStubText).not.toContain("at ");
    expect(listAuditEvents(db)).toHaveLength(1);

    // Verify provider methods reject directly with ServerError and revokeToken is undefined.
    const storedClient = provider.clientsStore.getClient(registered.client_id);
    expect(storedClient).toBeDefined();
    expect("revokeToken" in provider).toBe(false);
    if (storedClient !== undefined) {
      await expect(
        provider.authorize(
          storedClient,
          { codeChallenge: "abc", redirectUri: "http://127.0.0.1:8080/callback" },
          {} as never
        )
      ).rejects.toThrow(ServerError);
      await expect(
        provider.challengeForAuthorizationCode(storedClient, "code")
      ).rejects.toThrow("not implemented yet");
      await expect(
        provider.exchangeAuthorizationCode(storedClient, "code")
      ).rejects.toThrow("not implemented yet");
      await expect(
        provider.exchangeRefreshToken(storedClient, "refresh")
      ).rejects.toThrow("not implemented yet");
      await expect(provider.verifyAccessToken("tok")).rejects.toThrow("not implemented yet");
    }
  });
});
