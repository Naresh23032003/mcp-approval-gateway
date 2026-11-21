import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import type Database from "better-sqlite3";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Config } from "../src/config/schema.js";
import { createOAuthRouter } from "../src/oauth/router.js";
import { hashPassphrase, verifyPassphrase } from "../src/passphrase.js";
import { LISTEN_HOST } from "../src/server/listen.js";
import { createPublicApp } from "../src/server/public-app.js";
import { listAuditEvents } from "../src/store/audit.js";
import { getAuthCodeByHash, hashAuthCode } from "../src/store/auth-codes.js";
import { insertClient } from "../src/store/clients.js";
import { openDb } from "../src/store/db.js";
import { listGrantsForClient } from "../src/store/grants.js";
import { CONSENT_SCRIPT_SHA256 } from "../src/ui/consent-page.js";
import { CONSENT_STYLE_SHA256 } from "../src/ui/style.js";

// Test fixture value only. Not a real secret.
const TEST_PASSPHRASE = "test-fixture-passphrase-correct-horse";
const PUBLIC_BASE_URL = "https://gw.example.ts.net";
const CANONICAL_RESOURCE = `${PUBLIC_BASE_URL}/mcp`;
const VALID_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

let testPassphraseHash = "";

const servers: http.Server[] = [];
const dbs: Database.Database[] = [];
const tempDirs: string[] = [];

beforeAll(async () => {
  testPassphraseHash = await hashPassphrase(TEST_PASSPHRASE);
});

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

interface TestServerOptions {
  verifyPassphrase?: (storedHash: string, pw: string) => Promise<boolean>;
  now?: () => number;
}

async function startConsentServer(options: TestServerOptions = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpgw-auth-"));
  tempDirs.push(dir);
  const db = openDb(dir);
  dbs.push(db);

  const config: Pick<Config, "public_base_url" | "tools" | "owner_passphrase_hash"> = {
    public_base_url: PUBLIC_BASE_URL,
    owner_passphrase_hash: testPassphraseHash,
    tools: [
      { name: "notes.search", class: "read", group: "read" },
      { name: "notes.get", class: "read", group: "read" },
      { name: "finance.list", class: "read", group: "finance" },
      { name: "mail.list", class: "read", group: "mail" },
      { name: "notes.append_note", class: "write" }
    ]
  };

  const oauthRouter = createOAuthRouter({
    config,
    db,
    verifyPassphrase: options.verifyPassphrase,
    now: options.now
  });
  const app = createPublicApp({ oauthRouter });
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

function registerTestClient(
  db: Database.Database,
  overrides: Partial<{
    clientId: string;
    clientName: string;
    redirectUris: string[];
    createdAt: number;
  }> = {}
) {
  return insertClient(db, {
    clientId: overrides.clientId ?? crypto.randomUUID(),
    clientName: overrides.clientName ?? "Claude Desktop",
    redirectUris: overrides.redirectUris ?? ["https://claude.ai/api/mcp/auth_callback"],
    createdAt: overrides.createdAt ?? Math.floor(Date.now() / 1000) - 120
  });
}

function extractCsrfFromHtml(htmlText: string): string {
  const match = /name="csrf_token"\s+value="([^"]+)"/.exec(htmlText);
  if (!match || match[1] === undefined) {
    throw new Error("Missing csrf_token hidden input in HTML");
  }
  return match[1];
}

function extractCookiePair(res: Response): string {
  const setCookie = res.headers.get("set-cookie");
  if (setCookie === null) {
    throw new Error("Missing Set-Cookie header");
  }
  const firstSegment = setCookie.split(";")[0];
  if (firstSegment === undefined) {
    throw new Error("Malformed Set-Cookie header");
  }
  return firstSegment;
}

function countAuthFailures(db: Database.Database): number {
  const row = db.prepare("SELECT COUNT(*) AS total FROM auth_failures").get() as { total: number };
  return row.total;
}

describe("Consent page and GET /authorize", () => {
  it("renders consent page with metadata, password field, CSRF cookie and strict hash CSP", async () => {
    const fixedNow = 1700000120;
    const { baseUrl, db } = await startConsentServer({ now: () => fixedNow });
    const client = registerTestClient(db, {
      clientName: "Claude Desktop",
      redirectUris: ["https://claude.ai/api/mcp/auth_callback"],
      createdAt: fixedNow - 120
    });

    const query = new URLSearchParams({
      client_id: client.clientId,
      redirect_uri: "https://claude.ai/api/mcp/auth_callback",
      response_type: "code",
      code_challenge: VALID_CHALLENGE,
      code_challenge_method: "S256",
      scope: "read finance write:notes.append_note unknown_scope",
      state: "xyz123",
      resource: CANONICAL_RESOURCE
    });

    const res = await fetch(`${baseUrl}/authorize?${query.toString()}`);
    const body = await res.text();

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(res.headers.get("access-control-allow-origin")).toBeNull();

    const setCookie = res.headers.get("set-cookie");
    expect(setCookie).not.toBeNull();
    expect(setCookie).toMatch(
      /^__Host-consent_csrf=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict$/
    );

    const csp = res.headers.get("content-security-policy");
    expect(csp).toBe(
      `default-src 'none'; style-src 'sha256-${CONSENT_STYLE_SHA256}'; script-src 'sha256-${CONSENT_SCRIPT_SHA256}'; form-action 'self' https://claude.ai; frame-ancestors 'none'; base-uri 'none'`
    );
    expect(csp).not.toContain("unsafe-inline");

    expect(body).toContain("Claude Desktop");
    expect(body).toContain("gw.example.ts.net");
    expect(body).toContain("claude.ai");
    expect(body).toContain("2 minutes ago");
    expect(body).toContain("Not verified");
    expect(body).toContain("Always included.");
    expect(body).toContain("notes.search, notes.get");
    expect(body).toContain("finance");
    expect(body).toContain("finance.list");
    expect(body).not.toContain("write:notes.append_note");
    expect(body).not.toContain("unknown_scope");
    expect(body).not.toContain("mail.list");
    expect(body).toContain('autocomplete="current-password"');
    expect(body).toContain('type="password"');
    expect(body).toContain('aria-pressed="false"');
    expect(body).toContain("The one you set with hash-passphrase.");
    expect(body).toContain("Allow read access");
    expect(body).toContain("formnovalidate");
    expect(body).not.toMatch(/<a[\s>]/i);
    expect(body).not.toContain("/approvals");
    expect(body).not.toContain("/admin");
  });

  it("puts <scheme>: in CSP form-action for custom-scheme redirect URIs", async () => {
    const { baseUrl, db } = await startConsentServer();
    const client = registerTestClient(db, {
      redirectUris: ["com.example.app:/callback"]
    });

    const query = new URLSearchParams({
      client_id: client.clientId,
      redirect_uri: "com.example.app:/callback",
      response_type: "code",
      code_challenge: VALID_CHALLENGE,
      code_challenge_method: "S256"
    });

    const res = await fetch(`${baseUrl}/authorize?${query.toString()}`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-security-policy")).toContain(
      "form-action 'self' com.example.app:;"
    );
  });

  it("rejects unregistered redirect_uri, unknown client, missing/plain PKCE, bad response_type and wrong resource with 400 and no redirect", async () => {
    const { baseUrl, db } = await startConsentServer();
    const client = registerTestClient(db, {
      redirectUris: ["https://claude.ai/api/mcp/auth_callback"]
    });

    const cases: Array<{ label: string; params: Record<string, string>; expectedReason: string; forbiddenEcho?: string }> = [
      {
        label: "unknown client",
        params: {
          client_id: "no-such-client-999",
          redirect_uri: "https://claude.ai/api/mcp/auth_callback",
          response_type: "code",
          code_challenge: VALID_CHALLENGE,
          code_challenge_method: "S256"
        },
        expectedReason: "unknown client",
        forbiddenEcho: "no-such-client-999"
      },
      {
        label: "unregistered redirect_uri",
        params: {
          client_id: client.clientId,
          redirect_uri: "https://evil.example/steal",
          response_type: "code",
          code_challenge: VALID_CHALLENGE,
          code_challenge_method: "S256"
        },
        expectedReason: "redirect address not registered",
        forbiddenEcho: "https://evil.example/steal"
      },
      {
        label: "redirect_uri with trailing slash difference (exact string match, V10.4.1)",
        params: {
          client_id: client.clientId,
          redirect_uri: "https://claude.ai/api/mcp/auth_callback/",
          response_type: "code",
          code_challenge: VALID_CHALLENGE,
          code_challenge_method: "S256"
        },
        expectedReason: "redirect address not registered",
        forbiddenEcho: "https://claude.ai/api/mcp/auth_callback/"
      },
      {
        label: "missing code_challenge",
        params: {
          client_id: client.clientId,
          redirect_uri: "https://claude.ai/api/mcp/auth_callback",
          response_type: "code",
          code_challenge_method: "S256"
        },
        expectedReason: "PKCE S256 missing"
      },
      {
        label: "plain code_challenge_method",
        params: {
          client_id: client.clientId,
          redirect_uri: "https://claude.ai/api/mcp/auth_callback",
          response_type: "code",
          code_challenge: VALID_CHALLENGE,
          code_challenge_method: "plain"
        },
        expectedReason: "PKCE S256 missing"
      },
      {
        label: "wrong response_type",
        params: {
          client_id: client.clientId,
          redirect_uri: "https://claude.ai/api/mcp/auth_callback",
          response_type: "token",
          code_challenge: VALID_CHALLENGE,
          code_challenge_method: "S256"
        },
        expectedReason: "request type not supported"
      },
      {
        label: "wrong resource",
        params: {
          client_id: client.clientId,
          redirect_uri: "https://claude.ai/api/mcp/auth_callback",
          response_type: "code",
          code_challenge: VALID_CHALLENGE,
          code_challenge_method: "S256",
          resource: "https://other.example/mcp"
        },
        expectedReason: "resource not recognised",
        forbiddenEcho: "https://other.example/mcp"
      }
    ];

    for (const tc of cases) {
      const res = await fetch(`${baseUrl}/authorize?${new URLSearchParams(tc.params).toString()}`, {
        redirect: "manual"
      });
      const text = await res.text();
      expect(res.status, tc.label).toBe(400);
      expect(res.headers.get("location"), tc.label).toBeNull();
      expect(res.headers.get("content-type"), tc.label).toBe("text/html; charset=utf-8");
      expect(text, tc.label).toContain("This connection request was not accepted.");
      expect(text, tc.label).toContain(tc.expectedReason);
      if (tc.forbiddenEcho !== undefined) {
        expect(text, tc.label).not.toContain(tc.forbiddenEcho);
      }
    }
  });

  it("escapes <script> and bidi characters in client_name when rendering GET /authorize (V1.2.1)", async () => {
    const { baseUrl, db } = await startConsentServer();
    const client = registerTestClient(db, {
      clientName: "<script>alert(1)</script> \u202Ertl",
      redirectUris: ["https://claude.ai/api/mcp/auth_callback"]
    });

    const query = new URLSearchParams({
      client_id: client.clientId,
      redirect_uri: "https://claude.ai/api/mcp/auth_callback",
      response_type: "code",
      code_challenge: VALID_CHALLENGE,
      code_challenge_method: "S256"
    });

    const res = await fetch(`${baseUrl}/authorize?${query.toString()}`);
    const body = await res.text();

    expect(res.status).toBe(200);
    expect(body).not.toContain("<script>alert");
    expect(body).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(body).toContain("\\u202E");
    expect(body).not.toContain("\u202E");
  });

  it("returns plain 404 for methods other than GET and POST on /authorize", async () => {
    const { baseUrl } = await startConsentServer();

    for (const method of ["PUT", "DELETE", "PATCH", "OPTIONS"]) {
      const res = await fetch(`${baseUrl}/authorize`, { method });
      expect(res.status, method).toBe(404);
      expect(res.headers.get("content-type"), method).toBe("text/plain; charset=utf-8");
      expect(res.headers.get("access-control-allow-origin"), method).toBeNull();
      expect(await res.text(), method).toBe("Not found.");
    }
  });
});

describe("Consent submission (POST /authorize)", () => {
  it("rejects missing CSRF field, mismatching cookie, and foreign Origin with 403 without calling Argon2id or adding auth_failures (V3.5.1)", async () => {
    const verifySpy = vi.fn(verifyPassphrase);
    const { baseUrl, db } = await startConsentServer({ verifyPassphrase: verifySpy });
    const client = registerTestClient(db);

    const getRes = await fetch(
      `${baseUrl}/authorize?${new URLSearchParams({
        client_id: client.clientId,
        redirect_uri: "https://claude.ai/api/mcp/auth_callback",
        response_type: "code",
        code_challenge: VALID_CHALLENGE,
        code_challenge_method: "S256"
      }).toString()}`
    );
    const csrfToken = extractCsrfFromHtml(await getRes.text());
    const cookie = extractCookiePair(getRes);

    const baseForm = {
      client_id: client.clientId,
      redirect_uri: "https://claude.ai/api/mcp/auth_callback",
      response_type: "code",
      code_challenge: VALID_CHALLENGE,
      code_challenge_method: "S256",
      scope: "",
      decision: "allow",
      passphrase: TEST_PASSPHRASE
    };

    // 1. Missing CSRF field
    const noFieldRes = await fetch(`${baseUrl}/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: PUBLIC_BASE_URL,
        Cookie: cookie
      },
      body: new URLSearchParams(baseForm).toString(),
      redirect: "manual"
    });
    expect(noFieldRes.status).toBe(403);
    expect(await noFieldRes.text()).toContain("request not accepted");

    // 2. Mismatching cookie
    const badCookieRes = await fetch(`${baseUrl}/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: PUBLIC_BASE_URL,
        Cookie: "__Host-consent_csrf=wrong-token-value"
      },
      body: new URLSearchParams({ ...baseForm, csrf_token: csrfToken }).toString(),
      redirect: "manual"
    });
    expect(badCookieRes.status).toBe(403);

    // 3. Foreign Origin
    const foreignOriginRes = await fetch(`${baseUrl}/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: "https://attacker.example",
        Cookie: cookie
      },
      body: new URLSearchParams({ ...baseForm, csrf_token: csrfToken }).toString(),
      redirect: "manual"
    });
    expect(foreignOriginRes.status).toBe(403);

    // 4. Missing Origin and missing Sec-Fetch-Site
    const missingOriginRes = await fetch(`${baseUrl}/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: cookie
      },
      body: new URLSearchParams({ ...baseForm, csrf_token: csrfToken }).toString(),
      redirect: "manual"
    });
    expect(missingOriginRes.status).toBe(403);

    expect(verifySpy).not.toHaveBeenCalled();
    expect(countAuthFailures(db)).toBe(0);
    expect(listGrantsForClient(db, client.clientId)).toHaveLength(0);
  });

  it("accepts Sec-Fetch-Site: same-origin when Origin is absent, issues hashed 60s code, writes grant and audit, and encodes state (V1.2.2)", async () => {
    const fixedNow = 1700001000;
    const { baseUrl, db } = await startConsentServer({ now: () => fixedNow });
    const client = registerTestClient(db, { createdAt: fixedNow - 60 });
    const trickyState = "a&b#c=d e";

    const getRes = await fetch(
      `${baseUrl}/authorize?${new URLSearchParams({
        client_id: client.clientId,
        redirect_uri: "https://claude.ai/api/mcp/auth_callback",
        response_type: "code",
        code_challenge: VALID_CHALLENGE,
        code_challenge_method: "S256",
        state: trickyState
      }).toString()}`
    );
    const csrfToken = extractCsrfFromHtml(await getRes.text());
    const cookie = extractCookiePair(getRes);

    const postRes = await fetch(`${baseUrl}/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Sec-Fetch-Site": "same-origin",
        Cookie: cookie
      },
      body: new URLSearchParams({
        csrf_token: csrfToken,
        client_id: client.clientId,
        redirect_uri: "https://claude.ai/api/mcp/auth_callback",
        response_type: "code",
        code_challenge: VALID_CHALLENGE,
        code_challenge_method: "S256",
        scope: "",
        state: trickyState,
        decision: "allow",
        passphrase: TEST_PASSPHRASE
      }).toString(),
      redirect: "manual"
    });

    expect(postRes.status).toBe(302);
    const location = postRes.headers.get("location");
    expect(location).not.toBeNull();
    expect(location).toContain("a%26b%23c%3Dd");

    const parsedLocation = new URL(location!);
    expect(`${parsedLocation.origin}${parsedLocation.pathname}`).toBe(
      "https://claude.ai/api/mcp/auth_callback"
    );
    expect(parsedLocation.searchParams.get("state")).toBe(trickyState);

    const issuedCode = parsedLocation.searchParams.get("code");
    expect(issuedCode).not.toBeNull();
    expect(issuedCode!.length).toBeGreaterThanOrEqual(40);

    const grants = listGrantsForClient(db, client.clientId);
    expect(grants).toHaveLength(1);
    expect(grants[0]?.scopes).toEqual(["read"]);
    expect(grants[0]?.resource).toBe(CANONICAL_RESOURCE);
    expect(grants[0]?.createdAt).toBe(fixedNow);
    expect(grants[0]?.revokedAt).toBeNull();

    const storedCode = getAuthCodeByHash(db, hashAuthCode(issuedCode!));
    expect(storedCode).toBeDefined();
    expect(storedCode?.grantId).toBe(grants[0]?.grantId);
    expect(storedCode?.redirectUri).toBe("https://claude.ai/api/mcp/auth_callback");
    expect(storedCode?.codeChallenge).toBe(VALID_CHALLENGE);
    expect(storedCode?.expiresAt).toBe(fixedNow + 60);
    expect(storedCode?.usedAt).toBeNull();

    // Verify raw code is never stored in auth_codes.
    const rawCodeLookup = getAuthCodeByHash(db, issuedCode!);
    expect(rawCodeLookup).toBeUndefined();

    const events = listAuditEvents(db).filter((e) => e.event === "consent_granted");
    expect(events).toHaveLength(1);
    expect(events[0]?.client_id).toBe(client.clientId);
  });

  it("grants read plus ticked requested read groups and ignores tampered write or unknown scopes", async () => {
    const { baseUrl, db } = await startConsentServer();
    const client = registerTestClient(db);

    const getRes = await fetch(
      `${baseUrl}/authorize?${new URLSearchParams({
        client_id: client.clientId,
        redirect_uri: "https://claude.ai/api/mcp/auth_callback",
        response_type: "code",
        code_challenge: VALID_CHALLENGE,
        code_challenge_method: "S256",
        scope: "read finance write:notes.append_note"
      }).toString()}`
    );
    const csrfToken = extractCsrfFromHtml(await getRes.text());
    const cookie = extractCookiePair(getRes);

    const form = new URLSearchParams();
    form.append("csrf_token", csrfToken);
    form.append("client_id", client.clientId);
    form.append("redirect_uri", "https://claude.ai/api/mcp/auth_callback");
    form.append("response_type", "code");
    form.append("code_challenge", VALID_CHALLENGE);
    form.append("code_challenge_method", "S256");
    form.append("scope", "read finance write:notes.append_note");
    form.append("granted_scopes", "finance");
    form.append("granted_scopes", "write:notes.append_note");
    form.append("granted_scopes", "mail"); // in config, not requested
    form.append("granted_scopes", "admin"); // unknown
    form.append("decision", "allow");
    form.append("passphrase", TEST_PASSPHRASE);

    const postRes = await fetch(`${baseUrl}/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: PUBLIC_BASE_URL,
        Cookie: cookie
      },
      body: form.toString(),
      redirect: "manual"
    });

    expect(postRes.status).toBe(302);
    const grants = listGrantsForClient(db, client.clientId);
    expect(grants).toHaveLength(1);
    expect(grants[0]?.scopes).toEqual(["read", "finance"]);
  });

  it("verifies passphrase exactly as typed, rejects >1024 code points without hashing, and keeps ticked scopes on 401 (V6.2.8)", async () => {
    const verifySpy = vi.fn(verifyPassphrase);
    const { baseUrl, db } = await startConsentServer({ verifyPassphrase: verifySpy });
    const client = registerTestClient(db);

    const fetchForm = async () => {
      const getRes = await fetch(
        `${baseUrl}/authorize?${new URLSearchParams({
          client_id: client.clientId,
          redirect_uri: "https://claude.ai/api/mcp/auth_callback",
          response_type: "code",
          code_challenge: VALID_CHALLENGE,
          code_challenge_method: "S256",
          scope: "read finance"
        }).toString()}`
      );
      return {
        csrfToken: extractCsrfFromHtml(await getRes.text()),
        cookie: extractCookiePair(getRes)
      };
    };

    // 1. Different case
    const f1 = await fetchForm();
    const caseRes = await fetch(`${baseUrl}/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: PUBLIC_BASE_URL,
        Cookie: f1.cookie
      },
      body: new URLSearchParams({
        csrf_token: f1.csrfToken,
        client_id: client.clientId,
        redirect_uri: "https://claude.ai/api/mcp/auth_callback",
        response_type: "code",
        code_challenge: VALID_CHALLENGE,
        code_challenge_method: "S256",
        scope: "read finance",
        granted_scopes: "finance",
        decision: "allow",
        passphrase: TEST_PASSPHRASE.toUpperCase()
      }).toString(),
      redirect: "manual"
    });
    const caseBody = await caseRes.text();
    expect(caseRes.status).toBe(401);
    expect(caseBody).toContain('role="alert"');
    expect(caseBody).toContain('tabindex="-1"');
    expect(caseBody).toContain("Wrong passphrase. 4 tries left before a 15 minute lock.");
    expect(caseBody).toContain('value="finance" checked');
    expect(caseBody).toContain("Allow read and finance access");
    expect(caseBody).not.toContain(TEST_PASSPHRASE.toUpperCase());
    expect(verifySpy).toHaveBeenCalledTimes(1);

    // 2. Trailing space
    const f2 = await fetchForm();
    const spaceRes = await fetch(`${baseUrl}/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: PUBLIC_BASE_URL,
        Cookie: f2.cookie
      },
      body: new URLSearchParams({
        csrf_token: f2.csrfToken,
        client_id: client.clientId,
        redirect_uri: "https://claude.ai/api/mcp/auth_callback",
        response_type: "code",
        code_challenge: VALID_CHALLENGE,
        code_challenge_method: "S256",
        scope: "read finance",
        decision: "allow",
        passphrase: `${TEST_PASSPHRASE} `
      }).toString(),
      redirect: "manual"
    });
    expect(spaceRes.status).toBe(401);
    expect(verifySpy).toHaveBeenCalledTimes(2);

    // 3. Over 1024 code points: rejected without calling argon2 verify
    const f3 = await fetchForm();
    const longRes = await fetch(`${baseUrl}/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: PUBLIC_BASE_URL,
        Cookie: f3.cookie
      },
      body: new URLSearchParams({
        csrf_token: f3.csrfToken,
        client_id: client.clientId,
        redirect_uri: "https://claude.ai/api/mcp/auth_callback",
        response_type: "code",
        code_challenge: VALID_CHALLENGE,
        code_challenge_method: "S256",
        scope: "read finance",
        decision: "allow",
        passphrase: "a".repeat(1025)
      }).toString(),
      redirect: "manual"
    });
    expect(longRes.status).toBe(401);
    expect(verifySpy).toHaveBeenCalledTimes(2);
    expect(listGrantsForClient(db, client.clientId)).toHaveLength(0);
  });

  it("redirects with error=access_denied on decision=cancel without creating a grant or verifying passphrase", async () => {
    const verifySpy = vi.fn(verifyPassphrase);
    const { baseUrl, db } = await startConsentServer({ verifyPassphrase: verifySpy });
    const client = registerTestClient(db);

    const getRes = await fetch(
      `${baseUrl}/authorize?${new URLSearchParams({
        client_id: client.clientId,
        redirect_uri: "https://claude.ai/api/mcp/auth_callback",
        response_type: "code",
        code_challenge: VALID_CHALLENGE,
        code_challenge_method: "S256",
        state: "cancel-state-1"
      }).toString()}`
    );
    const csrfToken = extractCsrfFromHtml(await getRes.text());
    const cookie = extractCookiePair(getRes);

    const cancelRes = await fetch(`${baseUrl}/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: PUBLIC_BASE_URL,
        Cookie: cookie
      },
      body: new URLSearchParams({
        csrf_token: csrfToken,
        client_id: client.clientId,
        redirect_uri: "https://claude.ai/api/mcp/auth_callback",
        response_type: "code",
        code_challenge: VALID_CHALLENGE,
        code_challenge_method: "S256",
        scope: "",
        state: "cancel-state-1",
        decision: "cancel"
      }).toString(),
      redirect: "manual"
    });

    expect(cancelRes.status).toBe(302);
    const location = new URL(cancelRes.headers.get("location")!);
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("state")).toBe("cancel-state-1");
    expect(location.searchParams.get("code")).toBeNull();
    expect(verifySpy).not.toHaveBeenCalled();
    expect(listGrantsForClient(db, client.clientId)).toHaveLength(0);
    expect(
      listAuditEvents(db).filter((e) => e.event === "consent_granted" || e.event === "auth_failed")
    ).toHaveLength(0);
  });

  it("never writes the test passphrase or issued authorization code to logs or database rows", async () => {
    const capturedLogs: string[] = [];
    const origLog = console.log;
    const origWarn = console.warn;
    const origError = console.error;
    const origInfo = console.info;

    console.log = (...args: unknown[]) => {
      capturedLogs.push(args.map(String).join(" "));
    };
    console.warn = (...args: unknown[]) => {
      capturedLogs.push(args.map(String).join(" "));
    };
    console.error = (...args: unknown[]) => {
      capturedLogs.push(args.map(String).join(" "));
    };
    console.info = (...args: unknown[]) => {
      capturedLogs.push(args.map(String).join(" "));
    };

    try {
      const { baseUrl, db } = await startConsentServer();
      const client = registerTestClient(db);

      const getRes = await fetch(
        `${baseUrl}/authorize?${new URLSearchParams({
          client_id: client.clientId,
          redirect_uri: "https://claude.ai/api/mcp/auth_callback",
          response_type: "code",
          code_challenge: VALID_CHALLENGE,
          code_challenge_method: "S256"
        }).toString()}`
      );
      const csrfToken = extractCsrfFromHtml(await getRes.text());
      const cookie = extractCookiePair(getRes);

      const postRes = await fetch(`${baseUrl}/authorize`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Origin: PUBLIC_BASE_URL,
          Cookie: cookie
        },
        body: new URLSearchParams({
          csrf_token: csrfToken,
          client_id: client.clientId,
          redirect_uri: "https://claude.ai/api/mcp/auth_callback",
          response_type: "code",
          code_challenge: VALID_CHALLENGE,
          code_challenge_method: "S256",
          scope: "",
          decision: "allow",
          passphrase: TEST_PASSPHRASE
        }).toString(),
        redirect: "manual"
      });

      expect(postRes.status).toBe(302);
      const issuedCode = new URL(postRes.headers.get("location")!).searchParams.get("code")!;
      expect(issuedCode.length).toBeGreaterThan(20);

      const combinedLogs = capturedLogs.join("\n");
      expect(combinedLogs).not.toContain(TEST_PASSPHRASE);
      expect(combinedLogs).not.toContain(issuedCode);

      const auditDump = JSON.stringify(listAuditEvents(db));
      expect(auditDump).not.toContain(TEST_PASSPHRASE);
      expect(auditDump).not.toContain(issuedCode);

      const codeRows = JSON.stringify(db.prepare("SELECT * FROM auth_codes").all());
      expect(codeRows).not.toContain(issuedCode);
      expect(codeRows).not.toContain(TEST_PASSPHRASE);
    } finally {
      console.log = origLog;
      console.warn = origWarn;
      console.error = origError;
      console.info = origInfo;
    }
  });
});
