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
import {
  CONSENT_LISTENER,
  FAILURE_RETENTION_SECONDS,
  getLockoutStatus,
  recordAuthFailure
} from "../src/store/auth-failures.js";
import { insertClient } from "../src/store/clients.js";
import { openDb } from "../src/store/db.js";

// Test fixture value only. Not a real secret.
const TEST_PASSPHRASE = "test-lockout-passphrase-correct-horse";
const PUBLIC_BASE_URL = "https://gw.example.ts.net";
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

function extractCsrf(htmlText: string): string {
  const match = /name="csrf_token"\s+value="([^"]+)"/.exec(htmlText);
  if (!match || match[1] === undefined) {
    throw new Error("Missing csrf_token");
  }
  return match[1];
}

function extractCookie(res: Response): string {
  const header = res.headers.get("set-cookie");
  if (!header) {
    throw new Error("Missing Set-Cookie");
  }
  return header.split(";")[0] ?? "";
}

describe("Consent passphrase lockout (S3, V6.1.1, V6.3.1)", () => {
  it("locks after 5 wrong passphrases, skips Argon2id on the 6th try, stays locked at 12 min and unlocks after 16 min", async () => {
    let fakeNow = 1700010000;
    const verifySpy = vi.fn(verifyPassphrase);

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpgw-lockout-"));
    tempDirs.push(dir);
    const db = openDb(dir);
    dbs.push(db);

    const config: Pick<Config, "public_base_url" | "tools" | "owner_passphrase_hash"> = {
      public_base_url: PUBLIC_BASE_URL,
      owner_passphrase_hash: testPassphraseHash,
      tools: [{ name: "notes.search", class: "read", group: "read" }]
    };

    const app = createPublicApp({
      oauthRouter: createOAuthRouter({
        config,
        db,
        verifyPassphrase: verifySpy,
        now: () => fakeNow
      })
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
    const baseUrl = `http://${addr.address}:${addr.port}`;

    const client = insertClient(db, {
      clientId: crypto.randomUUID(),
      clientName: "Lockout Test Client",
      redirectUris: ["https://claude.ai/api/mcp/auth_callback"],
      createdAt: fakeNow - 60
    });

    async function postAttempt(passphrase: string): Promise<Response> {
      const getRes = await fetch(
        `${baseUrl}/authorize?${new URLSearchParams({
          client_id: client.clientId,
          redirect_uri: "https://claude.ai/api/mcp/auth_callback",
          response_type: "code",
          code_challenge: VALID_CHALLENGE,
          code_challenge_method: "S256"
        }).toString()}`
      );
      const csrfToken = extractCsrf(await getRes.text());
      const cookie = extractCookie(getRes);

      return await fetch(`${baseUrl}/authorize`, {
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
          passphrase
        }).toString(),
        redirect: "manual"
      });
    }

    // Attempts 1..4 return 401 with decreasing remaining tries.
    for (let attempt = 1; attempt <= 4; attempt++) {
      fakeNow += 5;
      const res = await postAttempt(`wrong-passphrase-${attempt}`);
      const body = await res.text();
      expect(res.status, `attempt ${attempt}`).toBe(401);
      if (attempt === 3) {
        expect(body).toContain("2 tries left before a 15 minute lock");
      }
      if (attempt === 4) {
        expect(body).toContain("1 try left before a 15 minute lock");
      }
    }

    // 5th wrong passphrase triggers the 15-minute lock.
    fakeNow += 5;
    const fifthRes = await postAttempt("wrong-passphrase-5");
    const fifthBody = await fifthRes.text();
    expect(fifthRes.status).toBe(429);
    expect(fifthRes.headers.get("retry-after")).toBe("900");
    expect(fifthBody).not.toContain("<form");
    expect(fifthBody).toContain(
      "Too many wrong passphrases from this address. Try again in 15 minutes."
    );
    expect(verifySpy).toHaveBeenCalledTimes(5);

    // 6th attempt (even with the correct passphrase!) is blocked with 429 and no Argon2id call.
    fakeNow += 10;
    const sixthRes = await postAttempt(TEST_PASSPHRASE);
    const sixthBody = await sixthRes.text();
    expect(sixthRes.status).toBe(429);
    expect(sixthRes.headers.get("retry-after")).toBe("890");
    expect(sixthBody).not.toContain("<form");
    expect(verifySpy).toHaveBeenCalledTimes(5);

    const authFailedEvents = listAuditEvents(db).filter((e) => e.event === "auth_failed");
    expect(authFailedEvents).toHaveLength(5);
    expect(authFailedEvents.every((e) => e.client_id === client.clientId)).toBe(true);

    // Still locked 12 minutes after the 5th failure (past 10 min window, within 15 min lock).
    fakeNow += 12 * 60 - 10;
    const atTwelveMinRes = await postAttempt(TEST_PASSPHRASE);
    expect(atTwelveMinRes.status).toBe(429);
    expect(atTwelveMinRes.headers.get("retry-after")).toBe("180");
    expect(verifySpy).toHaveBeenCalledTimes(5);

    // 16 minutes after the 5th failure, the lock has expired and the correct passphrase succeeds.
    fakeNow += 4 * 60;
    const unlockedRes = await postAttempt(TEST_PASSPHRASE);
    expect(unlockedRes.status).toBe(302);
    expect(unlockedRes.headers.get("location")).toContain("code=");
    expect(verifySpy).toHaveBeenCalledTimes(6);
  });

  it("prunes auth_failures rows older than 24 hours on insert and does not lock across a >10 minute gap", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpgw-prune-"));
    tempDirs.push(dir);
    const db = openDb(dir);
    dbs.push(db);

    const baseTime = 1700100000;
    recordAuthFailure(db, CONSENT_LISTENER, "127.0.0.1", baseTime);
    recordAuthFailure(db, CONSENT_LISTENER, "127.0.0.1", baseTime + 10);
    recordAuthFailure(db, CONSENT_LISTENER, "127.0.0.1", baseTime + 20);
    recordAuthFailure(db, CONSENT_LISTENER, "127.0.0.1", baseTime + 30);

    // 11 minutes after the first failure, a 5th failure does not fall within 10 minutes of the first.
    recordAuthFailure(db, CONSENT_LISTENER, "127.0.0.1", baseTime + 660);
    const status = getLockoutStatus(db, CONSENT_LISTENER, "127.0.0.1", baseTime + 660);
    expect(status.locked).toBe(false);

    // Inserting a row more than 24 hours later deletes all rows older than 24 hours.
    const later = baseTime + FAILURE_RETENTION_SECONDS + 1000;
    recordAuthFailure(db, CONSENT_LISTENER, "127.0.0.1", later);
    const remaining = db.prepare("SELECT at FROM auth_failures").all() as Array<{ at: number }>;
    expect(remaining).toEqual([{ at: later }]);
  });
});
