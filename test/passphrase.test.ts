import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { COMMON_PASSWORDS } from "../src/data/common-passwords.js";
import {
  COMMON_PASSPHRASE_MESSAGE,
  TOO_SHORT_MESSAGE,
  hashPassphrase,
  validatePassphrase,
  verifyPassphrase
} from "../src/passphrase.js";

describe("passphrase validation and hashing", () => {
  const capturedLogs: string[] = [];
  const typedPassphrases = [
    "14chars-phrase",
    " leading-emoji-\u{1F680}-ok",
    "correct horse battery staple"
  ];

  beforeEach(() => {
    capturedLogs.length = 0;
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      capturedLogs.push(args.map(String).join(" "));
    });
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      capturedLogs.push(args.map(String).join(" "));
    });
    vi.spyOn(console, "warn").mockImplementation((...args: unknown[]) => {
      capturedLogs.push(args.map(String).join(" "));
    });
  });

  afterEach(() => {
    for (const secret of typedPassphrases) {
      for (const line of capturedLogs) {
        expect(line).not.toContain(secret);
      }
    }
    vi.restoreAllMocks();
  });

  it("bundles at least 10,000 common passwords", () => {
    expect(COMMON_PASSWORDS.size).toBeGreaterThanOrEqual(10000);
  });

  it("rejects a 14-character passphrase and accepts 15 code points with leading space, internal spaces and emoji", async () => {
    expect(validatePassphrase("14chars-phrase")).toBe(TOO_SHORT_MESSAGE);

    // 15 Unicode code points: leading space + "a b \u{1F680} c d e f1" (15 code points)
    const fifteenCodePoints = " a b \u{1F680} c d e f1";
    expect(Array.from(fifteenCodePoints)).toHaveLength(15);
    expect(validatePassphrase(fifteenCodePoints)).toBeNull();

    const digest = await hashPassphrase(fifteenCodePoints);
    expect(await verifyPassphrase(digest, fifteenCodePoints)).toBe(true);
    expect(await verifyPassphrase(digest, fifteenCodePoints.trimStart())).toBe(false);
  });

  it("rejects entries from the common password list in exact and upper-case form when length rule is bypassed", () => {
    expect(COMMON_PASSWORDS.has("password")).toBe(true);
    expect(validatePassphrase("password", { skipLengthCheck: true })).toBe(
      COMMON_PASSPHRASE_MESSAGE
    );
    expect(validatePassphrase("PASSWORD", { skipLengthCheck: true })).toBe(
      COMMON_PASSPHRASE_MESSAGE
    );
  });

  it("hashes with Argon2id and verifies exact match vs altered case or trailing space", async () => {
    const phrase = "correct horse battery staple";
    const hashed = await hashPassphrase(phrase);
    expect(hashed.startsWith("$argon2id$")).toBe(true);
    expect(hashed).toContain("m=19456,t=2,p=1");

    expect(await verifyPassphrase(hashed, phrase)).toBe(true);
    expect(
      await verifyPassphrase(hashed, "Correct Horse Battery Staple")
    ).toBe(false);
    expect(
      await verifyPassphrase(hashed, "correct horse battery staple ")
    ).toBe(false);
  });
});
