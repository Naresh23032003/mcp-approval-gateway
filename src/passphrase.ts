import { Algorithm, hash, verify } from "@node-rs/argon2";
import { COMMON_PASSWORDS } from "./data/common-passwords.js";

export const TOO_SHORT_MESSAGE =
  "Use at least 15 characters. Four random words work well.";
export const TOO_LONG_MESSAGE = "Use at most 1024 characters.";
export const COMMON_PASSPHRASE_MESSAGE =
  "That passphrase is on a list of commonly used passwords. Choose another.";
export const MISMATCH_MESSAGE =
  "The two entries differ. Nothing was written. Run the command again.";
export const CURRENT_MISMATCH_MESSAGE =
  "The current passphrase did not match. Nothing was written.";

export interface ValidatePassphraseOptions {
  skipLengthCheck?: boolean;
}

export function isCommonPassphrase(pw: string): boolean {
  return COMMON_PASSWORDS.has(pw) || COMMON_PASSWORDS.has(pw.toLowerCase());
}

export function validatePassphrase(
  pw: string,
  options?: ValidatePassphraseOptions
): string | null {
  const codePointCount = Array.from(pw).length;

  if (!options?.skipLengthCheck) {
    if (codePointCount < 15) {
      return TOO_SHORT_MESSAGE;
    }
    if (codePointCount > 1024) {
      return TOO_LONG_MESSAGE;
    }
  }

  if (isCommonPassphrase(pw)) {
    return COMMON_PASSPHRASE_MESSAGE;
  }

  return null;
}

export async function hashPassphrase(pw: string): Promise<string> {
  return hash(pw, {
    algorithm: Algorithm.Argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1
  });
}

export async function verifyPassphrase(
  storedHash: string,
  pw: string
): Promise<boolean> {
  if (!storedHash || !storedHash.startsWith("$argon2id$")) {
    return false;
  }
  try {
    return await verify(storedHash, pw);
  } catch {
    return false;
  }
}
