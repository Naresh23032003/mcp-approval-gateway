import crypto from "node:crypto";
import type Database from "better-sqlite3";
import type { Response } from "express";
import { z } from "zod";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import {
  InvalidClientMetadataError,
  ServerError
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type {
  AuthorizationParams,
  OAuthServerProvider
} from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type {
  OAuthClientInformationFull,
  OAuthTokens
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { getClientById, insertClient } from "../store/clients.js";

export const DEFAULT_CLIENT_NAME = "Unnamed client";
export const MAX_CLIENT_NAME_LENGTH = 100;
export const MAX_REDIRECT_URIS = 5;
export const MAX_REDIRECT_URI_LENGTH = 2048;

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const BLOCKED_SCHEMES = new Set(["javascript:", "data:", "file:", "vbscript:"]);
const CUSTOM_SCHEME_PATTERN = /^[a-z][a-z0-9+.-]*$/;

const ALLOWED_GRANT_TYPES = ["authorization_code", "refresh_token"] as const;
const DEFAULT_GRANT_TYPES: ("authorization_code" | "refresh_token")[] = [
  "authorization_code",
  "refresh_token"
];
const DEFAULT_RESPONSE_TYPES: ["code"] = ["code"];

function hasAuthorityCredentials(raw: string, parsed: URL): boolean {
  if (parsed.username !== "" || parsed.password !== "") {
    return true;
  }
  const schemeEnd = raw.indexOf("://");
  if (schemeEnd === -1) {
    return false;
  }
  const afterScheme = raw.slice(schemeEnd + 3);
  const authorityEnd = afterScheme.search(/[/?#]/);
  const authority = authorityEnd === -1 ? afterScheme : afterScheme.slice(0, authorityEnd);
  return authority.includes("@");
}

export function isAllowedRedirectUri(raw: string): boolean {
  if (raw.length === 0 || raw.length > MAX_REDIRECT_URI_LENGTH) {
    return false;
  }
  if (raw.includes("#")) {
    return false;
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return false;
  }

  if (parsed.hash !== "") {
    return false;
  }
  if (hasAuthorityCredentials(raw, parsed)) {
    return false;
  }

  const protocol = parsed.protocol.toLowerCase();
  if (BLOCKED_SCHEMES.has(protocol)) {
    return false;
  }

  if (protocol === "https:") {
    return parsed.hostname.length > 0;
  }

  if (protocol === "http:") {
    return LOOPBACK_HOSTS.has(parsed.hostname);
  }

  const scheme = protocol.slice(0, -1);
  return CUSTOM_SCHEME_PATTERN.test(scheme) && /[.-]/.test(scheme);
}

export const DcrMetadataSchema = z
  .object({
    redirect_uris: z
      .array(
        z
          .string()
          .min(1, "redirect_uri must not be empty.")
          .max(
            MAX_REDIRECT_URI_LENGTH,
            `redirect_uri must be at most ${MAX_REDIRECT_URI_LENGTH} characters.`
          )
          .refine(isAllowedRedirectUri, {
            message:
              "redirect_uri must be an absolute https URL, loopback http URL or custom scheme with a dot or dash, with no fragment or credentials."
          })
      )
      .min(1, `redirect_uris must contain between 1 and ${MAX_REDIRECT_URIS} entries.`)
      .max(MAX_REDIRECT_URIS, `redirect_uris must contain between 1 and ${MAX_REDIRECT_URIS} entries.`),
    client_name: z
      .string()
      .max(MAX_CLIENT_NAME_LENGTH, `client_name must be at most ${MAX_CLIENT_NAME_LENGTH} characters.`)
      .optional(),
    token_endpoint_auth_method: z
      .literal("none", {
        message: 'token_endpoint_auth_method must be "none".'
      })
      .optional(),
    grant_types: z
      .array(
        z.enum(ALLOWED_GRANT_TYPES, {
          message: 'grant_types may only include "authorization_code" and "refresh_token".'
        })
      )
      .min(1, 'grant_types must include at least one of "authorization_code" or "refresh_token".')
      .optional(),
    response_types: z
      .array(
        z.literal("code", {
          message: 'response_types must be ["code"].'
        })
      )
      .length(1, 'response_types must be ["code"].')
      .optional()
  })
  .strip();

export class SqliteClientsStore implements OAuthRegisteredClientsStore {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    const stored = getClientById(this.db, clientId);
    if (stored === undefined) {
      return undefined;
    }
    return {
      client_id: stored.clientId,
      client_id_issued_at: stored.createdAt,
      client_name: stored.clientName,
      redirect_uris: [...stored.redirectUris],
      token_endpoint_auth_method: "none",
      grant_types: [...DEFAULT_GRANT_TYPES],
      response_types: [...DEFAULT_RESPONSE_TYPES]
    };
  }

  registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">
  ): OAuthClientInformationFull {
    const parsed = DcrMetadataSchema.safeParse(client);
    if (!parsed.success) {
      const reason = parsed.error.issues[0]?.message ?? "Invalid client metadata.";
      throw new InvalidClientMetadataError(reason);
    }

    const withGenerated = client as Partial<
      Pick<OAuthClientInformationFull, "client_id" | "client_id_issued_at">
    >;
    const clientId =
      typeof withGenerated.client_id === "string" && withGenerated.client_id.length > 0
        ? withGenerated.client_id
        : crypto.randomUUID();
    const issuedAt =
      typeof withGenerated.client_id_issued_at === "number" &&
      Number.isInteger(withGenerated.client_id_issued_at)
        ? withGenerated.client_id_issued_at
        : Math.floor(Date.now() / 1000);

    const clientName =
      parsed.data.client_name !== undefined && parsed.data.client_name.length > 0
        ? parsed.data.client_name
        : DEFAULT_CLIENT_NAME;
    const grantTypes =
      parsed.data.grant_types !== undefined
        ? Array.from(new Set(parsed.data.grant_types))
        : [...DEFAULT_GRANT_TYPES];
    const responseTypes: ["code"] = [...DEFAULT_RESPONSE_TYPES];

    insertClient(this.db, {
      clientId,
      clientName,
      redirectUris: parsed.data.redirect_uris,
      createdAt: issuedAt
    });

    return {
      client_id: clientId,
      client_id_issued_at: issuedAt,
      client_name: clientName,
      redirect_uris: [...parsed.data.redirect_uris],
      token_endpoint_auth_method: "none",
      grant_types: grantTypes,
      response_types: responseTypes
    };
  }
}

export class SqliteOAuthProvider implements OAuthServerProvider {
  private readonly store: SqliteClientsStore;

  constructor(db: Database.Database) {
    this.store = new SqliteClientsStore(db);
  }

  get clientsStore(): SqliteClientsStore {
    return this.store;
  }

  authorize(
    _client: OAuthClientInformationFull,
    _params: AuthorizationParams,
    _res: Response
  ): Promise<void> {
    void _client;
    void _params;
    void _res;
    return Promise.reject(new ServerError("not implemented yet"));
  }

  challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    _authorizationCode: string
  ): Promise<string> {
    void _client;
    void _authorizationCode;
    return Promise.reject(new ServerError("not implemented yet"));
  }

  exchangeAuthorizationCode(
    _client: OAuthClientInformationFull,
    _authorizationCode: string,
    _codeVerifier?: string,
    _redirectUri?: string,
    _resource?: URL
  ): Promise<OAuthTokens> {
    void _client;
    void _authorizationCode;
    void _codeVerifier;
    void _redirectUri;
    void _resource;
    return Promise.reject(new ServerError("not implemented yet"));
  }

  exchangeRefreshToken(
    _client: OAuthClientInformationFull,
    _refreshToken: string,
    _scopes?: string[],
    _resource?: URL
  ): Promise<OAuthTokens> {
    void _client;
    void _refreshToken;
    void _scopes;
    void _resource;
    return Promise.reject(new ServerError("not implemented yet"));
  }

  verifyAccessToken(_token: string): Promise<AuthInfo> {
    void _token;
    return Promise.reject(new ServerError("not implemented yet"));
  }
}
