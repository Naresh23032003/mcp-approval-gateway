import type Database from "better-sqlite3";
import { Router, type RequestHandler } from "express";
import { metadataHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/metadata.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import type {
  OAuthMetadata,
  OAuthProtectedResourceMetadata
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { Config } from "../config/schema.js";
import { sendJson } from "../server/headers.js";
import { SqliteOAuthProvider } from "./provider.js";

export const RESOURCE_NAME = "mcp-approval-gateway";
export const REGISTER_RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;
export const REGISTER_RATE_LIMIT_MAX = 10;
export const TOKEN_RATE_LIMIT_WINDOW_MS = 60 * 1000;
export const TOKEN_RATE_LIMIT_MAX = 30;

export interface OAuthRouterOptions {
  readonly config: Pick<Config, "public_base_url" | "tools">;
  readonly db: Database.Database;
  readonly provider?: SqliteOAuthProvider;
}

export function buildScopesSupported(tools: Config["tools"]): string[] {
  const scopes = new Set<string>(["read"]);
  for (const tool of tools) {
    if (tool.class === "read") {
      scopes.add(tool.group ?? "read");
    } else {
      scopes.add(`write:${tool.name}`);
    }
  }
  return Array.from(scopes);
}

function exactPathHandler(handler: RequestHandler): RequestHandler {
  return (req, res, next) => {
    if (req.path !== "/") {
      next();
      return;
    }
    handler(req, res, next);
  };
}

export function createOAuthRouter(options: OAuthRouterOptions): Router {
  const provider = options.provider ?? new SqliteOAuthProvider(options.db);
  const publicBaseUrl = options.config.public_base_url;
  const scopesSupported = buildScopesSupported(options.config.tools);

  const oauthMetadata: OAuthMetadata = {
    issuer: publicBaseUrl,
    authorization_endpoint: `${publicBaseUrl}/authorize`,
    token_endpoint: `${publicBaseUrl}/token`,
    registration_endpoint: `${publicBaseUrl}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: scopesSupported
  };

  const protectedResourceMetadata: OAuthProtectedResourceMetadata = {
    resource: `${publicBaseUrl}/mcp`,
    authorization_servers: [publicBaseUrl],
    scopes_supported: scopesSupported,
    resource_name: RESOURCE_NAME
  };

  const router = Router();

  // Serve exact RFC 8414 and RFC 9728 metadata documents (both root and /mcp suffix)
  // before mcpAuthRouter so issuer has no trailing slash and auth methods stay public-only.
  router.use(
    "/.well-known/oauth-authorization-server",
    exactPathHandler(metadataHandler(oauthMetadata))
  );
  router.use(
    "/.well-known/oauth-protected-resource/mcp",
    exactPathHandler(metadataHandler(protectedResourceMetadata))
  );
  router.use(
    "/.well-known/oauth-protected-resource",
    exactPathHandler(metadataHandler(protectedResourceMetadata))
  );

  // Enforce JSON bodies on dynamic client registration (RFC 7591).
  router.post("/register", (req, res, next) => {
    const contentType = req.headers["content-type"];
    const mediaType =
      typeof contentType === "string"
        ? contentType.split(";")[0]?.trim().toLowerCase()
        : undefined;
    if (mediaType !== undefined && mediaType !== "" && mediaType !== "application/json") {
      sendJson(res, 415, { error: "unsupported_media_type" });
      return;
    }

    // The MCP SDK registration handler maps non-ServerError OAuthErrors to 400.
    // Rewrite temporarily_unavailable (e.g. client store cap reached) to 429.
    const originalJson = res.json.bind(res);
    res.json = ((body: unknown) => {
      if (
        res.statusCode === 400 &&
        typeof body === "object" &&
        body !== null &&
        "error" in body &&
        (body as { error?: unknown }).error === "temporarily_unavailable"
      ) {
        res.status(429);
      }
      return originalJson(body);
    }) as typeof res.json;

    next();
  });

  router.use(
    mcpAuthRouter({
      provider,
      issuerUrl: new URL(publicBaseUrl),
      baseUrl: new URL(publicBaseUrl),
      resourceServerUrl: new URL("/mcp", publicBaseUrl),
      resourceName: RESOURCE_NAME,
      scopesSupported,
      clientRegistrationOptions: {
        rateLimit: {
          windowMs: REGISTER_RATE_LIMIT_WINDOW_MS,
          max: REGISTER_RATE_LIMIT_MAX
        }
      },
      tokenOptions: {
        rateLimit: {
          windowMs: TOKEN_RATE_LIMIT_WINDOW_MS,
          max: TOKEN_RATE_LIMIT_MAX
        }
      }
    })
  );

  return router;
}
