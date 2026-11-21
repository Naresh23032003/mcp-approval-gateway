import type Database from "better-sqlite3";
import express, { type Express, type Router } from "express";
import type { Config } from "../config/schema.js";
import { createOAuthRouter } from "../oauth/router.js";
import { createPublicRouter } from "../public/index.js";
import {
  PUBLIC_BODY_LIMIT,
  errorHandler,
  notFoundHandler,
  requireBodyContentType,
  securityHeaders
} from "./headers.js";

export interface PublicAppDeps {
  router?: Router;
  oauthRouter?: Router;
  config?: Pick<Config, "public_base_url" | "tools">;
  db?: Database.Database;
}

export function createPublicApp(deps: PublicAppDeps = {}): Express {
  const app = express();
  app.disable("x-powered-by");
  // Whether Tailscale Funnel passes the original client address is unverified.
  app.set("trust proxy", false);

  app.use(securityHeaders);
  app.use(requireBodyContentType);
  app.use(express.json({ limit: PUBLIC_BODY_LIMIT }));
  app.use(express.urlencoded({ extended: false, limit: PUBLIC_BODY_LIMIT }));

  if (deps.oauthRouter !== undefined) {
    app.use(deps.oauthRouter);
  } else if (deps.config !== undefined && deps.db !== undefined) {
    app.use(createOAuthRouter({ config: deps.config, db: deps.db }));
  }

  app.use(deps.router ?? createPublicRouter());
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
