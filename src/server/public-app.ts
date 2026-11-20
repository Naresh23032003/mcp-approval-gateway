import express, { type Express, type Router } from "express";
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

  app.use(deps.router ?? createPublicRouter());
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
