import express, { type Express, type Router } from "express";
import { createApproveRouter } from "../approve/index.js";
import {
  errorHandler,
  notFoundHandler,
  requireBodyContentType,
  securityHeaders
} from "./headers.js";

export interface ApproveAppDeps {
  router?: Router;
}

export function createApproveApp(deps: ApproveAppDeps = {}): Express {
  const app = express();
  app.disable("x-powered-by");
  // Whether Tailscale Serve passes the original client address is unverified.
  app.set("trust proxy", false);

  app.use(securityHeaders);
  app.use(requireBodyContentType);

  app.use(deps.router ?? createApproveRouter());
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
