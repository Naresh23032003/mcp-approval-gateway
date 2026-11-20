import { Router } from "express";

export function createPublicRouter(): Router {
  const router = Router();
  // OAuth and MCP routes are mounted here by later tasks.
  return router;
}
