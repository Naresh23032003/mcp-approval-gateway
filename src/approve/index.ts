import { Router } from "express";

export function createApproveRouter(): Router {
  const router = Router();

  router.get("/approvals", (_req, res) => {
    res.status(501);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.send("Not implemented.");
  });

  router.get("/admin", (_req, res) => {
    res.status(501);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.send("Not implemented.");
  });

  return router;
}
