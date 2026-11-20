import type { NextFunction, Request, Response } from "express";

export const DEFAULT_CSP =
  "default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

export const PUBLIC_BODY_LIMIT = "64kb";

const BODY_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const ALLOWED_BODY_CONTENT_TYPES = new Set([
  "application/json",
  "application/x-www-form-urlencoded"
]);

export function setCsp(res: Response, value: string): void {
  res.setHeader("Content-Security-Policy", value);
}

export function sendJson(res: Response, status: number, payload: Record<string, unknown>): void {
  res.status(status);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.send(JSON.stringify(payload));
}

export function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader("Strict-Transport-Security", "max-age=31536000");
  res.setHeader("X-Content-Type-Options", "nosniff");
  setCsp(res, DEFAULT_CSP);
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
  next();
}

function hasRequestBody(req: Request): boolean {
  const transferEncoding = req.headers["transfer-encoding"];
  if (typeof transferEncoding === "string" && transferEncoding.trim().length > 0) {
    return true;
  }

  const contentLength = req.headers["content-length"];
  if (typeof contentLength === "string") {
    const parsed = Number.parseInt(contentLength.trim(), 10);
    if (Number.isFinite(parsed) && parsed > 0) {
      return true;
    }
  }

  return false;
}

function extractMediaType(contentTypeHeader: string | undefined): string | null {
  if (typeof contentTypeHeader !== "string") {
    return null;
  }
  const [rawType] = contentTypeHeader.split(";");
  if (rawType === undefined) {
    return null;
  }
  const normalized = rawType.trim().toLowerCase();
  return normalized.length > 0 ? normalized : null;
}

export function requireBodyContentType(req: Request, res: Response, next: NextFunction): void {
  if (!BODY_METHODS.has(req.method.toUpperCase())) {
    next();
    return;
  }

  if (!hasRequestBody(req)) {
    next();
    return;
  }

  const mediaType = extractMediaType(req.headers["content-type"]);
  if (mediaType === null || !ALLOWED_BODY_CONTENT_TYPES.has(mediaType)) {
    sendJson(res, 415, { error: "unsupported_media_type" });
    return;
  }

  next();
}

export function notFoundHandler(_req: Request, res: Response): void {
  res.status(404);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.send("Not found.");
}

interface HttpErrorLike {
  status?: unknown;
  statusCode?: unknown;
  type?: unknown;
}

export function errorHandler(
  err: unknown,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  void _next;
  if (res.headersSent) {
    return;
  }

  if (typeof err === "object" && err !== null) {
    const httpErr = err as HttpErrorLike;
    const status =
      typeof httpErr.status === "number"
        ? httpErr.status
        : typeof httpErr.statusCode === "number"
          ? httpErr.statusCode
          : undefined;
    const errType = typeof httpErr.type === "string" ? httpErr.type : undefined;

    if (errType === "entity.too.large" || status === 413) {
      sendJson(res, 413, { error: "payload_too_large" });
      return;
    }

    if (
      errType === "entity.parse.failed" ||
      (err instanceof SyntaxError && status === 400) ||
      status === 400
    ) {
      sendJson(res, 400, { error: "invalid_request" });
      return;
    }

    if (errType === "encoding.unsupported" || status === 415) {
      sendJson(res, 415, { error: "unsupported_media_type" });
      return;
    }
  }

  sendJson(res, 500, { error: "internal_server_error" });
}
