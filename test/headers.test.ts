import http from "node:http";
import type { AddressInfo } from "node:net";
import { Router } from "express";
import { afterEach, describe, expect, it } from "vitest";
import { createApproveApp } from "../src/server/approve-app.js";
import { DEFAULT_CSP, setCsp } from "../src/server/headers.js";
import { LISTEN_HOST } from "../src/server/listen.js";
import { createPublicApp } from "../src/server/public-app.js";

const servers: http.Server[] = [];

async function listenApp(app: http.RequestListener): Promise<string> {
  const server = http.createServer(app);
  servers.push(server);
  const addr = await new Promise<AddressInfo>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, LISTEN_HOST, () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("Missing TCP address"));
        return;
      }
      resolve(address);
    });
  });
  return `http://${addr.address}:${addr.port}`;
}

function expectSecurityHeaders(res: Response, expectedCsp: string = DEFAULT_CSP): void {
  expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  expect(res.headers.get("strict-transport-security")).toBe("max-age=31536000");
  expect(res.headers.get("referrer-policy")).toBe("no-referrer");
  expect(res.headers.get("cache-control")).toBe("no-store");
  expect(res.headers.get("content-security-policy")).toBe(expectedCsp);
  expect(res.headers.get("x-powered-by")).toBeNull();
  expect(res.headers.get("access-control-allow-origin")).toBeNull();
  for (const [name] of res.headers.entries()) {
    expect(name.toLowerCase().startsWith("access-control-")).toBe(false);
  }
}

afterEach(async () => {
  while (servers.length > 0) {
    const server = servers.pop();
    if (server && server.listening) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }
  }
});

describe("security headers on both apps", () => {
  it("sets all required security headers and omits X-Powered-By and CORS on 200, 404 and 501 responses", async () => {
    const publicRouter = Router();
    publicRouter.get("/ok", (_req, res) => {
      res.status(200);
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.send(JSON.stringify({ ok: true }));
    });
    publicRouter.get("/custom-csp", (_req, res) => {
      setCsp(res, "default-src 'none'; style-src 'self' 'unsafe-inline'");
      res.status(200).type("text/plain; charset=utf-8").send("ok");
    });

    const publicBase = await listenApp(createPublicApp({ router: publicRouter }));
    const approveBase = await listenApp(createApproveApp());

    const res200 = await fetch(`${publicBase}/ok`);
    expect(res200.status).toBe(200);
    expectSecurityHeaders(res200);

    const resCustomCsp = await fetch(`${publicBase}/custom-csp`);
    expect(resCustomCsp.status).toBe(200);
    expectSecurityHeaders(resCustomCsp, "default-src 'none'; style-src 'self' 'unsafe-inline'");

    const resPublic404 = await fetch(`${publicBase}/missing`);
    expect(resPublic404.status).toBe(404);
    expectSecurityHeaders(resPublic404);

    const resApprove501 = await fetch(`${approveBase}/approvals`);
    expect(resApprove501.status).toBe(501);
    expectSecurityHeaders(resApprove501);

    const resApprove404 = await fetch(`${approveBase}/missing`);
    expect(resApprove404.status).toBe(404);
    expectSecurityHeaders(resApprove404);
  });

  it("never leaks internal error message or stack trace in 500 responses", async () => {
    const publicRouter = Router();
    publicRouter.get("/boom", () => {
      throw new Error("secret internal database detail");
    });

    const publicBase = await listenApp(createPublicApp({ router: publicRouter }));
    const res = await fetch(`${publicBase}/boom`);
    const body = await res.text();

    expect(res.status).toBe(500);
    expect(res.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expectSecurityHeaders(res);
    expect(JSON.parse(body)).toEqual({ error: "internal_server_error" });
    expect(body).not.toContain("secret internal database detail");
    expect(body).not.toContain("at ");
  });
});

describe("request Content-Type, body size and JSON validation", () => {
  it("returns 415 for POST, PUT, PATCH and DELETE requests with a body and unsupported Content-Type", async () => {
    const publicBase = await listenApp(createPublicApp());
    const approveBase = await listenApp(createApproveApp());

    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      const res = await fetch(`${publicBase}/token`, {
        method,
        headers: { "Content-Type": "text/plain" },
        body: "plain text body"
      });
      expect(res.status).toBe(415);
      expect(res.headers.get("content-type")).toBe("application/json; charset=utf-8");
      expectSecurityHeaders(res);
      expect(await res.json()).toEqual({ error: "unsupported_media_type" });
    }

    const approveRes = await fetch(`${approveBase}/approvals`, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: "plain text body"
    });
    expect(approveRes.status).toBe(415);
    expectSecurityHeaders(approveRes);
    expect(await approveRes.json()).toEqual({ error: "unsupported_media_type" });
  });

  it("accepts application/json and application/x-www-form-urlencoded with charset parameters", async () => {
    const publicRouter = Router();
    publicRouter.post("/echo", (req, res) => {
      res.status(200);
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.send(JSON.stringify({ body: req.body as unknown }));
    });
    const publicBase = await listenApp(createPublicApp({ router: publicRouter }));

    const jsonRes = await fetch(`${publicBase}/echo`, {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify({ hello: "world" })
    });
    expect(jsonRes.status).toBe(200);
    expectSecurityHeaders(jsonRes);
    expect(await jsonRes.json()).toEqual({ body: { hello: "world" } });

    const formRes = await fetch(`${publicBase}/echo`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
      body: "grant_type=authorization_code&code=abc"
    });
    expect(formRes.status).toBe(200);
    expectSecurityHeaders(formRes);
    expect(await formRes.json()).toEqual({
      body: { grant_type: "authorization_code", code: "abc" }
    });
  });

  it("returns 413 with no stack trace when a public JSON or form body exceeds 64 KB", async () => {
    const publicBase = await listenApp(createPublicApp());
    const oversizeJson = JSON.stringify({ data: "x".repeat(70 * 1024) });

    const jsonRes = await fetch(`${publicBase}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: oversizeJson
    });
    const jsonBody = await jsonRes.text();

    expect(jsonRes.status).toBe(413);
    expect(jsonRes.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expectSecurityHeaders(jsonRes);
    expect(JSON.parse(jsonBody)).toEqual({ error: "payload_too_large" });
    expect(jsonBody).not.toContain("at ");
    expect(jsonBody).not.toContain("PayloadTooLargeError");

    const oversizeForm = `payload=${"a".repeat(70 * 1024)}`;
    const formRes = await fetch(`${publicBase}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: oversizeForm
    });
    const formBody = await formRes.text();

    expect(formRes.status).toBe(413);
    expect(formRes.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expectSecurityHeaders(formRes);
    expect(JSON.parse(formBody)).toEqual({ error: "payload_too_large" });
  });

  it("returns 400 without parser error text when malformed JSON is posted", async () => {
    const publicBase = await listenApp(createPublicApp());

    const res = await fetch(`${publicBase}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: '{"client_name": '
    });
    const body = await res.text();

    expect(res.status).toBe(400);
    expect(res.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expectSecurityHeaders(res);
    expect(JSON.parse(body)).toEqual({ error: "invalid_request" });
    expect(body).not.toContain("Unexpected");
    expect(body).not.toContain("SyntaxError");
    expect(body).not.toContain("JSON");
    expect(body).not.toContain("at ");
  });
});
