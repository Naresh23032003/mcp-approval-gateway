import crypto from "node:crypto";
import type Database from "better-sqlite3";
import { Router, type Request, type Response } from "express";
import { z } from "zod";
import type { Config } from "../config/schema.js";
import { verifyPassphrase as defaultVerifyPassphrase } from "../passphrase.js";
import { notFoundHandler, setCsp } from "../server/headers.js";
import { recordEvent } from "../store/audit.js";
import {
  AUTH_CODE_TTL_SECONDS,
  generateAuthCode,
  hashAuthCode,
  insertAuthCode
} from "../store/auth-codes.js";
import {
  CONSENT_LISTENER,
  LOCKOUT_MAX_FAILURES,
  getLockoutStatus,
  recordAuthFailure
} from "../store/auth-failures.js";
import { getClientById, type StoredClient } from "../store/clients.js";
import { insertGrant } from "../store/grants.js";
import {
  buildConsentCsp,
  buildStaticPageCsp,
  formatRelativeTime,
  renderConsentPage,
  renderInvalidPage,
  renderLockedPage,
  type InvalidAuthorizeReason
} from "../ui/consent-page.js";
import {
  buildAuthorizationCodeRedirect,
  buildAuthorizationErrorRedirect,
  displayHostForUri,
  redirectOriginForCsp
} from "./redirect.js";

export const CONSENT_CSRF_COOKIE = "__Host-consent_csrf";
export const MAX_PASSPHRASE_CODE_POINTS = 1024;
const MAX_PARAM_LENGTH = 2048;

const NonEmptyParamSchema = z.string().min(1).max(MAX_PARAM_LENGTH);
const OptionalParamSchema = z.string().max(MAX_PARAM_LENGTH).optional();
const ResponseTypeSchema = z.literal("code");
const PkceSchema = z.object({
  code_challenge_method: z.literal("S256"),
  code_challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/)
});

const ValidatedAuthorizeParamsSchema = z.object({
  client_id: z.string().min(1).max(256),
  redirect_uri: NonEmptyParamSchema,
  response_type: ResponseTypeSchema,
  code_challenge_method: z.literal("S256"),
  code_challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  scope: OptionalParamSchema,
  state: OptionalParamSchema,
  resource: OptionalParamSchema
});

export interface AuthorizeConfig {
  readonly public_base_url: string;
  readonly tools: Config["tools"];
  readonly owner_passphrase_hash?: string;
}

export interface AuthorizeRouterOptions {
  readonly config: AuthorizeConfig;
  readonly db: Database.Database;
  readonly verifyPassphrase?: (storedHash: string, passphrase: string) => Promise<boolean>;
  readonly now?: () => number;
}

interface ValidatedAuthorizeRequest {
  readonly client: StoredClient;
  readonly redirectUri: string;
  readonly responseType: "code";
  readonly codeChallenge: string;
  readonly codeChallengeMethod: "S256";
  readonly scope: string;
  readonly state?: string;
  readonly rawResource?: string;
  readonly canonicalResource: string;
}

type ValidationOutcome =
  | { readonly ok: true; readonly data: ValidatedAuthorizeRequest }
  | { readonly ok: false; readonly reason: InvalidAuthorizeReason };

function generateCsrfToken(): string {
  return crypto.randomBytes(32).toString("base64url");
}

function setCsrfCookie(res: Response, token: string): void {
  res.setHeader(
    "Set-Cookie",
    `${CONSENT_CSRF_COOKIE}=${token}; Path=/; Secure; HttpOnly; SameSite=Strict`
  );
}

function clearCsrfCookie(res: Response): void {
  res.setHeader(
    "Set-Cookie",
    `${CONSENT_CSRF_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`
  );
}

function getCookieValue(cookieHeader: string | undefined, name: string): string | undefined {
  if (typeof cookieHeader !== "string" || cookieHeader.length === 0) {
    return undefined;
  }
  let found: string | undefined;
  for (const segment of cookieHeader.split(";")) {
    const eqIndex = segment.indexOf("=");
    if (eqIndex === -1) {
      continue;
    }
    const key = segment.slice(0, eqIndex).trim();
    if (key !== name) {
      continue;
    }
    if (found !== undefined) {
      return undefined;
    }
    found = segment.slice(eqIndex + 1).trim();
  }
  return found;
}

function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length === 0 || bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function isAllowedPostOrigin(req: Request, expectedOrigin: string): boolean {
  const origin = req.headers.origin;
  if (typeof origin === "string" && origin.length > 0) {
    return origin === expectedOrigin;
  }
  const fetchSite = req.headers["sec-fetch-site"];
  return typeof fetchSite === "string" && fetchSite === "same-origin";
}

function sendHtml(res: Response, status: number, csp: string, htmlBody: string): void {
  setCsp(res, csp);
  res.status(status);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(htmlBody);
}

function sendInvalid(res: Response, status: 400 | 403, reason: InvalidAuthorizeReason): void {
  sendHtml(res, status, buildStaticPageCsp(), renderInvalidPage(reason));
}

function sendLocked(res: Response, retryAfterSeconds: number): void {
  res.setHeader("Retry-After", String(Math.max(1, Math.ceil(retryAfterSeconds))));
  sendHtml(res, 429, buildStaticPageCsp(), renderLockedPage());
}

function validateAuthorizeParams(
  raw: Record<string, unknown>,
  db: Database.Database,
  publicBaseUrl: string
): ValidationOutcome {
  const canonicalResource = `${publicBaseUrl}/mcp`;

  const clientIdParse = z.string().min(1).max(256).safeParse(raw.client_id);
  if (!clientIdParse.success) {
    return { ok: false, reason: "unknown client" };
  }
  const client = getClientById(db, clientIdParse.data);
  if (client === undefined) {
    return { ok: false, reason: "unknown client" };
  }

  const redirectParse = NonEmptyParamSchema.safeParse(raw.redirect_uri);
  if (!redirectParse.success || !client.redirectUris.includes(redirectParse.data)) {
    return { ok: false, reason: "redirect address not registered" };
  }

  const responseTypeParse = ResponseTypeSchema.safeParse(raw.response_type);
  if (!responseTypeParse.success) {
    return { ok: false, reason: "request type not supported" };
  }

  const pkceParse = PkceSchema.safeParse({
    code_challenge_method: raw.code_challenge_method,
    code_challenge: raw.code_challenge
  });
  if (!pkceParse.success) {
    return { ok: false, reason: "PKCE S256 missing" };
  }

  const resourceParse = OptionalParamSchema.safeParse(raw.resource);
  if (!resourceParse.success) {
    return { ok: false, reason: "resource not recognised" };
  }
  if (resourceParse.data !== undefined && resourceParse.data !== canonicalResource) {
    return { ok: false, reason: "resource not recognised" };
  }

  const scopeParse = OptionalParamSchema.safeParse(raw.scope);
  const stateParse = OptionalParamSchema.safeParse(raw.state);
  if (!scopeParse.success || !stateParse.success) {
    return { ok: false, reason: "request not accepted" };
  }

  const fullParse = ValidatedAuthorizeParamsSchema.safeParse({
    client_id: clientIdParse.data,
    redirect_uri: redirectParse.data,
    response_type: responseTypeParse.data,
    code_challenge_method: pkceParse.data.code_challenge_method,
    code_challenge: pkceParse.data.code_challenge,
    scope: scopeParse.data,
    state: stateParse.data,
    resource: resourceParse.data
  });
  if (!fullParse.success) {
    return { ok: false, reason: "request not accepted" };
  }

  return {
    ok: true,
    data: {
      client,
      redirectUri: fullParse.data.redirect_uri,
      responseType: fullParse.data.response_type,
      codeChallenge: fullParse.data.code_challenge,
      codeChallengeMethod: fullParse.data.code_challenge_method,
      scope: fullParse.data.scope ?? "",
      state: fullParse.data.state,
      rawResource: fullParse.data.resource,
      canonicalResource
    }
  };
}

interface ReadScopePlan {
  readonly readTools: readonly string[];
  readonly optionalGroups: readonly {
    readonly group: string;
    readonly tools: readonly string[];
  }[];
}

function buildReadScopePlan(tools: Config["tools"], requestedScope: string): ReadScopePlan {
  const readTools: string[] = [];
  const groupTools = new Map<string, string[]>();

  for (const tool of tools) {
    if (tool.class !== "read") {
      continue;
    }
    const group = tool.group ?? "read";
    if (group === "read") {
      readTools.push(tool.name);
    } else {
      const existing = groupTools.get(group);
      if (existing !== undefined) {
        existing.push(tool.name);
      } else {
        groupTools.set(group, [tool.name]);
      }
    }
  }

  const requestedTokens = new Set(
    requestedScope
      .trim()
      .split(/\s+/)
      .filter((token) => token.length > 0)
  );

  const optionalGroups: Array<{ readonly group: string; readonly tools: readonly string[] }> = [];
  for (const [group, toolNames] of groupTools.entries()) {
    if (requestedTokens.has(group)) {
      optionalGroups.push({ group, tools: toolNames });
    }
  }

  return { readTools, optionalGroups };
}

function parseSubmittedScopes(raw: unknown): Set<string> {
  if (typeof raw === "string") {
    return new Set([raw]);
  }
  if (Array.isArray(raw)) {
    const out = new Set<string>();
    for (const item of raw) {
      if (typeof item === "string") {
        out.add(item);
      }
    }
    return out;
  }
  return new Set();
}

function formatTriesLeftMessage(remainingTries: number): string {
  const count = Math.max(1, remainingTries);
  const noun = count === 1 ? "try" : "tries";
  return `Wrong passphrase. ${count} ${noun} left before a 15 minute lock.`;
}

export function createAuthorizeRouter(options: AuthorizeRouterOptions): Router {
  const router = Router();
  const verifyPassphraseFn = options.verifyPassphrase ?? defaultVerifyPassphrase;
  const nowFn = options.now ?? (() => Math.floor(Date.now() / 1000));
  const publicBaseUrl = options.config.public_base_url;
  const expectedOrigin = new URL(publicBaseUrl).origin;
  const gatewayHost = displayHostForUri(publicBaseUrl);
  const passphraseHash = options.config.owner_passphrase_hash ?? "";

  function renderConsentResponse(
    res: Response,
    status: 200 | 401,
    validated: ValidatedAuthorizeRequest,
    checkedOptionalGroups: ReadonlySet<string>,
    nowSeconds: number,
    errorMessage?: string
  ): void {
    const plan = buildReadScopePlan(options.config.tools, validated.scope);
    const csrfToken = generateCsrfToken();
    setCsrfCookie(res, csrfToken);

    const filteredScope = ["read", ...plan.optionalGroups.map((entry) => entry.group)].join(" ");

    const htmlBody = renderConsentPage({
      clientName: validated.client.clientName,
      gatewayHost,
      redirectHost: displayHostForUri(validated.redirectUri),
      registeredAgo: formatRelativeTime(validated.client.createdAt, nowSeconds),
      readTools: plan.readTools,
      optionalGroups: plan.optionalGroups.map((entry) => ({
        group: entry.group,
        tools: entry.tools,
        checked: checkedOptionalGroups.has(entry.group)
      })),
      csrfToken,
      hidden: {
        clientId: validated.client.clientId,
        redirectUri: validated.redirectUri,
        responseType: validated.responseType,
        codeChallenge: validated.codeChallenge,
        codeChallengeMethod: validated.codeChallengeMethod,
        scope: filteredScope,
        state: validated.state,
        resource: validated.rawResource
      },
      errorMessage
    });

    const redirectOrigin = redirectOriginForCsp(validated.redirectUri);
    sendHtml(res, status, buildConsentCsp(redirectOrigin), htmlBody);
  }

  function handleGet(req: Request, res: Response): void {
    const queryObj =
      req.query !== null && typeof req.query === "object"
        ? (req.query as Record<string, unknown>)
        : {};
    const validation = validateAuthorizeParams(queryObj, options.db, publicBaseUrl);
    if (!validation.ok) {
      sendInvalid(res, 400, validation.reason);
      return;
    }

    renderConsentResponse(res, 200, validation.data, new Set<string>(), nowFn());
  }

  async function handlePost(req: Request, res: Response): Promise<void> {
    const rawBody =
      req.body !== null && typeof req.body === "object"
        ? (req.body as Record<string, unknown>)
        : {};

    const cookieToken = getCookieValue(req.headers.cookie, CONSENT_CSRF_COOKIE);
    const formToken = typeof rawBody.csrf_token === "string" ? rawBody.csrf_token : undefined;

    if (
      !isAllowedPostOrigin(req, expectedOrigin) ||
      cookieToken === undefined ||
      formToken === undefined ||
      !constantTimeEquals(cookieToken, formToken)
    ) {
      sendInvalid(res, 403, "request not accepted");
      return;
    }

    const validation = validateAuthorizeParams(rawBody, options.db, publicBaseUrl);
    if (!validation.ok) {
      sendInvalid(res, 400, validation.reason);
      return;
    }

    const validated = validation.data;
    const decision = typeof rawBody.decision === "string" ? rawBody.decision : "";

    if (decision === "cancel") {
      const location = buildAuthorizationErrorRedirect(
        validated.redirectUri,
        "access_denied",
        validated.state
      );
      clearCsrfCookie(res);
      res.status(302);
      res.setHeader("Location", location);
      res.end();
      return;
    }

    if (decision !== "allow") {
      sendInvalid(res, 400, "request not accepted");
      return;
    }

    const nowSeconds = nowFn();
    const source = req.ip ?? "unknown";
    const lockBefore = getLockoutStatus(options.db, CONSENT_LISTENER, source, nowSeconds);
    if (lockBefore.locked) {
      sendLocked(res, lockBefore.retryAfterSeconds);
      return;
    }

    const submittedScopes = parseSubmittedScopes(rawBody.granted_scopes);
    const plan = buildReadScopePlan(options.config.tools, validated.scope);
    const allowedOptionalSet = new Set(plan.optionalGroups.map((entry) => entry.group));
    const keptCheckedScopes = new Set<string>();
    for (const candidate of submittedScopes) {
      if (allowedOptionalSet.has(candidate)) {
        keptCheckedScopes.add(candidate);
      }
    }

    const passphrase = typeof rawBody.passphrase === "string" ? rawBody.passphrase : "";
    let passphraseValid = false;

    if (passphrase.length > 0 && Array.from(passphrase).length <= MAX_PASSPHRASE_CODE_POINTS) {
      passphraseValid = await verifyPassphraseFn(passphraseHash, passphrase);
    }

    if (!passphraseValid) {
      recordAuthFailure(options.db, CONSENT_LISTENER, source, nowSeconds);
      recordEvent(options.db, {
        event: "auth_failed",
        clientId: validated.client.clientId
      });

      const lockAfter = getLockoutStatus(options.db, CONSENT_LISTENER, source, nowSeconds);
      if (lockAfter.locked) {
        sendLocked(res, lockAfter.retryAfterSeconds);
        return;
      }

      const remainingTries = LOCKOUT_MAX_FAILURES - lockAfter.recentFailures;
      renderConsentResponse(
        res,
        401,
        validated,
        keptCheckedScopes,
        nowSeconds,
        formatTriesLeftMessage(remainingTries)
      );
      return;
    }

    const grantedScopes: string[] = ["read"];
    for (const entry of plan.optionalGroups) {
      if (keptCheckedScopes.has(entry.group)) {
        grantedScopes.push(entry.group);
      }
    }

    const authCode = generateAuthCode();
    const codeHash = hashAuthCode(authCode);

    const writeGrantAndCode = options.db.transaction(() => {
      const grant = insertGrant(options.db, {
        clientId: validated.client.clientId,
        scopes: grantedScopes,
        resource: validated.canonicalResource,
        createdAt: nowSeconds
      });
      insertAuthCode(options.db, {
        codeHash,
        grantId: grant.grantId,
        redirectUri: validated.redirectUri,
        codeChallenge: validated.codeChallenge,
        expiresAt: nowSeconds + AUTH_CODE_TTL_SECONDS
      });
      recordEvent(options.db, {
        event: "consent_granted",
        clientId: validated.client.clientId
      });
    });
    writeGrantAndCode();

    const location = buildAuthorizationCodeRedirect(
      validated.redirectUri,
      authCode,
      validated.state
    );
    clearCsrfCookie(res);
    res.status(302);
    res.setHeader("Location", location);
    res.end();
  }

  router.all("/authorize", (req, res, next) => {
    if (req.method === "GET") {
      handleGet(req, res);
      return;
    }
    if (req.method === "POST") {
      void handlePost(req, res).catch(next);
      return;
    }
    notFoundHandler(req, res);
  });

  return router;
}
