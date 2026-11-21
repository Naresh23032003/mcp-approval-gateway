import http from "node:http";
import type { AddressInfo } from "node:net";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express, { type Express, type NextFunction, type Request, type Response } from "express";
import { z } from "zod";
import {
  PUBLIC_BODY_LIMIT,
  errorHandler,
  notFoundHandler,
  securityHeaders
} from "../server/headers.js";
import { NotesStore } from "./notes.js";

export const DEFAULT_DEMO_HOST = "127.0.0.1";
export const DEFAULT_DEMO_PORT = 9000;

export interface DemoAppOptions {
  readonly store?: NotesStore;
}

export interface StartDemoOptions {
  readonly host?: string;
  readonly port?: number;
  readonly store?: NotesStore;
}

export interface DemoHandle {
  readonly server: http.Server;
  readonly address: AddressInfo;
  readonly url: string;
  readonly store: NotesStore;
  readonly close: () => Promise<void>;
}

const searchInputSchema = z
  .object({
    query: z.string().min(1).max(200)
  })
  .strict();

const appendNoteInputSchema = z
  .object({
    text: z.string().min(1).max(1000)
  })
  .strict();

function createDemoMcpServer(store: NotesStore): McpServer {
  const server = new McpServer({
    name: "mcp-approval-gateway-demo",
    version: "0.1.0"
  });

  server.registerTool(
    "notes.search",
    {
      description: "Search in-memory notes by case-insensitive substring.",
      inputSchema: searchInputSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    ({ query }) => ({
      content: [
        {
          type: "text",
          text: store.formatSearchResults(query)
        }
      ]
    })
  );

  server.registerTool(
    "notes.append_note",
    {
      description: "Append a new note to the in-memory notes store.",
      inputSchema: appendNoteInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false
      }
    },
    ({ text }) => {
      const note = store.append(text);
      return {
        content: [
          {
            type: "text",
            text: `Added note ${note.id}.`
          }
        ]
      };
    }
  );

  return server;
}

function methodNotAllowedHandler(_req: Request, res: Response): void {
  res.status(405);
  res.setHeader("Allow", "POST");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.send(
    JSON.stringify({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed."
      },
      id: null
    })
  );
}

export function createDemoApp(options: DemoAppOptions = {}): Express {
  const store = options.store ?? new NotesStore();
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", false);

  app.use(securityHeaders);
  app.use(express.json({ limit: PUBLIC_BODY_LIMIT }));

  app.post("/mcp", async (req: Request, res: Response, next: NextFunction) => {
    const server = createDemoMcpServer(store);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    });

    let closed = false;
    const cleanup = (): void => {
      if (closed) {
        return;
      }
      closed = true;
      void transport.close().catch(() => undefined);
      void server.close().catch(() => undefined);
    };

    res.once("close", cleanup);

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err: unknown) {
      cleanup();
      next(err);
    }
  });

  app.get("/mcp", methodNotAllowedHandler);
  app.delete("/mcp", methodNotAllowedHandler);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}

function formatHostForUrl(address: AddressInfo): string {
  if (address.family === "IPv6") {
    return `[${address.address}]`;
  }
  return address.address;
}

function closeServer(server: http.Server): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close((err) => {
      if (err) {
        reject(err);
        return;
      }
      resolve();
    });
    if (typeof server.closeIdleConnections === "function") {
      server.closeIdleConnections();
    }
  });
}

export async function startDemo(options: StartDemoOptions = {}): Promise<DemoHandle> {
  const host = options.host ?? DEFAULT_DEMO_HOST;
  const port = options.port ?? DEFAULT_DEMO_PORT;
  const store = options.store ?? new NotesStore();

  const app = createDemoApp({ store });
  const server = http.createServer(app);

  const address = await new Promise<AddressInfo>((resolve, reject) => {
    const onError = (err: NodeJS.ErrnoException): void => {
      server.removeListener("listening", onListening);
      if (err.code === "EADDRINUSE") {
        reject(
          new Error(`demo server cannot bind ${host}:${port}: port ${port} is already in use.`)
        );
        return;
      }
      reject(new Error(`demo server failed to bind ${host}:${port}: ${err.message}`));
    };

    const onListening = (): void => {
      server.removeListener("error", onError);
      const addr = server.address();
      if (addr === null || typeof addr === "string") {
        reject(new Error("demo server did not expose a TCP address."));
        return;
      }
      resolve(addr);
    };

    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, host);
  });

  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) {
      return;
    }
    closed = true;
    await closeServer(server);
  };

  return {
    server,
    address,
    url: `http://${formatHostForUrl(address)}:${address.port}/mcp`,
    store,
    close
  };
}
