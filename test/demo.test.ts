import fs from "node:fs";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";
import { DEFAULT_MAX_NOTES, MAX_SEARCH_RESULTS, NO_MATCH_TEXT, NotesStore } from "../src/demo/notes.js";
import { startDemo, type DemoHandle } from "../src/demo/server.js";

const handlesToClose: DemoHandle[] = [];
const clientsToClose: Client[] = [];

async function startTestDemo(store?: NotesStore): Promise<DemoHandle> {
  const handle = await startDemo({ host: "127.0.0.1", port: 0, store });
  handlesToClose.push(handle);
  return handle;
}

async function connectClient(url: string): Promise<Client> {
  const client = new Client({
    name: "demo-test-client",
    version: "0.1.0"
  });
  const transport = new StreamableHTTPClientTransport(new URL(url));
  await client.connect(transport);
  clientsToClose.push(client);
  return client;
}

function getFirstTextContent(result: unknown): string {
  if (typeof result !== "object" || result === null || !("content" in result)) {
    throw new Error("Expected content array in tool result");
  }
  const { content } = result as { content?: unknown };
  if (!Array.isArray(content)) {
    throw new Error("Expected content array in tool result");
  }
  const first = content[0] as { type?: unknown; text?: unknown } | undefined;
  if (first?.type !== "text" || typeof first.text !== "string") {
    throw new Error("Expected text content in tool result");
  }
  return first.text;
}

afterEach(async () => {
  while (clientsToClose.length > 0) {
    const client = clientsToClose.pop();
    if (client) {
      await client.close().catch(() => undefined);
    }
  }
  while (handlesToClose.length > 0) {
    const handle = handlesToClose.pop();
    if (handle) {
      await handle.close();
    }
  }
});

describe("demo MCP server", () => {
  it("lists exactly notes.search and notes.append_note with expected annotations", async () => {
    const handle = await startTestDemo();
    const client = await connectClient(handle.url);

    const { tools } = await client.listTools();
    const names = tools.map((tool) => tool.name);

    expect(names).toEqual(["notes.search", "notes.append_note"]);

    const searchTool = tools.find((tool) => tool.name === "notes.search");
    const appendTool = tools.find((tool) => tool.name === "notes.append_note");

    expect(searchTool?.annotations?.readOnlyHint).toBe(true);
    expect(appendTool?.annotations?.readOnlyHint).toBe(false);
    expect(appendTool?.annotations?.destructiveHint).toBe(false);
  });

  it("searches seeded notes case-insensitively and returns No notes match. when none match", async () => {
    const handle = await startTestDemo();
    const client = await connectClient(handle.url);

    const matchResult = await client.callTool({
      name: "notes.search",
      arguments: { query: "passport" }
    });
    expect(matchResult.isError).not.toBe(true);
    expect(getFirstTextContent(matchResult)).toBe("2: Renew the passport in March");

    const upperMatchResult = await client.callTool({
      name: "notes.search",
      arguments: { query: "PLANTS" }
    });
    expect(upperMatchResult.isError).not.toBe(true);
    expect(getFirstTextContent(upperMatchResult)).toBe("1: Water the plants on Sunday");

    const noMatchResult = await client.callTool({
      name: "notes.search",
      arguments: { query: "nonexistent-term" }
    });
    expect(noMatchResult.isError).not.toBe(true);
    expect(getFirstTextContent(noMatchResult)).toBe(NO_MATCH_TEXT);
  });

  it("appends a note and returns it in subsequent searches", async () => {
    const handle = await startTestDemo();
    const client = await connectClient(handle.url);

    const appendResult = await client.callTool({
      name: "notes.append_note",
      arguments: { text: "buy milk" }
    });
    expect(appendResult.isError).not.toBe(true);
    expect(getFirstTextContent(appendResult)).toBe("Added note 4.");

    const searchResult = await client.callTool({
      name: "notes.search",
      arguments: { query: "milk" }
    });
    expect(searchResult.isError).not.toBe(true);
    expect(getFirstTextContent(searchResult)).toBe("4: buy milk");
  });

  it("rejects empty or overlong arguments for notes.search and notes.append_note without changing the store", async () => {
    const handle = await startTestDemo();
    const client = await connectClient(handle.url);
    const beforeNotes = handle.store.listAll();

    const emptySearch = await client.callTool({
      name: "notes.search",
      arguments: { query: "" }
    });
    expect(emptySearch.isError).toBe(true);
    expect(getFirstTextContent(emptySearch)).toContain("Invalid arguments");

    const longSearch = await client.callTool({
      name: "notes.search",
      arguments: { query: "a".repeat(201) }
    });
    expect(longSearch.isError).toBe(true);
    expect(getFirstTextContent(longSearch)).toContain("Invalid arguments");

    const emptyAppend = await client.callTool({
      name: "notes.append_note",
      arguments: { text: "" }
    });
    expect(emptyAppend.isError).toBe(true);
    expect(getFirstTextContent(emptyAppend)).toContain("Invalid arguments");

    const longAppend = await client.callTool({
      name: "notes.append_note",
      arguments: { text: "b".repeat(1001) }
    });
    expect(longAppend.isError).toBe(true);
    expect(getFirstTextContent(longAppend)).toContain("Invalid arguments");

    expect(handle.store.listAll()).toEqual(beforeNotes);
  });

  it("rejects unknown extra keys on tool arguments without modifying the store", async () => {
    const handle = await startTestDemo();
    const client = await connectClient(handle.url);
    const beforeNotes = handle.store.listAll();

    const extraAppend = await client.callTool({
      name: "notes.append_note",
      arguments: { text: "x", admin: true }
    });
    expect(extraAppend.isError).toBe(true);
    expect(getFirstTextContent(extraAppend)).toContain("Invalid arguments");

    const extraSearch = await client.callTool({
      name: "notes.search",
      arguments: { query: "passport", admin: true }
    });
    expect(extraSearch.isError).toBe(true);
    expect(getFirstTextContent(extraSearch)).toContain("Invalid arguments");

    expect(handle.store.listAll()).toEqual(beforeNotes);
  });

  it("caps search results at 20 and drops the oldest non-seed note past 1000 notes", async () => {
    const store = new NotesStore();
    for (let i = 0; i < DEFAULT_MAX_NOTES; i += 1) {
      store.append(`bulk note item ${i}`);
    }

    expect(store.size()).toBe(DEFAULT_MAX_NOTES);
    const allNotes = store.listAll();
    expect(allNotes[0]).toEqual({ id: 1, text: "Water the plants on Sunday" });
    expect(allNotes[1]).toEqual({ id: 2, text: "Renew the passport in March" });
    expect(allNotes[2]).toEqual({ id: 3, text: "Router admin page is on the second shelf" });
    // First 3 added notes (items 0, 1, 2) were evicted to keep total at 1000.
    expect(allNotes[3]).toEqual({ id: 7, text: "bulk note item 3" });
    expect(allNotes[allNotes.length - 1]).toEqual({
      id: DEFAULT_MAX_NOTES + 3,
      text: `bulk note item ${DEFAULT_MAX_NOTES - 1}`
    });

    const handle = await startTestDemo(store);
    const client = await connectClient(handle.url);
    const searchResult = await client.callTool({
      name: "notes.search",
      arguments: { query: "bulk note item" }
    });
    expect(searchResult.isError).not.toBe(true);
    const lines = getFirstTextContent(searchResult).split("\n");
    expect(lines).toHaveLength(MAX_SEARCH_RESULTS);
  });

  it("returns 405 with Allow: POST for GET /mcp and DELETE /mcp and 404 for unknown routes", async () => {
    const handle = await startTestDemo();
    const baseUrl = `http://${handle.address.address}:${handle.address.port}`;

    for (const method of ["GET", "DELETE"]) {
      const res = await fetch(`${baseUrl}/mcp`, { method });
      expect(res.status).toBe(405);
      expect(res.headers.get("allow")).toBe("POST");
    }

    const notFoundGet = await fetch(`${baseUrl}/anything`);
    expect(notFoundGet.status).toBe(404);

    const notFoundPost = await fetch(`${baseUrl}/anything`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    expect(notFoundPost.status).toBe(404);
  });

  it("returns 413 when a 70 KB JSON body is posted to /mcp", async () => {
    const handle = await startTestDemo();
    const oversizeBody = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { padding: "x".repeat(70 * 1024) }
    });

    const res = await fetch(handle.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream"
      },
      body: oversizeBody
    });
    const text = await res.text();

    expect(res.status).toBe(413);
    expect(JSON.parse(text)).toEqual({ error: "payload_too_large" });
    expect(text).not.toContain("at ");
  });
});

describe("CLI demo subcommand", () => {
  it("starts without reading gateway.toml, serves MCP initialize and exits 0 on abort", async () => {
    let stdout = "";
    let stderr = "";
    const controller = new AbortController();
    let initialized = false;
    let clientError: Error | undefined;

    const code = await runCli(["demo"], {
      configPath: "/nonexistent/path/gateway.toml",
      env: { DEMO_HOST: "127.0.0.1", DEMO_PORT: "0" },
      signal: controller.signal,
      stdout: {
        write: (chunk: string) => {
          stdout += chunk;
          return true;
        }
      },
      stderr: {
        write: (chunk: string) => {
          stderr += chunk;
          return true;
        }
      },
      onDemoListening: (handle) => {
        void (async () => {
          const client = new Client({ name: "cli-demo-test", version: "0.1.0" });
          try {
            const transport = new StreamableHTTPClientTransport(new URL(handle.url));
            await client.connect(transport);
            const { tools } = await client.listTools();
            initialized = tools.length === 2;
          } catch (err: unknown) {
            clientError = err instanceof Error ? err : new Error(String(err));
          } finally {
            await client.close().catch(() => undefined);
            controller.abort();
          }
        })();
      }
    });

    if (clientError !== undefined) {
      throw clientError;
    }
    expect(code).toBe(0);
    expect(initialized).toBe(true);
    expect(stderr).toBe("");
    expect(stdout).toContain("demo | listening on http://127.0.0.1:");
    expect(stdout).toContain("/mcp");
  });

  it("exits 1 when DEMO_PORT is invalid", async () => {
    let stdout = "";
    let stderr = "";

    const code = await runCli(["demo"], {
      env: { DEMO_HOST: "127.0.0.1", DEMO_PORT: "not-a-port" },
      stdout: {
        write: (chunk: string) => {
          stdout += chunk;
          return true;
        }
      },
      stderr: {
        write: (chunk: string) => {
          stderr += chunk;
          return true;
        }
      }
    });

    expect(code).toBe(1);
    expect(stdout).toBe("");
    expect(stderr).toContain("DEMO_PORT");
  });
});

describe("demo source boundaries", () => {
  it("contains no child_process, file-system access, outbound network calls or gateway config imports", () => {
    const demoDir = path.resolve("src/demo");
    const files = fs.readdirSync(demoDir).filter((name) => name.endsWith(".ts"));
    expect(files.sort()).toEqual(["notes.ts", "server.ts"]);

    for (const fileName of files) {
      const source = fs.readFileSync(path.join(demoDir, fileName), "utf8");
      expect(source).not.toMatch(/child_process/);
      expect(source).not.toMatch(/node:fs|from\s+["']fs["']|writeFile|appendFile|createWriteStream/);
      expect(source).not.toMatch(/\bfetch\s*\(|https?\.request\s*\(|https?\.get\s*\(/);
      expect(source).not.toMatch(/gateway\.toml|\.\.\/config\/|\.\.\/public\/|\.\.\/approve\//);
    }
  });
});
