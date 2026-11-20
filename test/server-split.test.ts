import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { ESLint } from "eslint";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";
import { hashPassphrase } from "../src/passphrase.js";
import { LISTEN_HOST, startListeners, type ListenersHandle } from "../src/server/listen.js";
import { routes, routesFor } from "../src/server/routes.js";

const handlesToClose: ListenersHandle[] = [];
const rawServersToClose: net.Server[] = [];
const tempDirs: string[] = [];

function writeTempConfig(contents: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpgw-split-"));
  tempDirs.push(dir);
  const filePath = path.join(dir, "gateway.toml");
  fs.writeFileSync(filePath, contents, "utf8");
  return filePath;
}

async function getFreePort(): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, LISTEN_HOST, () => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") {
        server.close(() => reject(new Error("Could not read ephemeral port")));
        return;
      }
      const { port } = addr;
      server.close((err) => {
        if (err) reject(err);
        else resolve(port);
      });
    });
  });
}

async function startTestListeners(): Promise<ListenersHandle> {
  const handle = await startListeners({
    listen: { public_port: 0, approve_port: 0 }
  });
  handlesToClose.push(handle);
  return handle;
}

afterEach(async () => {
  while (handlesToClose.length > 0) {
    const handle = handlesToClose.pop();
    if (handle) {
      await handle.close();
    }
  }
  while (rawServersToClose.length > 0) {
    const server = rawServersToClose.pop();
    if (server && server.listening) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }
  }
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe("route table invariants (V3.5.3)", () => {
  it("contains all expected public and approve routes with consistent flags", () => {
    const publicRoutes = routesFor("public");
    const approveRoutes = routesFor("approve");

    expect(publicRoutes.length + approveRoutes.length).toBe(routes.length);
    expect(publicRoutes.every((r) => r.listener === "public" && r.public === true)).toBe(true);
    expect(approveRoutes.every((r) => r.listener === "approve" && r.public === false)).toBe(true);

    const publicKeys = publicRoutes.map((r) => `${r.method} ${r.path}`);
    expect(publicKeys).toEqual([
      "GET /.well-known/oauth-protected-resource",
      "GET /.well-known/oauth-authorization-server",
      "POST /register",
      "GET /authorize",
      "POST /authorize",
      "POST /token",
      "POST /mcp"
    ]);

    const approveKeys = approveRoutes.map((r) => `${r.method} ${r.path}`);
    expect(approveKeys).toEqual(["GET /approvals", "GET /admin"]);
  });

  it("ensures no GET route is marked as state-changing", () => {
    for (const route of routes) {
      if (route.method === "GET") {
        expect(route.mutates).toBe(false);
        expect(route.path).not.toMatch(/\/(create|update|delete|approve|deny|revoke|mutate)/i);
      }
      if (route.mutates) {
        expect(route.method).toBe("POST");
      }
    }
  });
});

describe("listener split (S6)", () => {
  it("binds both listeners strictly to 127.0.0.1 and closes cleanly", async () => {
    const handle = await startTestListeners();

    expect(handle.publicAddress.address).toBe("127.0.0.1");
    expect(handle.approveAddress.address).toBe("127.0.0.1");
    expect(handle.publicAddress.port).not.toBe(handle.approveAddress.port);

    const pubRes = await fetch(`http://127.0.0.1:${handle.publicAddress.port}/anything`);
    expect(pubRes.status).toBe(404);

    const appRes = await fetch(`http://127.0.0.1:${handle.approveAddress.port}/approvals`);
    expect(appRes.status).toBe(501);

    await handle.close();
    expect(handle.publicServer.listening).toBe(false);
    expect(handle.approveServer.listening).toBe(false);

    await expect(
      fetch(`http://127.0.0.1:${handle.publicAddress.port}/anything`)
    ).rejects.toThrow();
    await expect(
      fetch(`http://127.0.0.1:${handle.approveAddress.port}/approvals`)
    ).rejects.toThrow();
  });

  it("returns plain 404 Not found. for /approvals, /admin, /login and /anything on the public app", async () => {
    const handle = await startTestListeners();
    const baseUrl = `http://127.0.0.1:${handle.publicAddress.port}`;

    for (const targetPath of ["/approvals", "/admin", "/login", "/anything"]) {
      const res = await fetch(`${baseUrl}${targetPath}`);
      expect(res.status).toBe(404);
      expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
      expect(await res.text()).toBe("Not found.");
    }
  });

  it("does not return 405 on unsupported methods for public routes", async () => {
    const handle = await startTestListeners();
    const baseUrl = `http://127.0.0.1:${handle.publicAddress.port}`;

    const res = await fetch(`${baseUrl}/token`, { method: "DELETE" });
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(await res.text()).toBe("Not found.");
  });

  it("returns 404 for every approve route requested on the public listener and vice versa", async () => {
    const handle = await startTestListeners();
    const publicBase = `http://127.0.0.1:${handle.publicAddress.port}`;
    const approveBase = `http://127.0.0.1:${handle.approveAddress.port}`;

    for (const route of routesFor("approve")) {
      const res = await fetch(`${publicBase}${route.path}`, { method: route.method });
      expect(res.status).toBe(404);
      expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
      expect(await res.text()).toBe("Not found.");
    }

    for (const route of routesFor("public")) {
      const res = await fetch(`${approveBase}${route.path}`, { method: route.method });
      expect(res.status).toBe(404);
      expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
      expect(await res.text()).toBe("Not found.");
    }
  });

  it("serves placeholder 501 responses on approve routes", async () => {
    const handle = await startTestListeners();
    const approveBase = `http://127.0.0.1:${handle.approveAddress.port}`;

    for (const targetPath of ["/approvals", "/admin"]) {
      const res = await fetch(`${approveBase}${targetPath}`);
      expect(res.status).toBe(501);
      expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
      expect(await res.text()).toBe("Not implemented.");
    }
  });

  it("exits 1 and names port 8080 when port 8080 is already in use", async () => {
    const blocker = net.createServer();
    rawServersToClose.push(blocker);

    const occupiedByBlocker = await new Promise<boolean>((resolve, reject) => {
      blocker.once("error", (err: NodeJS.ErrnoException) => {
        if (err.code === "EADDRINUSE") {
          resolve(false);
          return;
        }
        reject(err);
      });
      blocker.listen(8080, LISTEN_HOST, () => resolve(true));
    });
    expect(typeof occupiedByBlocker).toBe("boolean");

    const hashed = await hashPassphrase("correct horse battery staple");
    const approvePort = await getFreePort();
    const configPath = writeTempConfig(
      [
        'public_base_url = "https://gw.example.ts.net"',
        'upstream_url = "http://demo:9000/mcp"',
        `owner_passphrase_hash = "${hashed}"`,
        "",
        "[listen]",
        "public_port = 8080",
        `approve_port = ${approvePort}`,
        "",
        "[[tools]]",
        'name = "notes.search"',
        'class = "read"'
      ].join("\n")
    );

    let stdout = "";
    let stderr = "";
    const code = await runCli(["serve"], {
      configPath,
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
    expect(stderr).toContain("8080");
  });

  it("closes the public listener if the approve port is already in use", async () => {
    const publicPort = await getFreePort();
    const blocker = net.createServer();
    rawServersToClose.push(blocker);
    const approvePort = await new Promise<number>((resolve, reject) => {
      blocker.once("error", reject);
      blocker.listen(0, LISTEN_HOST, () => {
        const addr = blocker.address();
        if (addr === null || typeof addr === "string") {
          reject(new Error("Missing address"));
          return;
        }
        resolve(addr.port);
      });
    });

    await expect(
      startListeners({
        listen: { public_port: publicPort, approve_port: approvePort }
      })
    ).rejects.toThrow(String(approvePort));

    // Confirm publicPort is free again after cleanup.
    const probe = net.createServer();
    rawServersToClose.push(probe);
    await new Promise<void>((resolve, reject) => {
      probe.once("error", reject);
      probe.listen(publicPort, LISTEN_HOST, () => resolve());
    });
  });

  it("starts both listeners on serve, prints both endpoints and exits 0 on SIGTERM", async () => {
    const hashed = await hashPassphrase("correct horse battery staple");
    const publicPort = await getFreePort();
    const approvePort = await getFreePort();
    const configPath = writeTempConfig(
      [
        'public_base_url = "https://gw.example.ts.net"',
        'upstream_url = "http://demo:9000/mcp"',
        `owner_passphrase_hash = "${hashed}"`,
        "",
        "[listen]",
        `public_port = ${publicPort}`,
        `approve_port = ${approvePort}`,
        "",
        "[[tools]]",
        'name = "notes.search"',
        'class = "read"'
      ].join("\n")
    );

    let stdout = "";
    let stderr = "";
    let boundHandle: ListenersHandle | undefined;

    const codePromise = runCli(["serve"], {
      configPath,
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
      onListening: (handle) => {
        boundHandle = handle;
        process.emit("SIGTERM");
      }
    });

    const code = await codePromise;

    expect(code).toBe(0);
    expect(stderr).toBe("");
    expect(boundHandle?.publicAddress.address).toBe("127.0.0.1");
    expect(boundHandle?.approveAddress.address).toBe("127.0.0.1");
    expect(boundHandle?.publicServer.listening).toBe(false);
    expect(boundHandle?.approveServer.listening).toBe(false);
    expect(stdout).toContain(`gateway | public listener   127.0.0.1:${publicPort}`);
    expect(stdout).toContain("oauth and mcp routes only");
    expect(stdout).toContain(`gateway | approve listener  127.0.0.1:${approvePort}`);
    expect(stdout).toContain("private, tailnet only through the sidecar");
  });
});

describe("ESLint listener isolation rules", () => {
  it("rejects imports from src/approve in src/public, src/oauth and src/mcp, and the reverse", async () => {
    const eslint = new ESLint({
      overrideConfigFile: path.resolve("eslint.config.js")
    });

    const publicImportsApprove = await eslint.lintText(
      'import { createApproveRouter } from "../approve/index.js";\nexport const r = createApproveRouter;\n',
      { filePath: path.resolve("src/public/index.ts") }
    );
    expect(
      publicImportsApprove[0]?.messages.some((m) => m.ruleId === "no-restricted-imports")
    ).toBe(true);

    const approveImportsPublic = await eslint.lintText(
      'import { createPublicRouter } from "../public/index.js";\nexport const r = createPublicRouter;\n',
      { filePath: path.resolve("src/approve/index.ts") }
    );
    expect(
      approveImportsPublic[0]?.messages.some((m) => m.ruleId === "no-restricted-imports")
    ).toBe(true);

    // Confirm the child_process restriction still applies inside scoped directories.
    const publicChildProcess = await eslint.lintText(
      'import { exec } from "node:child_process";\nexport const x = exec;\n',
      { filePath: path.resolve("src/public/index.ts") }
    );
    expect(
      publicChildProcess[0]?.messages.some((m) =>
        m.message.includes("The gateway never runs OS commands")
      )
    ).toBe(true);

    // Confirm future public-side directories (src/oauth and src/mcp) inherit the same boundary rule.
    for (const futureFile of ["src/oauth/handler.ts", "src/mcp/proxy.ts"]) {
      const cfg = (await eslint.calculateConfigForFile(path.resolve(futureFile))) as {
        rules?: { "no-restricted-imports"?: unknown[] };
      };
      const ruleEntry = cfg.rules?.["no-restricted-imports"];
      expect(ruleEntry).toBeDefined();
      const serialized = JSON.stringify(ruleEntry);
      expect(serialized).toContain("approve");
      expect(serialized).toContain("node:child_process");
    }
  }, 15000);
});
