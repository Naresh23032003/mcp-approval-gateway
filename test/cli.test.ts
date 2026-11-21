import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";
import { hashPassphrase } from "../src/passphrase.js";

const tempDirs: string[] = [];

async function getFreePort(): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") {
        server.close(() => reject(new Error("Missing port")));
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

function writeTempConfig(contents: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpgw-cli-"));
  tempDirs.push(dir);
  const filePath = path.join(dir, "gateway.toml");
  fs.writeFileSync(filePath, contents, "utf8");
  return filePath;
}

function createIo(stdinText: string, configPath: string) {
  let stdout = "";
  let stderr = "";
  const stdin = Readable.from([stdinText]) as NodeJS.ReadableStream & {
    isTTY?: boolean;
  };
  stdin.isTTY = false;

  return {
    io: {
      stdin,
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
      configPath
    },
    getStdout: () => stdout,
    getStderr: () => stderr
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe("CLI serve and hash-passphrase commands", () => {
  it("exits 1 on serve when owner_passphrase_hash is empty and prints 1 problem", async () => {
    const configPath = writeTempConfig(
      [
        'public_base_url = "https://gw.example.ts.net"',
        'upstream_url = "http://demo:9000/mcp"',
        'owner_passphrase_hash = ""',
        "",
        "[[tools]]",
        'name = "notes.search"',
        'class = "read"'
      ].join("\n")
    );

    const { io, getStdout, getStderr } = createIo("", configPath);
    const code = await runCli(["serve"], io);

    expect(code).toBe(1);
    expect(getStdout()).toBe("");
    expect(getStderr()).toContain(
      "gateway | gateway.toml: owner_passphrase_hash is empty. Run hash-passphrase and paste the result."
    );
    expect(getStderr()).toContain("gateway | 1 problem. Nothing started.");
  });

  it("starts both listeners and exits 0 on serve when config is valid and stopped", async () => {
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

    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpgw-cli-data-"));
    tempDirs.push(dataDir);
    const controller = new AbortController();
    const { io, getStdout, getStderr } = createIo("", configPath);
    const code = await runCli(["serve"], {
      ...io,
      env: { DATA_DIR: dataDir },
      signal: controller.signal,
      onListening: () => {
        controller.abort();
      }
    });

    expect(code).toBe(0);
    expect(getStderr()).toBe("");
    expect(getStdout()).toContain(`gateway | public listener   127.0.0.1:${publicPort}`);
    expect(getStdout()).toContain("oauth and mcp routes only");
    expect(getStdout()).toContain(`gateway | approve listener  127.0.0.1:${approvePort}`);
    expect(getStdout()).toContain("private, tailnet only through the sidecar");
  });

  it("hashes a valid passphrase on piped stdin without leaking the passphrase", async () => {
    const missingConfigPath = path.join(os.tmpdir(), "nonexistent-gateway.toml");
    const secret = "correct horse battery staple";
    const { io, getStdout, getStderr } = createIo(
      `${secret}\n${secret}\n`,
      missingConfigPath
    );

    const code = await runCli(["hash-passphrase"], io);
    expect(code).toBe(0);
    expect(getStdout()).toContain(
      "Paste this line into gateway.toml. The passphrase itself is not stored."
    );
    expect(getStdout()).toMatch(/owner_passphrase_hash = "\$argon2id\$v=19\$/);
    expect(getStdout()).not.toContain(secret);
    expect(getStderr()).not.toContain(secret);
  });

  it("exits 1 when two different passphrases are entered on piped stdin", async () => {
    const missingConfigPath = path.join(os.tmpdir(), "nonexistent-gateway.toml");
    const { io, getStdout, getStderr } = createIo(
      "first valid passphrase entry\nsecond valid passphrase entry\n",
      missingConfigPath
    );

    const code = await runCli(["hash-passphrase"], io);
    expect(code).toBe(1);
    expect(getStdout()).toBe("");
    expect(getStderr()).toContain(
      "The two entries differ. Nothing was written. Run the command again."
    );
  });

  it("requires current passphrase when config already holds a non-empty hash and exits 1 on wrong current passphrase", async () => {
    const currentHash = await hashPassphrase("current horse battery staple");
    const configPath = writeTempConfig(
      [
        'public_base_url = "https://gw.example.ts.net"',
        'upstream_url = "http://demo:9000/mcp"',
        `owner_passphrase_hash = "${currentHash}"`,
        "",
        "[[tools]]",
        'name = "notes.search"',
        'class = "read"'
      ].join("\n")
    );

    const { io, getStdout, getStderr } = createIo(
      "wrong current passphrase\nnew valid passphrase here\nnew valid passphrase here\n",
      configPath
    );

    const code = await runCli(["hash-passphrase"], io);
    expect(code).toBe(1);
    expect(getStdout()).toBe("");
    expect(getStderr()).toContain(
      "The current passphrase did not match. Nothing was written."
    );
    expect(getStdout()).not.toContain("$argon2id$");
  });
});
