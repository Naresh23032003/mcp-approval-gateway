#!/usr/bin/env node
import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { parse } from "smol-toml";
import { loadConfig } from "./config/load.js";
import {
  DEFAULT_DEMO_HOST,
  DEFAULT_DEMO_PORT,
  startDemo,
  type DemoHandle
} from "./demo/server.js";
import {
  CURRENT_MISMATCH_MESSAGE,
  MISMATCH_MESSAGE,
  hashPassphrase,
  validatePassphrase,
  verifyPassphrase
} from "./passphrase.js";
import { startListeners, type ListenersHandle } from "./server/listen.js";

export interface CliIo {
  stdin?: NodeJS.ReadableStream & { isTTY?: boolean; setRawMode?: (mode: boolean) => void };
  stdout?: { write: (chunk: string) => unknown };
  stderr?: { write: (chunk: string) => unknown };
  configPath?: string;
  env?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  onListening?: (handle: ListenersHandle) => void;
  onDemoListening?: (handle: DemoHandle) => void;
}

function readExistingPassphraseHash(configPath: string): string | null {
  if (!fs.existsSync(configPath)) {
    return null;
  }
  try {
    const raw = fs.readFileSync(configPath, "utf8");
    const parsed = parse(raw) as Record<string, unknown>;
    if (
      typeof parsed.owner_passphrase_hash === "string" &&
      parsed.owner_passphrase_hash.length > 0
    ) {
      return parsed.owner_passphrase_hash;
    }
  } catch {
    // Ignore parse error here; treat as no hash configured
  }
  return null;
}

async function createPromptReader(
  stdin: NodeJS.ReadableStream & { isTTY?: boolean; setRawMode?: (mode: boolean) => void },
  stderr: { write: (chunk: string) => unknown }
): Promise<(promptText: string) => Promise<string>> {
  if (stdin.isTTY && typeof stdin.setRawMode === "function") {
    return (promptText: string) =>
      new Promise<string>((resolve) => {
        stderr.write(`${promptText} `);
        stdin.setRawMode?.(true);
        stdin.resume();
        let buffer = "";

        const onData = (chunk: Buffer | string): void => {
          const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
          for (const ch of text) {
            if (ch === "\r" || ch === "\n") {
              stdin.removeListener("data", onData);
              stdin.setRawMode?.(false);
              stdin.pause();
              stderr.write("\n");
              resolve(buffer);
              return;
            }
            if (ch === "\u0003") {
              stdin.removeListener("data", onData);
              stdin.setRawMode?.(false);
              stdin.pause();
              stderr.write("\n");
              resolve("");
              return;
            }
            if (ch === "\u007f" || ch === "\b") {
              const chars = Array.from(buffer);
              chars.pop();
              buffer = chars.join("");
              continue;
            }
            buffer += ch;
          }
        };

        stdin.on("data", onData);
      });
  }

  const chunks: Buffer[] = [];
  for await (const chunk of stdin) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk, "utf8") : Buffer.from(chunk));
  }
  const fullInput = Buffer.concat(chunks).toString("utf8");
  const lines = fullInput.split(/\r?\n/);
  let index = 0;

  return (promptText: string): Promise<string> => {
    stderr.write(`${promptText} \n`);
    const line = lines[index] ?? "";
    index += 1;
    return Promise.resolve(line);
  };
}

export async function runServe(configPath: string, io?: CliIo): Promise<number> {
  const stdout = io?.stdout ?? process.stdout;
  const stderr = io?.stderr ?? process.stderr;

  const result = loadConfig(configPath);
  if (!result.ok) {
    for (const problem of result.problems) {
      stderr.write(`gateway | ${problem}\n`);
    }
    const count = result.problems.length;
    const noun = count === 1 ? "problem" : "problems";
    stderr.write(`gateway | ${count} ${noun}. Nothing started.\n`);
    return 1;
  }

  let listeners: ListenersHandle;
  try {
    listeners = await startListeners(result.config);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    stderr.write(`gateway | ${message}\n`);
    return 1;
  }

  const publicEndpoint = `${listeners.publicAddress.address}:${listeners.publicAddress.port}`;
  const approveEndpoint = `${listeners.approveAddress.address}:${listeners.approveAddress.port}`;
  const publicPad = " ".repeat(Math.max(2, 24 - publicEndpoint.length));
  const approvePad = " ".repeat(Math.max(2, 24 - approveEndpoint.length));
  stdout.write(`gateway | public listener   ${publicEndpoint}${publicPad}oauth and mcp routes only\n`);
  stdout.write(
    `gateway | approve listener  ${approveEndpoint}${approvePad}private, tailnet only through the sidecar\n`
  );

  return await new Promise<number>((resolve) => {
    let shuttingDown = false;

    const shutdown = (): void => {
      if (shuttingDown) {
        return;
      }
      shuttingDown = true;
      process.removeListener("SIGTERM", onSignal);
      process.removeListener("SIGINT", onSignal);
      io?.signal?.removeEventListener("abort", shutdown);
      listeners
        .close()
        .then(() => resolve(0))
        .catch((closeErr: unknown) => {
          const msg = closeErr instanceof Error ? closeErr.message : String(closeErr);
          stderr.write(`gateway | shutdown error: ${msg}\n`);
          resolve(1);
        });
    };

    const onSignal = (): void => {
      shutdown();
    };

    process.on("SIGTERM", onSignal);
    process.on("SIGINT", onSignal);
    if (io?.signal) {
      if (io.signal.aborted) {
        shutdown();
        return;
      }
      io.signal.addEventListener("abort", shutdown, { once: true });
    }
    io?.onListening?.(listeners);
  });
}

export async function runHashPassphrase(configPath: string, io?: CliIo): Promise<number> {
  const stdin = io?.stdin ?? process.stdin;
  const stdout = io?.stdout ?? process.stdout;
  const stderr = io?.stderr ?? process.stderr;

  const prompt = await createPromptReader(stdin, stderr);
  const existingHash = readExistingPassphraseHash(configPath);

  if (existingHash !== null) {
    const currentPw = await prompt("Current passphrase (not shown):");
    const matched = await verifyPassphrase(existingHash, currentPw);
    if (!matched) {
      stderr.write(`${CURRENT_MISMATCH_MESSAGE}\n`);
      return 1;
    }
  }

  const firstEntry = await prompt("Owner passphrase (not shown):");
  const secondEntry = await prompt("Repeat it:");

  if (secondEntry !== "" && firstEntry !== secondEntry) {
    stderr.write(`${MISMATCH_MESSAGE}\n`);
    return 1;
  }

  const validationError = validatePassphrase(firstEntry);
  if (validationError !== null) {
    stderr.write(`${validationError}\n`);
    return 1;
  }

  if (firstEntry !== secondEntry) {
    stderr.write(`${MISMATCH_MESSAGE}\n`);
    return 1;
  }

  const hashed = await hashPassphrase(firstEntry);
  stdout.write("Paste this line into gateway.toml. The passphrase itself is not stored.\n");
  stdout.write(`owner_passphrase_hash = "${hashed}"\n`);
  return 0;
}

function parseDemoPort(rawPort: string | undefined): number | null {
  if (rawPort === undefined || rawPort.trim() === "") {
    return DEFAULT_DEMO_PORT;
  }
  const trimmed = rawPort.trim();
  if (!/^\d+$/.test(trimmed)) {
    return null;
  }
  const parsed = Number.parseInt(trimmed, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 65535) {
    return null;
  }
  return parsed;
}

export async function runDemo(io?: CliIo): Promise<number> {
  const stdout = io?.stdout ?? process.stdout;
  const stderr = io?.stderr ?? process.stderr;
  const env = io?.env ?? process.env;

  const rawHost = env.DEMO_HOST;
  const host =
    rawHost !== undefined && rawHost.trim().length > 0 ? rawHost.trim() : DEFAULT_DEMO_HOST;
  const port = parseDemoPort(env.DEMO_PORT);
  if (port === null) {
    stderr.write("demo | DEMO_PORT must be an integer between 0 and 65535.\n");
    return 1;
  }

  let handle: DemoHandle;
  try {
    handle = await startDemo({ host, port });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    stderr.write(`demo | ${message}\n`);
    return 1;
  }

  stdout.write(`demo | listening on ${handle.url} (in-memory, no auth, do not publish)\n`);

  return await new Promise<number>((resolve) => {
    let shuttingDown = false;

    const shutdown = (): void => {
      if (shuttingDown) {
        return;
      }
      shuttingDown = true;
      process.removeListener("SIGTERM", onSignal);
      process.removeListener("SIGINT", onSignal);
      io?.signal?.removeEventListener("abort", shutdown);
      handle
        .close()
        .then(() => resolve(0))
        .catch((closeErr: unknown) => {
          const msg = closeErr instanceof Error ? closeErr.message : String(closeErr);
          stderr.write(`demo | shutdown error: ${msg}\n`);
          resolve(1);
        });
    };

    const onSignal = (): void => {
      shutdown();
    };

    process.on("SIGTERM", onSignal);
    process.on("SIGINT", onSignal);
    if (io?.signal) {
      if (io.signal.aborted) {
        shutdown();
        return;
      }
      io.signal.addEventListener("abort", shutdown, { once: true });
    }
    io?.onDemoListening?.(handle);
  });
}

export async function runCli(args: string[], io?: CliIo): Promise<number> {
  const stderr = io?.stderr ?? process.stderr;
  const configPath = io?.configPath ?? process.env.GATEWAY_CONFIG ?? "/config/gateway.toml";
  const command = args[0] ?? "serve";

  if (command === "serve") {
    return runServe(configPath, io);
  }
  if (command === "hash-passphrase") {
    return runHashPassphrase(configPath, io);
  }
  if (command === "demo") {
    return runDemo(io);
  }

  stderr.write(
    `gateway | unknown command "${command}". Use "serve", "hash-passphrase" or "demo".\n`
  );
  return 1;
}

const isMain =
  process.argv[1] !== undefined &&
  (import.meta.url === pathToFileURL(process.argv[1]).href ||
    process.argv[1].endsWith("cli.js") ||
    process.argv[1].endsWith("cli.ts"));

if (isMain) {
  runCli(process.argv.slice(2))
    .then((code) => {
      process.exit(code);
    })
    .catch((err: unknown) => {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`gateway | fatal error: ${message}\n`);
      process.exit(1);
    });
}
