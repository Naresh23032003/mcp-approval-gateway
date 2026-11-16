import fs from "node:fs";
import { parse } from "smol-toml";
import { ConfigSchema, type Config } from "./schema.js";

export { ConfigSchema, type Config } from "./schema.js";

export type LoadConfigResult =
  | { ok: true; config: Config }
  | { ok: false; problems: string[] };

const KNOWN_KEYS_BY_SCOPE: Record<string, readonly string[]> = {
  "": [
    "public_base_url",
    "upstream_url",
    "owner_passphrase_hash",
    "listen",
    "queue",
    "notify",
    "tools"
  ],
  listen: ["public_port", "approve_port"],
  queue: ["ttl_minutes", "max_pending", "purge_days"],
  notify: ["ntfy_url"],
  tools: ["name", "class", "group"]
};

export function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    new Array<number>(n + 1).fill(0)
  );
  for (let i = 0; i <= m; i++) {
    dp[i]![0] = i;
  }
  for (let j = 0; j <= n; j++) {
    dp[0]![j] = j;
  }
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i]![j] = Math.min(
        dp[i - 1]![j]! + 1,
        dp[i]![j - 1]! + 1,
        dp[i - 1]![j - 1]! + cost
      );
    }
  }
  return dp[m]![n]!;
}

function findClosestKnownKey(unknownKey: string, scope: string): string | null {
  const scopeCandidates = KNOWN_KEYS_BY_SCOPE[scope] ?? [];
  const rootCandidates = KNOWN_KEYS_BY_SCOPE[""] ?? [];
  const candidates = Array.from(new Set([...scopeCandidates, ...rootCandidates]));
  let bestKey: string | null = null;
  let bestDistance = 3;
  for (const candidate of candidates) {
    const dist = levenshteinDistance(unknownKey, candidate);
    if (dist <= 2 && dist < bestDistance) {
      bestDistance = dist;
      bestKey = candidate;
    }
  }
  return bestKey;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function findKeyLineNumber(rawText: string, key: string): number | null {
  const lines = rawText.split(/\r?\n/);
  const keyPattern = new RegExp(`^\\s*${escapeRegExp(key)}\\s*=`);
  const tablePattern = new RegExp(`^\\s*\\[+\\s*${escapeRegExp(key)}\\s*\\]+`);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (keyPattern.test(line) || tablePattern.test(line)) {
      return i + 1;
    }
  }
  return null;
}

function getScopeName(path: PropertyKey[]): string {
  if (path.length === 0) return "";
  const first = String(path[0]);
  if (first === "listen" || first === "queue" || first === "notify" || first === "tools") {
    return first;
  }
  return "";
}

function getValueAtPath(obj: unknown, path: PropertyKey[]): unknown {
  let current: unknown = obj;
  for (const segment of path) {
    if (current === null || typeof current !== "object") {
      return undefined;
    }
    current = (current as Record<PropertyKey, unknown>)[segment];
  }
  return current;
}

function formatDotPath(path: PropertyKey[]): string {
  return path.filter((segment) => typeof segment !== "number").map(String).join(".");
}

function formatMissingMessage(dotPath: string): string {
  switch (dotPath) {
    case "public_base_url":
      return "gateway.toml: public_base_url is missing. Set it to the https address clients use.";
    case "upstream_url":
      return "gateway.toml: upstream_url is missing. Set it to the http or https URL of the upstream MCP server.";
    case "owner_passphrase_hash":
      return "gateway.toml: owner_passphrase_hash is empty. Run hash-passphrase and paste the result.";
    case "tools":
      return "gateway.toml: tools is missing. Configure at least one [[tools]] entry.";
    case "tools.name":
      return "gateway.toml: tools.name is missing. Set a tool name matching ^[a-z][a-z0-9_.-]{0,63}$.";
    case "tools.class":
      return 'gateway.toml: tools.class is missing. Set it to "read" or "write".';
    default:
      return `gateway.toml: ${dotPath || "config"} is missing.`;
  }
}

export function loadConfig(
  filePath: string = process.env.GATEWAY_CONFIG ?? "/config/gateway.toml"
): LoadConfigResult {
  let rawText: string;
  try {
    rawText = fs.readFileSync(filePath, "utf8");
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      problems: [`gateway.toml: cannot read "${filePath}": ${message}`]
    };
  }

  let parsed: unknown;
  try {
    parsed = parse(rawText);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      problems: [`gateway.toml: TOML syntax error: ${message}`]
    };
  }

  const result = ConfigSchema.safeParse(parsed);
  if (result.success) {
    return { ok: true, config: result.data };
  }

  const problems: string[] = [];
  const addProblem = (msg: string): void => {
    if (!problems.includes(msg)) {
      problems.push(msg);
    }
  };

  // Pre-scan unrecognized_keys to detect typos for missing required fields in the same scope
  const suggestedTargets = new Set<string>();
  for (const issue of result.error.issues) {
    if (issue.code === "unrecognized_keys") {
      const scope = getScopeName(issue.path);
      for (const uk of issue.keys) {
        const suggestion = findClosestKnownKey(uk, scope);
        if (suggestion !== null) {
          suggestedTargets.add(suggestion);
          if (scope) {
            suggestedTargets.add(`${scope}.${suggestion}`);
          }
        }
      }
    }
  }

  for (const issue of result.error.issues) {
    if (issue.code === "unrecognized_keys") {
      const scope = getScopeName(issue.path);
      for (const uk of issue.keys) {
        const suggestion = findClosestKnownKey(uk, scope);
        const line = findKeyLineNumber(rawText, uk);
        const linePart = line !== null ? ` line ${line}` : "";
        const didYouMean = suggestion !== null ? ` Did you mean "${suggestion}"?` : "";
        addProblem(`gateway.toml${linePart}: unknown key "${uk}".${didYouMean}`);
      }
      continue;
    }

    const dotPath = formatDotPath(issue.path);
    const actualValue = getValueAtPath(parsed, issue.path);

    if (issue.code === "invalid_type" && actualValue === undefined) {
      if (suggestedTargets.has(dotPath)) {
        continue;
      }
      addProblem(formatMissingMessage(dotPath));
      continue;
    }

    if (issue.message.startsWith("gateway.toml")) {
      addProblem(issue.message);
    } else if (dotPath && !issue.message.startsWith(dotPath)) {
      addProblem(`gateway.toml: ${dotPath}: ${issue.message}`);
    } else {
      addProblem(`gateway.toml: ${issue.message}`);
    }
  }

  // Ensure cross-field checks are always reported even when sibling fields had validation errors
  if (parsed !== null && typeof parsed === "object") {
    const rootObj = parsed as Record<string, unknown>;
    if (rootObj.listen !== null && typeof rootObj.listen === "object") {
      const listenObj = rootObj.listen as Record<string, unknown>;
      const pubPort = listenObj.public_port ?? 8080;
      const appPort = listenObj.approve_port ?? 8081;
      if (typeof pubPort === "number" && typeof appPort === "number" && pubPort === appPort) {
        addProblem("gateway.toml: listen.approve_port must differ from listen.public_port.");
      }
    }

    if (Array.isArray(rootObj.tools)) {
      const seenNames = new Set<string>();
      for (const rawTool of rootObj.tools) {
        if (rawTool !== null && typeof rawTool === "object") {
          const toolObj = rawTool as Record<string, unknown>;
          const name = typeof toolObj.name === "string" ? toolObj.name : undefined;
          const toolClass = toolObj.class;
          const group = toolObj.group;

          if (toolClass === "write" && group !== undefined) {
            addProblem(
              `gateway.toml: tools.group is not allowed on write tool "${name ?? ""}". Only read tools may set a group.`
            );
          }

          if (name !== undefined) {
            if (seenNames.has(name)) {
              addProblem(
                `gateway.toml: tools.name "${name}" is duplicated. Tool names must be unique.`
              );
            } else {
              seenNames.add(name);
            }
          }
        }
      }
    }
  }

  return { ok: false, problems };
}
