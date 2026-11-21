import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ESLint } from "eslint";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config/load.js";

const tempDirs: string[] = [];

function writeTempConfig(contents: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpgw-cfg-"));
  tempDirs.push(dir);
  const filePath = path.join(dir, "gateway.toml");
  fs.writeFileSync(filePath, contents, "utf8");
  return filePath;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

const SAMPLE_HASH =
  "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZXRlc3Q$R29vZEhhc2hWYWx1ZVRlc3RPdXRwdXQ";

describe("repo configuration and static security rules", () => {
  it("enforces strict TypeScript with sourceMap disabled in tsconfig.json", () => {
    const raw = fs.readFileSync(path.resolve("tsconfig.json"), "utf8");
    const parsed = JSON.parse(raw) as {
      compilerOptions: { strict?: boolean; sourceMap?: boolean };
    };
    expect(parsed.compilerOptions.strict).toBe(true);
    expect(parsed.compilerOptions.sourceMap).toBe(false);
  });

  it("lists npm, docker and github-actions in .github/dependabot.yml", () => {
    const dependabot = fs.readFileSync(
      path.resolve(".github/dependabot.yml"),
      "utf8"
    );
    expect(dependabot).toContain('package-ecosystem: "npm"');
    expect(dependabot).toContain('package-ecosystem: "docker"');
    expect(dependabot).toContain('package-ecosystem: "github-actions"');
  });

  it("rejects child_process, eval and SHA-1/MD5 through ESLint rules", async () => {
    const eslint = new ESLint({
      overrideConfigFile: path.resolve("eslint.config.js")
    });

    const childProcessRes = await eslint.lintText(
      'import { exec } from "node:child_process";\nexport const x = exec;\n',
      { filePath: path.resolve("src/cli.ts") }
    );
    expect(
      childProcessRes[0]?.messages.some((m) =>
        m.message.includes("The gateway never runs OS commands")
      )
    ).toBe(true);

    const evalRes = await eslint.lintText('eval("1 + 1");\n', {
      filePath: path.resolve("src/cli.ts")
    });
    expect(evalRes[0]?.messages.some((m) => m.ruleId === "no-eval")).toBe(true);

    const sha1Res = await eslint.lintText(
      'import { createHash } from "node:crypto";\nexport const h = createHash("sha1");\n',
      { filePath: path.resolve("src/cli.ts") }
    );
    expect(
      sha1Res[0]?.messages.some(
        (m) => m.ruleId === "no-restricted-syntax" && m.message.includes("V11.4.1")
      )
    ).toBe(true);
  }, 15000);
});

describe("loadConfig", () => {
  it("reports all 3 problems at once for missing public_base_url, unknown key upstream_ur with hint, and empty hash", () => {
    const filePath = writeTempConfig(
      [
        "# gateway config",
        "owner_passphrase_hash = \"\"",
        "",
        "[[tools]]",
        "name = \"notes.search\"",
        "class = \"read\"",
        "upstream_ur = \"http://demo:9000/mcp\""
      ].join("\n")
    );

    const result = loadConfig(filePath);
    expect(result.ok).toBe(false);
    if (result.ok) return;

    expect(result.problems).toHaveLength(3);
    expect(
      result.problems.some((p) => p.includes("public_base_url is missing"))
    ).toBe(true);
    expect(
      result.problems.some(
        (p) =>
          p.includes('line 7: unknown key "upstream_ur"') &&
          p.includes('Did you mean "upstream_url"?')
      )
    ).toBe(true);
    expect(
      result.problems.some((p) => p.includes("owner_passphrase_hash is empty"))
    ).toBe(true);
  });

  it("applies default values for a valid minimal config", () => {
    const filePath = writeTempConfig(
      [
        'public_base_url = "https://gw.example.ts.net"',
        'upstream_url = "http://demo:9000/mcp"',
        `owner_passphrase_hash = "${SAMPLE_HASH}"`,
        "",
        "[[tools]]",
        'name = "notes.search"',
        'class = "read"'
      ].join("\n")
    );

    const result = loadConfig(filePath);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.config.listen.public_port).toBe(8080);
    expect(result.config.listen.approve_port).toBe(8081);
    expect(result.config.queue.ttl_minutes).toBe(15);
    expect(result.config.queue.max_pending).toBe(50);
    expect(result.config.queue.purge_days).toBe(7);
    expect(result.config.tools[0]?.group).toBe("read");
  });

  it("rejects non-local http public_base_url and accepts http://127.0.0.1:9999", () => {
    const insecurePath = writeTempConfig(
      [
        'public_base_url = "http://example.com"',
        'upstream_url = "http://demo:9000/mcp"',
        `owner_passphrase_hash = "${SAMPLE_HASH}"`,
        "",
        "[[tools]]",
        'name = "notes.search"',
        'class = "read"'
      ].join("\n")
    );
    const insecureResult = loadConfig(insecurePath);
    expect(insecureResult.ok).toBe(false);
    if (!insecureResult.ok) {
      expect(
        insecureResult.problems.some((p) => p.includes("public_base_url"))
      ).toBe(true);
    }

    const loopbackPath = writeTempConfig(
      [
        'public_base_url = "http://127.0.0.1:9999"',
        'upstream_url = "http://demo:9000/mcp"',
        `owner_passphrase_hash = "${SAMPLE_HASH}"`,
        "",
        "[[tools]]",
        'name = "notes.search"',
        'class = "read"'
      ].join("\n")
    );
    const loopbackResult = loadConfig(loopbackPath);
    expect(loopbackResult.ok).toBe(true);
  });

  it("reports duplicate tool names, reserved approval_status, and a write tool with a group", () => {
    const filePath = writeTempConfig(
      [
        'public_base_url = "https://gw.example.ts.net"',
        'upstream_url = "http://demo:9000/mcp"',
        `owner_passphrase_hash = "${SAMPLE_HASH}"`,
        "",
        "[[tools]]",
        'name = "notes.search"',
        'class = "read"',
        "",
        "[[tools]]",
        'name = "notes.search"',
        'class = "read"',
        "",
        "[[tools]]",
        'name = "approval_status"',
        'class = "read"',
        "",
        "[[tools]]",
        'name = "notes.append_note"',
        'class = "write"',
        'group = "read"'
      ].join("\n")
    );

    const result = loadConfig(filePath);
    expect(result.ok).toBe(false);
    if (result.ok) return;

    expect(
      result.problems.some((p) => p.includes('"notes.search" is duplicated'))
    ).toBe(true);
    expect(
      result.problems.some((p) => p.includes("approval_status"))
    ).toBe(true);
    expect(
      result.problems.some((p) =>
        p.includes('tools.group is not allowed on write tool "notes.append_note"')
      )
    ).toBe(true);
  });

  it("reports TOML syntax errors as a single problem", () => {
    const filePath = writeTempConfig('public_base_url = "unterminated\n');
    const result = loadConfig(filePath);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.problems).toHaveLength(1);
      expect(result.problems[0]).toContain("TOML syntax error");
    }
  });
});
