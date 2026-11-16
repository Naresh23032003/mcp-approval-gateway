import { z } from "zod";

export const ToolNamePattern = /^[a-z][a-z0-9_.-]{0,63}$/;
export const ToolGroupPattern = /^[a-z][a-z0-9_-]{0,31}$/;

const LOCAL_HTTP_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function isValidPublicBaseUrl(value: string): { ok: true } | { ok: false; reason: string } {
  if (value.trim() === "") {
    return {
      ok: false,
      reason: "public_base_url is missing. Set it to the https address clients use."
    };
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return {
      ok: false,
      reason: "public_base_url must be a valid https URL with no path, query or fragment."
    };
  }

  const isHttps = parsed.protocol === "https:";
  const isLocalHttp = parsed.protocol === "http:" && LOCAL_HTTP_HOSTS.has(parsed.hostname);
  if (!isHttps && !isLocalHttp) {
    return {
      ok: false,
      reason:
        "public_base_url must use https (http is only allowed for localhost, 127.0.0.1 or [::1])."
    };
  }

  if (
    parsed.pathname !== "/" ||
    value.endsWith("/") ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    value.includes("?") ||
    value.includes("#")
  ) {
    return {
      ok: false,
      reason: "public_base_url must not contain a path, trailing slash, query or fragment."
    };
  }

  return { ok: true };
}

export function isValidHttpOrHttpsUrl(value: string): boolean {
  if (value.trim() === "") {
    return false;
  }
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

export const ListenSchema = z
  .object({
    public_port: z
      .number()
      .int("listen.public_port must be an integer between 1024 and 65535.")
      .min(1024, "listen.public_port must be between 1024 and 65535.")
      .max(65535, "listen.public_port must be between 1024 and 65535.")
      .default(8080),
    approve_port: z
      .number()
      .int("listen.approve_port must be an integer between 1024 and 65535.")
      .min(1024, "listen.approve_port must be between 1024 and 65535.")
      .max(65535, "listen.approve_port must be between 1024 and 65535.")
      .default(8081)
  })
  .strict()
  .superRefine((val, ctx) => {
    if (val.public_port === val.approve_port) {
      ctx.addIssue({
        code: "custom",
        path: ["approve_port"],
        message: "listen.approve_port must differ from listen.public_port."
      });
    }
  });

export const QueueSchema = z
  .object({
    ttl_minutes: z
      .number()
      .int("queue.ttl_minutes must be an integer between 1 and 1440.")
      .min(1, "queue.ttl_minutes must be between 1 and 1440.")
      .max(1440, "queue.ttl_minutes must be between 1 and 1440.")
      .default(15),
    max_pending: z
      .number()
      .int("queue.max_pending must be an integer between 1 and 500.")
      .min(1, "queue.max_pending must be between 1 and 500.")
      .max(500, "queue.max_pending must be between 1 and 500.")
      .default(50),
    purge_days: z
      .number()
      .int("queue.purge_days must be an integer between 1 and 365.")
      .min(1, "queue.purge_days must be between 1 and 365.")
      .max(365, "queue.purge_days must be between 1 and 365.")
      .default(7)
  })
  .strict();

export const NotifySchema = z
  .object({
    ntfy_url: z
      .string()
      .refine(isValidHttpOrHttpsUrl, {
        message: "notify.ntfy_url must be a valid http or https URL."
      })
      .optional()
  })
  .strict();

export const ToolSchema = z
  .object({
    name: z
      .string()
      .regex(ToolNamePattern, "tools.name must match ^[a-z][a-z0-9_.-]{0,63}$.")
      .refine((name) => name !== "approval_status", {
        message: 'tools.name cannot be "approval_status" (reserved by the gateway).'
      }),
    class: z.enum(["read", "write"], {
      message: 'tools.class must be "read" or "write".'
    }),
    group: z
      .string()
      .regex(ToolGroupPattern, "tools.group must match ^[a-z][a-z0-9_-]{0,31}$ (no colon).")
      .optional()
  })
  .strict()
  .superRefine((tool, ctx) => {
    if (tool.class === "write" && tool.group !== undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["group"],
        message: `tools.group is not allowed on write tool "${tool.name}". Only read tools may set a group.`
      });
    }
  })
  .transform((tool) => ({
    name: tool.name,
    class: tool.class,
    ...(tool.class === "read" ? { group: tool.group ?? "read" } : {})
  }));

export const ConfigSchema = z
  .object({
    public_base_url: z.string().superRefine((val, ctx) => {
      const check = isValidPublicBaseUrl(val);
      if (!check.ok) {
        ctx.addIssue({
          code: "custom",
          message: check.reason
        });
      }
    }),
    upstream_url: z
      .string()
      .min(1, "upstream_url is missing. Set it to the http or https URL of the upstream MCP server.")
      .refine(isValidHttpOrHttpsUrl, {
        message: "upstream_url must be a valid http or https URL."
      }),
    owner_passphrase_hash: z.string().superRefine((val, ctx) => {
      if (val === "") {
        ctx.addIssue({
          code: "custom",
          message: "owner_passphrase_hash is empty. Run hash-passphrase and paste the result."
        });
      } else if (!val.startsWith("$argon2id$")) {
        ctx.addIssue({
          code: "custom",
          message:
            'owner_passphrase_hash must start with "$argon2id$". Run hash-passphrase and paste the result.'
        });
      }
    }),
    listen: ListenSchema.default({ public_port: 8080, approve_port: 8081 }),
    queue: QueueSchema.default({ ttl_minutes: 15, max_pending: 50, purge_days: 7 }),
    notify: NotifySchema.default({}),
    tools: z
      .array(ToolSchema)
      .min(1, "tools must contain at least one tool entry.")
      .superRefine((tools, ctx) => {
        const seen = new Set<string>();
        for (let i = 0; i < tools.length; i++) {
          const item = tools[i];
          if (!item) continue;
          if (seen.has(item.name)) {
            ctx.addIssue({
              code: "custom",
              path: [i, "name"],
              message: `tools.name "${item.name}" is duplicated. Tool names must be unique.`
            });
          } else {
            seen.add(item.name);
          }
        }
      })
  })
  .strict();

export type Config = z.infer<typeof ConfigSchema>;
