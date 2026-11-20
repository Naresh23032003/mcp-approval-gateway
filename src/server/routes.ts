export type HttpMethod = "GET" | "POST";
export type ListenerName = "public" | "approve";

export interface RouteEntry {
  readonly method: HttpMethod;
  readonly path: string;
  readonly listener: ListenerName;
  readonly public: boolean;
  readonly mutates: boolean;
}

// Wildcard /.well-known/* is represented by the two concrete OAuth metadata documents below.
export const routes: readonly RouteEntry[] = Object.freeze([
  {
    method: "GET",
    path: "/.well-known/oauth-protected-resource",
    listener: "public",
    public: true,
    mutates: false
  },
  {
    method: "GET",
    path: "/.well-known/oauth-authorization-server",
    listener: "public",
    public: true,
    mutates: false
  },
  {
    method: "POST",
    path: "/register",
    listener: "public",
    public: true,
    mutates: true
  },
  {
    method: "GET",
    path: "/authorize",
    listener: "public",
    public: true,
    mutates: false
  },
  {
    method: "POST",
    path: "/authorize",
    listener: "public",
    public: true,
    mutates: true
  },
  {
    method: "POST",
    path: "/token",
    listener: "public",
    public: true,
    mutates: true
  },
  {
    method: "POST",
    path: "/mcp",
    listener: "public",
    public: true,
    mutates: true
  },
  {
    method: "GET",
    path: "/approvals",
    listener: "approve",
    public: false,
    mutates: false
  },
  {
    method: "GET",
    path: "/admin",
    listener: "approve",
    public: false,
    mutates: false
  }
]);

export function routesFor(listener: ListenerName): readonly RouteEntry[] {
  return routes.filter((entry) => entry.listener === listener);
}
