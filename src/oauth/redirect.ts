export function buildAuthorizationCodeRedirect(
  redirectUri: string,
  code: string,
  state?: string
): string {
  const url = new URL(redirectUri);
  url.searchParams.set("code", code);
  if (state !== undefined && state !== "") {
    url.searchParams.set("state", state);
  }
  return url.toString();
}

export function buildAuthorizationErrorRedirect(
  redirectUri: string,
  error: string,
  state?: string
): string {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  if (state !== undefined && state !== "") {
    url.searchParams.set("state", state);
  }
  return url.toString();
}

export function redirectOriginForCsp(redirectUri: string): string {
  const url = new URL(redirectUri);
  if (url.protocol === "http:" || url.protocol === "https:") {
    return url.origin;
  }
  return url.protocol;
}

export function displayHostForUri(rawUri: string): string {
  const url = new URL(rawUri);
  if (url.host.length > 0) {
    return url.host;
  }
  return url.protocol.endsWith(":") ? url.protocol.slice(0, -1) : url.protocol;
}
