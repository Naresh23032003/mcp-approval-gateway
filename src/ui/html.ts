const SAFE_HTML_BRAND = Symbol("SafeHtml");

const HTML_ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;"
};

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => HTML_ESCAPE_MAP[ch] ?? ch);
}

export class SafeHtml {
  readonly [SAFE_HTML_BRAND] = true;
  readonly value: string;

  constructor(value: string) {
    this.value = value;
  }

  toString(): string {
    return this.value;
  }
}

export function isSafeHtml(value: unknown): value is SafeHtml {
  return value instanceof SafeHtml && value[SAFE_HTML_BRAND] === true;
}

export function raw(trustedHtml: string): SafeHtml {
  return new SafeHtml(trustedHtml);
}

export type HtmlValue =
  | SafeHtml
  | string
  | number
  | boolean
  | null
  | undefined
  | readonly HtmlValue[];

function isInsideOpenScriptTag(accumulatedStatic: string): boolean {
  const lower = accumulatedStatic.toLowerCase();
  const lastOpen = lower.lastIndexOf("<script");
  if (lastOpen === -1) {
    return false;
  }
  const charAfterOpen = lower[lastOpen + 7];
  if (
    charAfterOpen !== undefined &&
    charAfterOpen !== ">" &&
    charAfterOpen !== "/" &&
    !/\s/.test(charAfterOpen)
  ) {
    return false;
  }
  const lastClose = lower.lastIndexOf("</script");
  return lastClose < lastOpen;
}

function renderHtmlValue(value: HtmlValue): string {
  if (value === null || value === undefined || value === false) {
    return "";
  }
  if (isSafeHtml(value)) {
    return value.value;
  }
  if (Array.isArray(value)) {
    let out = "";
    const items: readonly HtmlValue[] = value;
    for (const item of items) {
      out += renderHtmlValue(item);
    }
    return out;
  }
  if (typeof value === "string") {
    return escapeHtml(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return escapeHtml(String(value));
  }
  return "";
}

export function html(
  strings: TemplateStringsArray,
  ...values: readonly HtmlValue[]
): SafeHtml {
  let out = "";
  let staticSoFar = "";

  for (let i = 0; i < strings.length; i++) {
    const literal = strings[i] ?? "";
    out += literal;
    staticSoFar += literal;

    if (i < values.length) {
      if (isInsideOpenScriptTag(staticSoFar)) {
        throw new Error("Data interpolation inside a <script> context is not permitted.");
      }
      out += renderHtmlValue(values[i]);
    }
  }

  return new SafeHtml(out);
}
