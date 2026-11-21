import crypto from "node:crypto";

export interface ColorTokens {
  readonly bg: string;
  readonly surface: string;
  readonly code: string;
  readonly ink: string;
  readonly muted: string;
  readonly edge: string;
  readonly primary: string;
  readonly "on-primary": string;
  readonly danger: string;
  readonly "danger-bg": string;
  readonly amber: string;
  readonly "amber-bg": string;
  readonly ok: string;
  readonly "ok-bg": string;
  readonly focus: string;
}

export const LIGHT_TOKENS: ColorTokens = Object.freeze({
  bg: "#F1F4F5",
  surface: "#FFFFFF",
  code: "#EAEFF1",
  ink: "#15222B",
  muted: "#46545E",
  edge: "#7B8A94",
  primary: "#0B5F73",
  "on-primary": "#FFFFFF",
  danger: "#A3122F",
  "danger-bg": "#FDE8EC",
  amber: "#7A4700",
  "amber-bg": "#FFF0D1",
  ok: "#17663A",
  "ok-bg": "#E2F3E8",
  focus: "#1553D6"
});

export const DARK_TOKENS: ColorTokens = Object.freeze({
  bg: "#0E1519",
  surface: "#162026",
  code: "#0B1114",
  ink: "#E4ECEF",
  muted: "#A3B3BB",
  edge: "#66767F",
  primary: "#58C2D8",
  "on-primary": "#06222A",
  danger: "#FF8DA1",
  "danger-bg": "#33121A",
  amber: "#F3C56B",
  "amber-bg": "#2B2110",
  ok: "#7FDB9F",
  "ok-bg": "#10281A",
  focus: "#7DB2FF"
});

function formatTokenBlock(tokens: ColorTokens): string {
  return Object.entries(tokens)
    .map(([name, hex]) => `  --${name}: ${hex};`)
    .join("\n");
}

export const CONSENT_CSS = `:root {
${formatTokenBlock(LIGHT_TOKENS)}
}
@media (prefers-color-scheme: dark) {
  :root {
${formatTokenBlock(DARK_TOKENS)}
  }
}
*, *::before, *::after {
  box-sizing: border-box;
}
html {
  color-scheme: light dark;
}
body {
  margin: 0;
  padding: 24px 16px;
  background: var(--bg);
  color: var(--ink);
  font-family: system-ui, sans-serif;
  font-size: 16px;
  line-height: 24px;
}
main {
  max-width: 28rem;
  margin: 0 auto;
  text-align: left;
}
.card {
  background: var(--surface);
  border: 1px solid var(--edge);
  border-radius: 6px;
  padding: 20px;
}
h1 {
  margin: 0 0 8px 0;
  font-size: 20px;
  line-height: 28px;
  font-weight: 700;
  overflow-wrap: anywhere;
}
h2 {
  margin: 20px 0 8px 0;
  font-size: 16px;
  line-height: 24px;
  font-weight: 700;
}
p {
  margin: 0 0 12px 0;
}
.muted {
  color: var(--muted);
}
.data {
  font-family: ui-monospace, monospace;
  background: var(--code);
  padding: 1px 6px;
  border-radius: 4px;
  overflow-wrap: anywhere;
}
.meta {
  margin: 16px 0;
  padding: 12px 0;
  border-top: 1px solid var(--edge);
  border-bottom: 1px solid var(--edge);
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 8px 12px;
  align-items: baseline;
}
.meta dt {
  margin: 0;
  color: var(--muted);
  font-weight: 600;
}
.meta dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.scope-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-bottom: 16px;
}
.scope-item {
  border: 1px solid var(--edge);
  border-radius: 6px;
  padding: 10px 12px;
  background: var(--surface);
}
.scope-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 8px;
}
.scope-name {
  font-weight: 700;
}
.scope-note {
  color: var(--muted);
  font-size: 14px;
}
.scope-tools {
  display: block;
  margin: 6px 0 0 0;
  font-size: 14px;
  line-height: 20px;
  color: var(--muted);
  font-family: ui-monospace, monospace;
  overflow-wrap: anywhere;
}
.scope-checkbox {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  min-height: 44px;
  cursor: pointer;
}
.scope-checkbox input[type="checkbox"] {
  width: 20px;
  height: 20px;
  margin: 2px 0 0 0;
  flex: 0 0 auto;
  accent-color: var(--primary);
}
.scope-checkbox-body {
  display: block;
  flex: 1 1 auto;
}
.notice {
  background: var(--code);
  border-left: 3px solid var(--edge);
  border-radius: 4px;
  padding: 10px 12px;
  margin: 16px 0;
}
.field {
  margin: 16px 0;
}
.field label {
  display: block;
  font-weight: 700;
  margin-bottom: 6px;
}
.passphrase-row {
  display: flex;
  gap: 8px;
  align-items: stretch;
}
.passphrase-row input {
  flex: 1 1 auto;
  min-width: 0;
  min-height: 44px;
  padding: 8px 12px;
  font-family: system-ui, sans-serif;
  font-size: 16px;
  line-height: 24px;
  color: var(--ink);
  background: var(--surface);
  border: 2px solid var(--edge);
  border-radius: 6px;
}
.toggle-btn {
  flex: 0 0 auto;
  min-height: 44px;
  min-width: 68px;
  padding: 8px 12px;
  font-family: system-ui, sans-serif;
  font-size: 16px;
  line-height: 24px;
  font-weight: 600;
  color: var(--ink);
  background: var(--surface);
  border: 2px solid var(--edge);
  border-radius: 6px;
  cursor: pointer;
}
.help {
  margin: 6px 0 0 0;
  color: var(--muted);
  font-size: 14px;
  line-height: 20px;
}
.actions {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-top: 20px;
}
.btn-primary,
.btn-secondary {
  width: 100%;
  min-height: 44px;
  padding: 10px 16px;
  font-family: system-ui, sans-serif;
  font-size: 16px;
  line-height: 24px;
  font-weight: 600;
  border-radius: 6px;
  cursor: pointer;
}
.btn-primary {
  background: var(--primary);
  color: var(--on-primary);
  border: 2px solid var(--primary);
}
.btn-secondary {
  background: var(--surface);
  color: var(--ink);
  border: 2px solid var(--edge);
}
.footnote {
  margin: 12px 0 0 0;
  font-size: 14px;
  line-height: 20px;
}
.error-summary {
  background: var(--danger-bg);
  color: var(--danger);
  border: 2px solid var(--danger);
  border-radius: 6px;
  padding: 12px 16px;
  margin-bottom: 16px;
}
.error-label {
  font-weight: 700;
  margin: 0 0 4px 0;
}
.error-summary p:last-child {
  margin-bottom: 0;
}
button:focus-visible,
input:focus-visible,
#error-summary:focus {
  outline: 3px solid var(--focus);
  outline-offset: 2px;
}
@media (forced-colors: active) {
  .card,
  .scope-item,
  .error-summary,
  .passphrase-row input,
  .toggle-btn,
  .btn-primary,
  .btn-secondary {
    border-color: ButtonBorder;
  }
  .btn-primary {
    background: Highlight;
    color: HighlightText;
    border-color: Highlight;
  }
  button:focus-visible,
  input:focus-visible,
  #error-summary:focus {
    outline: 3px solid Highlight;
    outline-offset: 2px;
  }
}`;

export const CONSENT_STYLE_SHA256 = crypto
  .createHash("sha256")
  .update(CONSENT_CSS, "utf8")
  .digest("base64");
