import crypto from "node:crypto";
import { html, raw, type SafeHtml } from "./html.js";
import { CONSENT_CSS, CONSENT_STYLE_SHA256 } from "./style.js";
import { visibleEscape } from "./visible.js";

export type InvalidAuthorizeReason =
  | "unknown client"
  | "redirect address not registered"
  | "PKCE S256 missing"
  | "request type not supported"
  | "resource not recognised"
  | "request not accepted";

export interface OptionalReadGroup {
  readonly group: string;
  readonly tools: readonly string[];
  readonly checked: boolean;
}

export interface ConsentHiddenParams {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly responseType: string;
  readonly codeChallenge: string;
  readonly codeChallengeMethod: string;
  readonly scope: string;
  readonly state?: string;
  readonly resource?: string;
}

export interface ConsentPageModel {
  readonly clientName: string;
  readonly gatewayHost: string;
  readonly redirectHost: string;
  readonly registeredAgo: string;
  readonly readTools: readonly string[];
  readonly optionalGroups: readonly OptionalReadGroup[];
  readonly csrfToken: string;
  readonly hidden: ConsentHiddenParams;
  readonly errorMessage?: string;
}

export const CONSENT_SCRIPT = `(function(){
var err=document.getElementById("error-summary");
if(err){err.focus();}
var pw=document.getElementById("passphrase");
var toggle=document.getElementById("toggle-passphrase");
if(pw&&toggle){
toggle.addEventListener("click",function(){
var showing=pw.type==="text";
pw.type=showing?"password":"text";
toggle.setAttribute("aria-pressed",showing?"false":"true");
toggle.textContent=showing?"Show":"Hide";
});
}
var allowBtn=document.getElementById("allow-button");
var boxes=document.querySelectorAll('input[name="granted_scopes"]');
function updateAllowLabel(){
if(!allowBtn){return;}
var names=["read"];
for(var i=0;i<boxes.length;i++){
if(boxes[i].checked){names.push(boxes[i].value);}
}
if(names.length===1){
allowBtn.textContent="Allow read access";
}else if(names.length===2){
allowBtn.textContent="Allow "+names[0]+" and "+names[1]+" access";
}else{
allowBtn.textContent="Allow "+names.slice(0,-1).join(", ")+" and "+names[names.length-1]+" access";
}
}
for(var j=0;j<boxes.length;j++){
boxes[j].addEventListener("change",updateAllowLabel);
}
var form=document.getElementById("consent-form");
if(form){
var submitted=false;
form.addEventListener("submit",function(ev){
if(submitted){ev.preventDefault();return;}
submitted=true;
var submitter=ev.submitter;
var isCancel=submitter&&submitter.value==="cancel";
if(!isCancel&&allowBtn){
allowBtn.textContent="Checking...";
allowBtn.setAttribute("aria-busy","true");
}
});
}
})();`;

export const CONSENT_SCRIPT_SHA256 = crypto
  .createHash("sha256")
  .update(CONSENT_SCRIPT, "utf8")
  .digest("base64");

export function buildConsentCsp(redirectOrigin: string): string {
  return (
    `default-src 'none'; ` +
    `style-src 'sha256-${CONSENT_STYLE_SHA256}'; ` +
    `script-src 'sha256-${CONSENT_SCRIPT_SHA256}'; ` +
    `form-action 'self' ${redirectOrigin}; ` +
    `frame-ancestors 'none'; ` +
    `base-uri 'none'`
  );
}

export function buildStaticPageCsp(): string {
  return (
    `default-src 'none'; ` +
    `style-src 'sha256-${CONSENT_STYLE_SHA256}'; ` +
    `script-src 'none'; ` +
    `form-action 'none'; ` +
    `frame-ancestors 'none'; ` +
    `base-uri 'none'`
  );
}

export function formatRelativeTime(createdAtSeconds: number, nowSeconds: number): string {
  const diff = Math.max(0, Math.floor(nowSeconds - createdAtSeconds));
  if (diff < 60) {
    return diff <= 1 ? "just now" : `${diff} seconds ago`;
  }
  if (diff < 3600) {
    const minutes = Math.floor(diff / 60);
    return minutes === 1 ? "1 minute ago" : `${minutes} minutes ago`;
  }
  if (diff < 86400) {
    const hours = Math.floor(diff / 3600);
    return hours === 1 ? "1 hour ago" : `${hours} hours ago`;
  }
  const days = Math.floor(diff / 86400);
  return days === 1 ? "1 day ago" : `${days} days ago`;
}

export function formatAllowButtonLabel(checkedOptionalGroups: readonly string[]): string {
  const scopes = ["read", ...checkedOptionalGroups];
  if (scopes.length === 1) {
    return "Allow read access";
  }
  if (scopes.length === 2) {
    return `Allow ${scopes[0]} and ${scopes[1]} access`;
  }
  const head = scopes.slice(0, -1).join(", ");
  const last = scopes[scopes.length - 1] ?? "";
  return `Allow ${head} and ${last} access`;
}

function renderDocument(title: string, body: SafeHtml, includeScript: boolean): string {
  const scriptBlock = includeScript ? raw(`<script>${CONSENT_SCRIPT}</script>`) : raw("");
  return html`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>${raw(CONSENT_CSS)}</style>
</head>
<body>
<main>
${body}
</main>
${scriptBlock}
</body>
</html>`.toString();
}

export function renderInvalidPage(reason: InvalidAuthorizeReason): string {
  const body = html`<section class="card">
<h1>This connection request was not accepted.</h1>
<p>The app sent a request the gateway does not allow: ${reason}. Nothing was connected. Remove the connector and add it again. If it keeps failing, run doctor.</p>
</section>`;
  return renderDocument("Connection request not accepted", body, false);
}

export function renderLockedPage(): string {
  const body = html`<section class="card">
<div class="error-summary" role="alert">
<p class="error-label">Error</p>
<p>Too many wrong passphrases from this address. Try again in 15 minutes.</p>
</div>
<h1>Connection temporarily locked.</h1>
<p class="muted">No passphrase was checked. Wait 15 minutes before trying again.</p>
</section>`;
  return renderDocument("Too many wrong passphrases", body, false);
}

export function renderConsentPage(model: ConsentPageModel): string {
  const visibleName = visibleEscape(model.clientName);
  const checkedGroups = model.optionalGroups
    .filter((entry) => entry.checked)
    .map((entry) => entry.group);
  const allowLabel = formatAllowButtonLabel(checkedGroups);

  const errorBlock =
    model.errorMessage !== undefined
      ? html`<div id="error-summary" class="error-summary" role="alert" tabindex="-1">
<p class="error-label">Error</p>
<p>${model.errorMessage}</p>
</div>`
      : raw("");

  const readToolsBlock =
    model.readTools.length > 0
      ? html`<p class="scope-tools">${model.readTools.join(", ")}</p>`
      : raw("");

  const optionalGroupBlocks = model.optionalGroups.map((entry, idx) => {
    const checkboxId = `scope-group-${idx}`;
    const checkedAttr = entry.checked ? raw(" checked") : raw("");
    const toolsText =
      entry.tools.length > 0
        ? html`<span class="scope-tools">${entry.tools.join(", ")}</span>`
        : raw("");
    return html`<div class="scope-item">
<label class="scope-checkbox" for="${checkboxId}">
<input type="checkbox" id="${checkboxId}" name="granted_scopes" value="${entry.group}"${checkedAttr}>
<span class="scope-checkbox-body">
<span class="scope-name">${entry.group}</span>
${toolsText}
</span>
</label>
</div>`;
  });

  const stateInput =
    model.hidden.state !== undefined
      ? html`<input type="hidden" name="state" value="${model.hidden.state}">`
      : raw("");

  const resourceInput =
    model.hidden.resource !== undefined
      ? html`<input type="hidden" name="resource" value="${model.hidden.resource}">`
      : raw("");

  const body = html`<section class="card">
<h1>Allow "<span class="data">${visibleName}</span>" to use your gateway?</h1>
<p class="muted">The client chose this name. Not verified.</p>
<dl class="meta">
<dt>Gateway</dt>
<dd><span class="data">${model.gatewayHost}</span></dd>
<dt>Returns to</dt>
<dd><span class="data">${model.redirectHost}</span></dd>
<dt>Registered</dt>
<dd>${model.registeredAgo}</dd>
</dl>
${errorBlock}
<form id="consent-form" method="post" action="/authorize">
<input type="hidden" name="csrf_token" value="${model.csrfToken}">
<input type="hidden" name="client_id" value="${model.hidden.clientId}">
<input type="hidden" name="redirect_uri" value="${model.hidden.redirectUri}">
<input type="hidden" name="response_type" value="${model.hidden.responseType}">
<input type="hidden" name="code_challenge" value="${model.hidden.codeChallenge}">
<input type="hidden" name="code_challenge_method" value="${model.hidden.codeChallengeMethod}">
<input type="hidden" name="scope" value="${model.hidden.scope}">
${stateInput}
${resourceInput}
<h2>This app can</h2>
<div class="scope-list">
<div class="scope-item">
<div class="scope-header">
<span class="scope-name">Read</span>
<span class="scope-note">Always included.</span>
</div>
${readToolsBlock}
</div>
${optionalGroupBlocks}
</div>
<p class="notice">Anything that changes data is held. You approve or deny it on a page only your tailnet can open. The app cannot do it for you.</p>
<div class="field">
<label for="passphrase">Owner passphrase</label>
<div class="passphrase-row">
<input id="passphrase" name="passphrase" type="password" autocomplete="current-password" aria-describedby="passphrase-help" required>
<button type="button" id="toggle-passphrase" class="toggle-btn" aria-pressed="false" aria-controls="passphrase">Show</button>
</div>
<p id="passphrase-help" class="help">The one you set with hash-passphrase.</p>
</div>
<div class="actions">
<button type="submit" name="decision" value="allow" id="allow-button" class="btn-primary">${allowLabel}</button>
<button type="submit" name="decision" value="cancel" id="cancel-button" class="btn-secondary" formnovalidate>Cancel</button>
</div>
<p class="muted footnote">Continue only if you just added this gateway as a connector yourself.</p>
</form>
</section>`;

  return renderDocument("Allow connection", body, true);
}
