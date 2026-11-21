import { describe, expect, it } from "vitest";
import { renderConsentPage, renderInvalidPage, renderLockedPage } from "../src/ui/consent-page.js";
import { escapeHtml, html, isSafeHtml, raw } from "../src/ui/html.js";
import { visibleEscape } from "../src/ui/visible.js";

describe("HTML escaping helper (V1.2.1, V1.2.3)", () => {
  it("escapes all five HTML special characters in text and attribute contexts", () => {
    expect(escapeHtml(`& < > " '`)).toBe("&amp; &lt; &gt; &quot; &#39;");

    const untrusted = `"><script>alert('xss')</script>&`;
    const rendered = html`<input value="${untrusted}"><p>${untrusted}</p>`.toString();

    expect(rendered).toBe(
      `<input value="&quot;&gt;&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;&amp;"><p>&quot;&gt;&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;&amp;</p>`
    );
    expect(rendered).not.toContain("<script>");
  });

  it("allows trusted raw fragments and arrays while rejecting forged SafeHtml objects", () => {
    const items = [html`<li>${"<one>"}</li>`, html`<li>${"two"}</li>`];
    const rendered = html`<ul>${items}</ul>${raw("<span>ok</span>")}`.toString();
    expect(rendered).toBe("<ul><li>&lt;one&gt;</li><li>two</li></ul><span>ok</span>");

    const forged = { value: "<script>alert(1)</script>" };
    expect(isSafeHtml(forged)).toBe(false);
    expect(isSafeHtml(raw("<b>ok</b>"))).toBe(true);
  });

  it("refuses data interpolation inside a <script> element", () => {
    const payload = "alert(1)";
    expect(() => html`<script>var x = "${payload}";</script>`).toThrow(/script/i);
    expect(() => html`<SCRIPT type="text/javascript">${payload}</SCRIPT>`).toThrow(/script/i);
  });
});

describe("visibleEscape (V1.2.3, V3.2.2)", () => {
  it("renders control, zero-width and bidirectional override characters as literal \\uXXXX", () => {
    const bidi = "\u202E";
    const zeroWidth = "\u200B";
    const nul = "\u0000";
    const newline = "\n";
    const isolate = "\u2066";

    expect(visibleEscape(`App${bidi}Name`)).toBe("App\\u202EName");
    expect(visibleEscape(`A${zeroWidth}B${nul}C${newline}D${isolate}`)).toBe(
      "A\\u200BB\\u0000C\\u000AD\\u2066"
    );
    expect(visibleEscape("Normal Client Name 123 (v2)")).toBe("Normal Client Name 123 (v2)");
  });
});

describe("Consent page rendering", () => {
  it("escapes XSS and bidi characters in client name and contains no links", () => {
    const rendered = renderConsentPage({
      clientName: "<script>alert(1)</script>\u202Eevil",
      gatewayHost: "gw.example.ts.net",
      redirectHost: "claude.ai",
      registeredAgo: "2 minutes ago",
      readTools: ["notes.search", "notes.get"],
      optionalGroups: [
        { group: "finance", tools: ["finance.list"], checked: false }
      ],
      csrfToken: "csrf-token-value",
      hidden: {
        clientId: "client-123",
        redirectUri: "https://claude.ai/callback",
        responseType: "code",
        codeChallenge: "a".repeat(43),
        codeChallengeMethod: "S256",
        scope: "read finance"
      }
    });

    expect(rendered).not.toContain("<script>alert");
    expect(rendered).toContain("&lt;script&gt;alert(1)&lt;/script&gt;\\u202Eevil");
    expect(rendered).not.toContain("\u202E");
    expect(rendered).not.toMatch(/<a[\s>]/i);
    expect(rendered).not.toContain("/approvals");
    expect(rendered).not.toContain("/admin");
    expect(rendered).toContain("Not verified.");
    expect(rendered).toContain('autocomplete="current-password"');
    expect(rendered).toContain('type="password"');
    expect(rendered).toContain("Allow read access");
  });

  it("renders invalid and locked pages without forms or scripts", () => {
    const invalid = renderInvalidPage("unknown client");
    expect(invalid).toContain("This connection request was not accepted.");
    expect(invalid).toContain("unknown client");
    expect(invalid).not.toContain("<form");
    expect(invalid).not.toContain("<script");

    const locked = renderLockedPage();
    expect(locked).toContain(
      "Too many wrong passphrases from this address. Try again in 15 minutes."
    );
    expect(locked).not.toContain("<form");
    expect(locked).not.toContain("<script");
  });
});
