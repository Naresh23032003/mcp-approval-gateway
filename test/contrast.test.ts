import { describe, expect, it } from "vitest";
import { CONSENT_CSS, DARK_TOKENS, LIGHT_TOKENS, type ColorTokens } from "../src/ui/style.js";

function parseHexChannel(hex: string, offset: number): number {
  return Number.parseInt(hex.slice(offset, offset + 2), 16) / 255;
}

function linearizeChannel(channel: number): number {
  if (channel <= 0.04045) {
    return channel / 12.92;
  }
  return Math.pow((channel + 0.055) / 1.055, 2.4);
}

function relativeLuminance(hex: string): number {
  expect(hex).toMatch(/^#[0-9A-Fa-f]{6}$/);
  const r = linearizeChannel(parseHexChannel(hex, 1));
  const g = linearizeChannel(parseHexChannel(hex, 3));
  const b = linearizeChannel(parseHexChannel(hex, 5));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrastRatio(hexA: string, hexB: string): number {
  const lumA = relativeLuminance(hexA);
  const lumB = relativeLuminance(hexB);
  const lighter = Math.max(lumA, lumB);
  const darker = Math.min(lumA, lumB);
  return (lighter + 0.05) / (darker + 0.05);
}

type TokenName = keyof ColorTokens;

const TEXT_PAIRS: ReadonlyArray<readonly [TokenName, TokenName]> = [
  ["ink", "bg"],
  ["ink", "surface"],
  ["ink", "code"],
  ["muted", "bg"],
  ["muted", "surface"],
  ["muted", "code"],
  ["primary", "bg"],
  ["primary", "surface"],
  ["on-primary", "primary"],
  ["danger", "surface"],
  ["danger", "bg"],
  ["danger", "danger-bg"],
  ["amber", "surface"],
  ["amber", "amber-bg"],
  ["ok", "surface"],
  ["ok", "ok-bg"]
];

const UI_PAIRS: ReadonlyArray<readonly [TokenName, TokenName]> = [
  ["edge", "surface"],
  ["edge", "bg"],
  ["focus", "surface"],
  ["focus", "bg"]
];

describe("WCAG 2.2 contrast ratios for consent UI colour tokens", () => {
  for (const [themeName, tokens] of [
    ["light", LIGHT_TOKENS],
    ["dark", DARK_TOKENS]
  ] as const) {
    it(`meets at least 4.5:1 for all text pairs in ${themeName} mode`, () => {
      for (const [fg, bg] of TEXT_PAIRS) {
        const ratio = contrastRatio(tokens[fg], tokens[bg]);
        expect(
          ratio,
          `${themeName} text pair ${fg} (${tokens[fg]}) on ${bg} (${tokens[bg]}) = ${ratio.toFixed(2)}`
        ).toBeGreaterThanOrEqual(4.5);
      }
    });

    it(`meets at least 3.0:1 for all UI pairs in ${themeName} mode`, () => {
      for (const [fg, bg] of UI_PAIRS) {
        const ratio = contrastRatio(tokens[fg], tokens[bg]);
        expect(
          ratio,
          `${themeName} UI pair ${fg} (${tokens[fg]}) on ${bg} (${tokens[bg]}) = ${ratio.toFixed(2)}`
        ).toBeGreaterThanOrEqual(3.0);
      }
    });
  }

  it("ships system fonts, 44px touch targets, dark and forced-colors media queries, and no transitions or external requests", () => {
    expect(CONSENT_CSS).toContain("system-ui, sans-serif");
    expect(CONSENT_CSS).toContain("ui-monospace, monospace");
    expect(CONSENT_CSS).toContain("max-width: 28rem");
    expect(CONSENT_CSS).toContain("min-height: 44px");
    expect(CONSENT_CSS).toContain("outline: 3px solid var(--focus)");
    expect(CONSENT_CSS).toContain("outline-offset: 2px");
    expect(CONSENT_CSS).toContain("@media (prefers-color-scheme: dark)");
    expect(CONSENT_CSS).toContain("@media (forced-colors: active)");
    expect(CONSENT_CSS).not.toMatch(/transition\s*:/i);
    expect(CONSENT_CSS).not.toMatch(/@font-face/i);
    expect(CONSENT_CSS).not.toMatch(/url\s*\(/i);
  });
});
