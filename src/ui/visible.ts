const CONTROL_OR_FORMAT_PATTERN = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

const EXTRA_INVISIBLE_CODE_POINTS = new Set<number>([
  0x034f,
  0x115f,
  0x1160,
  0x17b4,
  0x17b5,
  0x180e,
  0x3164,
  0xffa0
]);

export function visibleEscape(input: string): string {
  let result = "";
  for (const ch of input) {
    const codePoint = ch.codePointAt(0);
    if (
      codePoint !== undefined &&
      (CONTROL_OR_FORMAT_PATTERN.test(ch) || EXTRA_INVISIBLE_CODE_POINTS.has(codePoint))
    ) {
      if (codePoint <= 0xffff) {
        result += `\\u${codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
      } else {
        result += `\\u{${codePoint.toString(16).toUpperCase()}}`;
      }
      continue;
    }
    result += ch;
  }
  return result;
}
