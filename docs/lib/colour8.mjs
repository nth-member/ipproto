// An 8-bit extension of Gigaspeak's Calc28 colour scheme, for protocol numbers
// 0-255. This is IPPROTO's own extension, not part of MDQNM.
//
// Gigaspeak (7 bits): foreground R,G,B = bits 6,5,4 (00/AA); background base =
// bit 3 (00/55), plus AA on R,G,B for bits 2,1,0. Here bit 7 does for the
// foreground what bit 3 does for the background: it sets the foreground base to
// 55. Numbers 0-127 therefore have exactly Gigaspeak's Calc28 colours, and all
// 256 colour pairs are distinct.

const hex2 = v => v.toString(16).toUpperCase().padStart(2, "0");

export function colors8(n) {
  if (!Number.isInteger(n) || n < 0 || n > 255) throw new RangeError(`Protocol number must be 0-255; received ${n}`);
  const part = (bit, base) => hex2(base + (n & bit ? 0xaa : 0));
  const fg = n & 0x80 ? 0x55 : 0x00, bg = n & 0x08 ? 0x55 : 0x00;
  return { foreground: `#${part(0x40, fg)}${part(0x20, fg)}${part(0x10, fg)}`, background: `#${part(0x04, bg)}${part(0x02, bg)}${part(0x01, bg)}` };
}

export function token8(n) {
  const { foreground, background } = colors8(n);
  return `<SPAN STYLE="COLOR:${foreground};BACKGROUND-COLOR:${background}">${n}</SPAN>`;
}

export const document8 = numbers => Array.from(numbers, token8).join("");

const TOKEN = /<SPAN STYLE="COLOR:(#[0-9A-F]{6});BACKGROUND-COLOR:(#[0-9A-F]{6})">(\d{1,3})<\/SPAN>/y;
// Strict inverse of document8.
export function decode8(doc) {
  const out = [];
  let off = 0;
  while (off < doc.length) {
    TOKEN.lastIndex = off;
    const m = TOKEN.exec(doc);
    if (!m) throw new SyntaxError(`Invalid token at offset ${off}`);
    const n = Number(m[3]);
    if (token8(n) !== m[0]) throw new SyntaxError(`Token at offset ${off} does not encode ${n}`);
    out.push(n);
    off = TOKEN.lastIndex;
  }
  return out;
}
