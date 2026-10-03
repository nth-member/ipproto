// The six SPAN grammars of the Random Gigamonkey Speaker, as one codec.
//
// Every grammar maps one ASCII byte (0x00..0x7F) to one canonical SPAN token.
// Two independent choices define a grammar:
//
//   colors  "rgba"  #RRGGBBAA, the alpha pair repeats the byte   (calc32)
//           "rgb"   #RRGGBB, no alpha                            (calc28)
//   form    "closed"  <SPAN …>payload</SPAN>  visible label
//           "open"    <SPAN …>               opening tag only; tokens nest
//           "empty"   <SPAN …></SPAN>        closed, no payload
//
// In both color depths the seven bits are carried by the RGB fields alone:
// foreground R,G,B = bits 6,5,4 (00/AA); background base = bit 3 (00/55), plus
// AA on R,G,B for bits 2,1,0. The 128 color pairs are therefore unique.

export const CONTROL_NAMES = Object.freeze([
  "NUL", "SOH", "STX", "ETX", "EOT", "ENQ", "ACK", "BEL",
  "BS", "HT", "LF", "VT", "FF", "CR", "SO", "SI",
  "DLE", "DC1", "DC2", "DC3", "DC4", "NAK", "SYN", "ETB",
  "CAN", "EM", "SUB", "ESC", "FS", "GS", "RS", "US"
]);

export const GRAMMARS = Object.freeze([
  { id: "span-transparent", title: "SPAN Transparent", colors: "rgba", form: "closed", source: "calc32 tt-taop-htmlcolor-by-span-transparent", display: "Visible payload" },
  { id: "span-transparent-zero-opening-tags", title: "SPAN Transparent Zero · Opening Tags", colors: "rgba", form: "open", source: "calc32 tt-taop-htmlcolor-by-span-transparent-zero", display: "No payload; tokens nest" },
  { id: "span-transparent-zero", title: "SPAN Transparent Zero · Closing Tags", colors: "rgba", form: "empty", source: "calc32 span-transparent-zero, each token closed", display: "No payload; sibling tokens" },
  { id: "calc28-span", title: "Calc28 Full SPAN", colors: "rgb", form: "closed", source: "calc28 tt-taop-htmlcolor-by-span", display: "Visible payload" },
  { id: "span-zero", title: "Span Zero", colors: "rgb", form: "open", source: "calc28 opening tags only", display: "Invisible; tokens nest" },
  { id: "span-zero-closing-tags", title: "Span Zero · Closing Tags", colors: "rgb", form: "empty", source: "calc28 opening tags, each closed", display: "Invisible; sibling tokens" }
].map(g => Object.freeze(g)));

export const DEFAULT_GRAMMAR = "span-transparent";

const hex2 = value => value.toString(16).toUpperCase().padStart(2, "0");

function assertByte(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0x7f) {
    throw new RangeError(`ASCII byte must be an integer from 0x00 through 0x7F; received ${value}`);
  }
}

export function labelForByte(byte) {
  assertByte(byte);
  if (byte < 0x20) return CONTROL_NAMES[byte];
  if (byte === 0x20) return "SP";
  if (byte === 0x7f) return "DEL";
  return String.fromCharCode(byte);
}

export function bytesToText(bytes) {
  let text = "";
  for (let i = 0; i < bytes.length; i += 65536) text += String.fromCharCode(...bytes.slice(i, i + 65536));
  return text;
}

function rgbFields(byte) {
  const base = byte & 0x08 ? 0x55 : 0x00;
  const bg = bit => hex2(base + (byte & bit ? 0xaa : 0));
  return {
    foreground: `${byte & 0x40 ? "AA" : "00"}${byte & 0x20 ? "AA" : "00"}${byte & 0x10 ? "AA" : "00"}`,
    background: `${bg(0x04)}${bg(0x02)}${bg(0x01)}`
  };
}

function build(spec) {
  const alpha = spec.colors === "rgba";
  const digits = alpha ? 8 : 6;

  function colorsForByte(byte) {
    assertByte(byte);
    const { foreground, background } = rgbFields(byte);
    const a = alpha ? hex2(byte) : "";
    return Object.freeze({ foreground: `#${foreground}${a}`, background: `#${background}${a}` });
  }

  function tokenForByte(byte) {
    const { foreground, background } = colorsForByte(byte);
    const open = `<SPAN STYLE="COLOR:${foreground};BACKGROUND-COLOR:${background}">`;
    if (spec.form === "open") return open;
    if (spec.form === "empty") return `${open}</SPAN>`;
    return `${open}${labelForByte(byte)}</SPAN>`;
  }

  const TOKENS = Object.freeze(Array.from({ length: 128 }, (_, byte) => tokenForByte(byte)));
  const ENCODED_LENGTHS = Object.freeze(TOKENS.map(token => encodeURIComponent(token).length));
  const BYTE_BY_OPENING = new Map(TOKENS.map((token, byte) => [token.slice(0, token.indexOf(">") + 1), byte]));
  const tail = spec.form === "closed" ? "([\\s\\S]*?)<\\/SPAN>" : spec.form === "empty" ? "<\\/SPAN>" : "";
  const pattern = new RegExp(`<SPAN STYLE="COLOR:#[0-9A-F]{${digits}};BACKGROUND-COLOR:#[0-9A-F]{${digits}}">${tail}`, "y");

  function encodeBytes(bytes) {
    if (bytes == null || typeof bytes[Symbol.iterator] !== "function") throw new TypeError("bytes must be iterable");
    let out = "";
    for (const byte of bytes) { assertByte(byte); out += TOKENS[byte]; }
    return out;
  }

  function encodeText(text) {
    if (typeof text !== "string") throw new TypeError("text must be a string");
    const bytes = new Array(text.length);
    for (let index = 0; index < text.length; index += 1) {
      const byte = text.charCodeAt(index);
      if (byte > 0x7f) throw new RangeError(`Non-ASCII character at UTF-16 index ${index}: ${JSON.stringify(text[index])}`);
      bytes[index] = byte;
    }
    return encodeBytes(bytes);
  }

  // Strict inverse of encodeBytes: any spelling other than the canonical
  // token sequence is rejected, with the offset of the first bad token.
  function decode(document) {
    if (typeof document !== "string") throw new TypeError("document must be a string");
    const bytes = [];
    let offset = 0;
    while (offset < document.length) {
      pattern.lastIndex = offset;
      const match = pattern.exec(document);
      if (!match) {
        throw new SyntaxError(`Invalid ${spec.title} token at offset ${offset}: ${JSON.stringify(document.slice(offset, offset + 48))}`);
      }
      const opening = match[0].slice(0, match[0].indexOf(">") + 1);
      const byte = BYTE_BY_OPENING.get(opening);
      if (byte === undefined) throw new SyntaxError(`Color tuple encodes no ASCII byte at offset ${offset}`);
      if (spec.form === "closed" && match[1] !== labelForByte(byte)) {
        throw new SyntaxError(`Payload ${JSON.stringify(match[1])} does not match byte 0x${hex2(byte)} at offset ${offset}`);
      }
      bytes.push(byte);
      offset = pattern.lastIndex;
    }
    return Object.freeze({ bytes: Object.freeze(bytes), text: bytesToText(bytes) });
  }

  return Object.freeze({
    ...spec,
    colorsForByte,
    tokenForByte: byte => { assertByte(byte); return TOKENS[byte]; },
    encodedTokenLength: byte => { assertByte(byte); return ENCODED_LENGTHS[byte]; },
    encodeBytes,
    encodeText,
    decode
  });
}

const BY_ID = new Map(GRAMMARS.map(spec => [spec.id, build(spec)]));

export function grammar(id = DEFAULT_GRAMMAR) {
  const g = BY_ID.get(id);
  if (!g) throw new RangeError(`Unknown grammar: ${id}`);
  return g;
}

export { hex2 };
