// Reads capture files: classic pcap (either byte order, micro- or nanosecond
// timestamps) and pcapng (sections, interfaces, enhanced/simple/obsolete packet
// blocks, if_tsresol). Returns the packets with their link type; decode.mjs
// takes it from there. Nothing leaves the browser.

export const LINKTYPE_NAMES = {
  0: "NULL (BSD loopback)", 1: "Ethernet", 12: "Raw IP", 14: "Raw IP", 101: "Raw IP", 108: "OpenBSD loopback",
  113: "Linux cooked (SLL)", 228: "Raw IPv4", 229: "Raw IPv6", 276: "Linux cooked v2 (SLL2)"
};

function classic(view, le, nano) {
  const u32 = o => view.getUint32(o, le);
  const linktype = u32(20) & 0x0fffffff;
  const snaplen = u32(16);
  const packets = [];
  let off = 24, truncatedFile = false;
  while (off + 16 <= view.byteLength) {
    const sec = u32(off), frac = u32(off + 4), incl = u32(off + 8), orig = u32(off + 12);
    off += 16;
    if (incl > view.byteLength - off) { truncatedFile = true; break; }
    packets.push({ ts: sec + frac / (nano ? 1e9 : 1e6), data: new Uint8Array(view.buffer, view.byteOffset + off, incl), origLen: orig, linktype });
    off += incl;
  }
  return { format: `pcap (${le ? "little" : "big"}-endian, ${nano ? "ns" : "µs"})`, snaplen, linktypes: [linktype], packets, truncatedFile };
}

function pcapng(view) {
  const packets = [];
  const linktypes = new Set();
  let le = true, interfaces = [], off = 0, truncatedFile = false;
  while (off + 12 <= view.byteLength) {
    let type = view.getUint32(off, le);
    if (type === 0x0a0d0d0a) {                      // section header: byte order from its magic
      le = view.getUint32(off + 8, true) === 0x1a2b3c4d;
      type = 0x0a0d0d0a;
      interfaces = [];
    }
    const len = view.getUint32(off + 4, le);
    if (len < 12 || off + len > view.byteLength) { truncatedFile = true; break; }
    const body = off + 8;
    if (type === 0x00000001) {                      // interface description
      const linktype = view.getUint16(body, le);
      let tsresol = 1e-6, o = body + 8;
      while (o + 4 <= off + len - 4) {
        const code = view.getUint16(o, le), olen = view.getUint16(o + 2, le);
        if (code === 0) break;
        if (code === 9 && olen >= 1) {
          const v = view.getUint8(o + 4);
          tsresol = v & 0x80 ? 2 ** -(v & 0x7f) : 10 ** -v;
        }
        o += 4 + Math.ceil(olen / 4) * 4;
      }
      interfaces.push({ linktype, tsresol, snaplen: view.getUint32(body + 4, le) });
      linktypes.add(linktype);
    } else if (type === 0x00000006 || type === 0x00000002) {   // enhanced / obsolete packet block
      const ifId = type === 6 ? view.getUint32(body, le) : view.getUint16(body, le);
      const hi = view.getUint32(body + 4, le), lo = view.getUint32(body + 8, le);
      const cap = view.getUint32(body + 12, le), orig = view.getUint32(body + 16, le);
      const iface = interfaces[ifId] ?? { linktype: 1, tsresol: 1e-6 };
      const start = body + 20;
      const n = Math.min(cap, off + len - 4 - start);
      packets.push({ ts: (hi * 4294967296 + lo) * iface.tsresol, data: new Uint8Array(view.buffer, view.byteOffset + start, Math.max(0, n)), origLen: orig, linktype: iface.linktype });
    } else if (type === 0x00000003) {               // simple packet block: interface 0, no timestamp
      const iface = interfaces[0] ?? { linktype: 1, snaplen: 0 };
      const orig = view.getUint32(body, le);
      const room = len - 16;
      const n = Math.min(orig, room, iface.snaplen || room);
      packets.push({ ts: null, data: new Uint8Array(view.buffer, view.byteOffset + body + 4, n), origLen: orig, linktype: iface.linktype });
    }
    off += len;
  }
  return { format: "pcapng", snaplen: null, linktypes: [...linktypes], packets, truncatedFile };
}

export function readCapture(buffer) {
  const view = new DataView(buffer instanceof ArrayBuffer ? buffer : buffer.buffer, buffer.byteOffset ?? 0, buffer.byteLength);
  if (view.byteLength < 24) throw new Error("The file is too short to be a capture.");
  const magicLE = view.getUint32(0, true);
  switch (magicLE) {
    case 0xa1b2c3d4: return classic(view, true, false);
    case 0xa1b23c4d: return classic(view, true, true);
    case 0xd4c3b2a1: return classic(view, false, false);
    case 0x4d3cb2a1: return classic(view, false, true);
    case 0x0a0d0d0a: return pcapng(view);
    default: throw new Error("Not a pcap or pcapng file (unknown magic number). Save the capture with tcpdump -w or as pcap/pcapng.");
  }
}
