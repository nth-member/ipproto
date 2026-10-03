// Builds IPv4/IPv6 packets with correct lengths and checksums, and writes them
// as a classic pcap file (link type 101, raw IP), which tcpdump and Wireshark read.

const be16 = (a, o, v) => { a[o] = (v >>> 8) & 0xff; a[o + 1] = v & 0xff; };
const be32 = (a, o, v) => { a[o] = (v >>> 24) & 0xff; a[o + 1] = (v >>> 16) & 0xff; a[o + 2] = (v >>> 8) & 0xff; a[o + 3] = v & 0xff; };
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

export function parseIPv4(text) { return Uint8Array.from(text.split(".").map(Number)); }
export function parseIPv6(text) {
  const [head, tail] = text.split("::");
  const h = head ? head.split(":") : [], t = tail !== undefined && tail ? tail.split(":") : [];
  const groups = [...h, ...Array(8 - h.length - t.length).fill("0"), ...t].map(g => parseInt(g, 16));
  const out = new Uint8Array(16);
  groups.forEach((g, i) => be16(out, i * 2, g));
  return out;
}

// One's-complement sum of 16-bit words.
export function checksum(...parts) {
  let sum = 0;
  for (const p of parts) {
    for (let i = 0; i + 1 < p.length; i += 2) sum += (p[i] << 8) | p[i + 1];
    if (p.length & 1) sum += p[p.length - 1] << 8;
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return ~sum & 0xffff;
}

export function ipv4({ src, dst, proto, payload, id = 0, ttl = 64 }) {
  const h = new Uint8Array(20);
  h[0] = 0x45; be16(h, 2, 20 + payload.length); be16(h, 4, id & 0xffff);
  h[8] = ttl; h[9] = proto;
  h.set(parseIPv4(src), 12); h.set(parseIPv4(dst), 16);
  be16(h, 10, checksum(h));
  return concat(h, payload);
}

export function ipv6({ src, dst, next, payload, hopLimit = 64 }) {
  const h = new Uint8Array(40);
  h[0] = 0x60; be16(h, 4, payload.length); h[6] = next; h[7] = hopLimit;
  h.set(parseIPv6(src), 8); h.set(parseIPv6(dst), 24);
  return concat(h, payload);
}

function pseudo(src, dst, proto, length, v6) {
  if (v6) {
    const p = new Uint8Array(40);
    p.set(parseIPv6(src), 0); p.set(parseIPv6(dst), 16); be32(p, 32, length); p[39] = proto;
    return p;
  }
  const p = new Uint8Array(12);
  p.set(parseIPv4(src), 0); p.set(parseIPv4(dst), 4); p[9] = proto; be16(p, 10, length);
  return p;
}

export function udp({ src, dst, sport, dport, payload, v6 = false }) {
  const h = new Uint8Array(8);
  be16(h, 0, sport); be16(h, 2, dport); be16(h, 4, 8 + payload.length);
  let c = checksum(pseudo(src, dst, 17, 8 + payload.length, v6), h, payload);
  if (c === 0) c = 0xffff;
  be16(h, 6, c);
  return concat(h, payload);
}

export function tcp({ src, dst, sport, dport, seq, ack = 0, payload, v6 = false }) {
  const h = new Uint8Array(20);
  be16(h, 0, sport); be16(h, 2, dport); be32(h, 4, seq >>> 0); be32(h, 8, ack >>> 0);
  h[12] = 5 << 4; h[13] = 0x18;                        // PSH, ACK
  be16(h, 14, 65535);
  be16(h, 16, checksum(pseudo(src, dst, 6, 20 + payload.length, v6), h, payload));
  return concat(h, payload);
}

export function icmpEcho({ id, seq, payload, v6 = false, src, dst }) {
  const h = new Uint8Array(8);
  h[0] = v6 ? 128 : 8; be16(h, 4, id); be16(h, 6, seq);
  be16(h, 2, v6 ? checksum(pseudo(src, dst, 58, 8 + payload.length, true), h, payload) : checksum(h, payload));
  return concat(h, payload);
}

// An IPv6 extension header (Hop-by-Hop, Routing, Destination Options, Mobility,
// HIP, Shim6, experimental): next header, length in 8-octet units less one,
// then PadN padding to a multiple of eight octets.
export function ipv6Ext(next, body = new Uint8Array(0)) {
  const len = Math.ceil((2 + body.length) / 8) * 8;
  const h = new Uint8Array(len);
  h[0] = next; h[1] = len / 8 - 1;
  h.set(body, 2);
  const pad = len - 2 - body.length;
  if (pad === 1) h[len - 1] = 0;                        // Pad1
  else if (pad >= 2) { h[2 + body.length] = 1; h[3 + body.length] = pad - 2; }   // PadN
  return h;
}
export function ipv6Routing(next) {                     // type 2 (Mobile IPv6), one address: 24 octets
  const h = new Uint8Array(24);
  h[0] = next; h[1] = 2; h[2] = 2; h[3] = 1;
  h.set(parseIPv6("2001:db8::99"), 8);
  return h;
}
export function ipv6Fragment(next, id) {                // a whole packet sent as fragment 0, no more fragments
  const h = new Uint8Array(8);
  h[0] = next; be32(h, 4, id);
  return h;
}
export function ah(next, spi, seq) {                    // RFC 4302: 12-octet ICV, length = 6 (in 4-octet units, less 2)
  const h = new Uint8Array(24);
  h[0] = next; h[1] = 4; be32(h, 4, spi); be32(h, 8, seq);
  return h;
}
export function esp(spi, seq, payload) {                // RFC 4303: SPI, sequence, then ciphertext (opaque here)
  const h = new Uint8Array(8);
  be32(h, 0, spi); be32(h, 4, seq);
  return concat(h, payload);
}
export function gre(ethertype, payload) {               // RFC 2784, no optional fields
  const h = new Uint8Array(4);
  be16(h, 2, ethertype);
  return concat(h, payload);
}
export function ethernet(ethertype, payload) {
  const h = new Uint8Array(14);
  h.set([0x02, 0, 0x5e, 0x10, 0, 0x01], 0); h.set([0x02, 0, 0x5e, 0x10, 0, 0x02], 6);
  be16(h, 12, ethertype);
  return concat(h, payload);
}
export function mplsLabel(label, payload) {             // one label, bottom of stack, TTL 64
  const h = new Uint8Array(4);
  be32(h, 0, ((label & 0xfffff) << 12) | (1 << 8) | 64);
  return concat(h, payload);
}

// packets: [{ ts (seconds), data (Uint8Array) }] -> pcap bytes, link type 101 (raw IP)
export function writePcap(packets, { snaplen = 262144, linktype = 101 } = {}) {
  const total = 24 + packets.reduce((n, p) => n + 16 + p.data.length, 0);
  const out = new Uint8Array(total);
  const v = new DataView(out.buffer);
  v.setUint32(0, 0xa1b2c3d4, true); v.setUint16(4, 2, true); v.setUint16(6, 4, true);
  v.setUint32(16, snaplen, true); v.setUint32(20, linktype, true);
  let o = 24;
  for (const p of packets) {
    const sec = Math.floor(p.ts), usec = Math.round((p.ts - sec) * 1e6);
    v.setUint32(o, sec, true); v.setUint32(o + 4, Math.min(usec, 999999), true);
    v.setUint32(o + 8, p.data.length, true); v.setUint32(o + 12, p.data.length, true);
    out.set(p.data, o + 16);
    o += 16 + p.data.length;
  }
  return out;
}

export { concat };
