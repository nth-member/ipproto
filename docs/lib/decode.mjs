// Decodes one captured packet down through its IP layers and records every IP
// protocol number it meets, outermost first:
//
//   link layer  Ethernet (with 802.1Q/802.1ad tags), Linux SLL and SLL2, raw IP,
//               BSD/OpenBSD loopback
//   IPv4        the Protocol field; AH (51) is skipped to the protocol after it;
//               a non-first fragment carries no header, so decoding stops there
//   IPv6        the Next Header chain through Hop-by-Hop (0), Routing (43),
//               Fragment (44), Destination Options (60), AH (51), Mobility (135),
//               HIP (139), Shim6 (140) and the experimental 253/254
//   tunnels     IPv4-in-IP (4, 94), IPv6-in-IP (41), GRE (47, including Ethernet
//               bridging), EtherIP (97), MPLS-in-IP (137), Ethernet (143);
//               the inner packet is decoded the same way
//
// ESP (50) is encrypted, so nothing after it can be read. Everything else is
// counted by its number and left undecoded.

export const ETHERTYPES = { 0x0800: "IPv4", 0x86dd: "IPv6", 0x0806: "ARP", 0x8035: "RARP", 0x88cc: "LLDP", 0x8847: "MPLS", 0x8848: "MPLS multicast", 0x888e: "EAPOL", 0x8863: "PPPoE discovery", 0x8864: "PPPoE session", 0x88f7: "PTP", 0x22f0: "AVTP", 0x8892: "PROFINET", 0x0842: "Wake-on-LAN" };
const IPV6_EXT = new Set([0, 43, 44, 60, 135, 139, 140, 253, 254]);
const MAX_DEPTH = 8;

const ipv4Text = (d, o) => `${d[o]}.${d[o + 1]}.${d[o + 2]}.${d[o + 3]}`;
function ipv6Text(d, o) {
  const g = [];
  for (let i = 0; i < 16; i += 2) g.push(((d[o + i] << 8) | d[o + i + 1]).toString(16));
  // collapse the longest run of zero groups
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== "0") { i += 1; continue; }
    let j = i; while (j < 8 && g[j] === "0") j += 1;
    if (j - i > bestLen && j - i > 1) { best = i; bestLen = j - i; }
    i = j;
  }
  if (best < 0) return g.join(":");
  return `${g.slice(0, best).join(":")}::${g.slice(best + bestLen).join(":")}`;
}
const u16 = (d, o) => (d[o] << 8) | d[o + 1];

// Link layer -> { ethertype, offset } or { nonIp: name }.
function linkLayer(d, linktype) {
  switch (linktype) {
    case 1: return ethernet(d, 0);
    case 12: case 14: case 101: return { ethertype: d.length && d[0] >> 4 === 6 ? 0x86dd : 0x0800, offset: 0 };
    case 228: return { ethertype: 0x0800, offset: 0 };
    case 229: return { ethertype: 0x86dd, offset: 0 };
    case 0: case 108: {
      if (d.length < 4) return { truncated: true };
      const fam = linktype === 108 ? (d[0] << 24 | d[1] << 16 | d[2] << 8 | d[3]) >>> 0 : (d[0] | d[1] << 8 | d[2] << 16 | d[3] << 24) >>> 0;
      const fam2 = fam > 0xffff ? ((fam >>> 24) | ((fam >>> 8) & 0xff00)) : fam;      // other byte order
      const f = [2, 24, 28, 30].includes(fam) ? fam : fam2;
      if (f === 2) return { ethertype: 0x0800, offset: 4 };
      if (f === 24 || f === 28 || f === 30) return { ethertype: 0x86dd, offset: 4 };
      return { nonIp: `loopback family ${fam}` };
    }
    case 113: return d.length < 16 ? { truncated: true } : { ethertype: u16(d, 14), offset: 16 };
    case 276: return d.length < 20 ? { truncated: true } : { ethertype: u16(d, 0), offset: 20 };
    default: return { unsupported: linktype };
  }
}

function ethernet(d, o) {
  if (d.length < o + 14) return { truncated: true };
  let type = u16(d, o + 12), off = o + 14;
  const vlans = [];
  while ((type === 0x8100 || type === 0x88a8 || type === 0x9100) && d.length >= off + 4) {
    vlans.push(u16(d, off) & 0x0fff);
    type = u16(d, off + 2); off += 4;
  }
  if (type < 0x0600) return { nonIp: "802.3 / LLC", vlans };
  return { ethertype: type, offset: off, vlans };
}

// Decodes from an ethertype at offset; appends to state.
function fromEthertype(d, type, off, st) {
  if (type === 0x0800) return ipv4(d, off, st);
  if (type === 0x86dd) return ipv6(d, off, st);
  if (type === 0x8847 || type === 0x8848) return mpls(d, off, st);
  if (st.layers.length === 0) st.nonIp = ETHERTYPES[type] ?? `EtherType 0x${type.toString(16).padStart(4, "0")}`;
  else st.innerNonIp = ETHERTYPES[type] ?? `EtherType 0x${type.toString(16).padStart(4, "0")}`;
}

function mpls(d, off, st) {
  while (d.length >= off + 4) {
    const bottom = d[off + 2] & 1;
    off += 4;
    if (bottom) break;
  }
  if (d.length <= off) { st.truncated = true; return; }
  const v = d[off] >> 4;
  if (v === 4) return ipv4(d, off, st);
  if (v === 6) return ipv6(d, off, st);
}

function ipv4(d, off, st) {
  if (st.layers.length >= MAX_DEPTH) return;
  if (d.length < off + 20 || d[off] >> 4 !== 4) { st.truncated = true; return; }
  const ihl = (d[off] & 0x0f) * 4;
  const total = u16(d, off + 2);
  const fragOffset = u16(d, off + 6) & 0x1fff;
  const moreFragments = (d[off + 6] & 0x20) !== 0;
  let proto = d[off + 9];
  const layer = { version: 4, src: ipv4Text(d, off + 12), dst: ipv4Text(d, off + 16), length: total, numbers: [proto], fragment: fragOffset > 0 || moreFragments };
  st.layers.push(layer);
  let p = off + ihl;
  if (fragOffset > 0) return;                         // a later fragment: no upper header here
  if (proto === 51 && d.length >= p + 2) {           // AH in IPv4: skip to the protected protocol
    const next = d[p], len = (d[p + 1] + 2) * 4;
    proto = next; layer.numbers.push(proto); p += len;
  }
  return upper(d, proto, p, st, layer);
}

function ipv6(d, off, st) {
  if (st.layers.length >= MAX_DEPTH) return;
  if (d.length < off + 40 || d[off] >> 4 !== 6) { st.truncated = true; return; }
  let next = d[off + 6];
  const layer = { version: 6, src: ipv6Text(d, off + 8), dst: ipv6Text(d, off + 24), length: 40 + u16(d, off + 4), numbers: [next], fragment: false };
  st.layers.push(layer);
  let p = off + 40;
  for (let guard = 0; guard < 16; guard += 1) {
    if (IPV6_EXT.has(next)) {
      if (d.length < p + 8) { st.truncated = true; return; }
      if (next === 44) {
        const fo = u16(d, p + 2) >> 3;
        layer.fragment = true;
        next = d[p]; p += 8; layer.numbers.push(next);
        if (fo > 0) return;
        continue;
      }
      const len = (d[p + 1] + 1) * 8;
      next = d[p]; p += len; layer.numbers.push(next);
      continue;
    }
    if (next === 51) {                                 // AH: length in 4-octet units, plus 2
      if (d.length < p + 2) { st.truncated = true; return; }
      const len = (d[p + 1] + 2) * 4;
      next = d[p]; p += len; layer.numbers.push(next);
      continue;
    }
    break;
  }
  return upper(d, next, p, st, layer);
}

// The protocol after the IP header(s): tunnels are opened, the rest recorded.
function upper(d, proto, p, st, layer) {
  layer.final = proto;
  if (proto === 59) return;                            // no next header
  switch (proto) {
    case 4: case 94: st.tunnels.push(proto); return ipv4(d, p, st);
    case 41: st.tunnels.push(proto); return ipv6(d, p, st);
    case 47: return gre(d, p, st);
    case 97: {                                          // EtherIP: 2-octet header, then Ethernet
      st.tunnels.push(97);
      const e = ethernet(d, p + 2);
      if (e.truncated) { st.truncated = true; return; }
      if (e.nonIp) { st.innerNonIp = e.nonIp; return; }
      return fromEthertype(d, e.ethertype, e.offset, st);
    }
    case 137: st.tunnels.push(137); return mpls(d, p, st);
    case 143: {
      st.tunnels.push(143);
      const e = ethernet(d, p);
      if (e.truncated) { st.truncated = true; return; }
      if (e.nonIp) { st.innerNonIp = e.nonIp; return; }
      return fromEthertype(d, e.ethertype, e.offset, st);
    }
    case 50: st.encrypted = true; return;
    default:
      if (proto === 6 && d.length >= p + 4) layer.ports = [u16(d, p), u16(d, p + 2)];
      if (proto === 17 && d.length >= p + 4) layer.ports = [u16(d, p), u16(d, p + 2)];
      if (proto === 132 && d.length >= p + 4) layer.ports = [u16(d, p), u16(d, p + 2)];
  }
}

function gre(d, p, st) {
  st.tunnels.push(47);
  if (d.length < p + 4) { st.truncated = true; return; }
  const flags = d[p], version = d[p + 1] & 0x07, type = u16(d, p + 2);
  let o = p + 4;
  if (version === 1) { o += 4; if (flags & 0x10) o += 4; if (d[p + 1] & 0x80) o += 4; st.innerNonIp = "PPP (PPTP)"; return; }
  if (flags & 0x80) o += 4;                            // checksum + reserved
  if (flags & 0x20) o += 4;                            // key
  if (flags & 0x10) o += 4;                            // sequence number
  if (type === 0x6558) {                               // transparent Ethernet bridging
    const e = ethernet(d, o);
    if (e.truncated) { st.truncated = true; return; }
    if (e.nonIp) { st.innerNonIp = e.nonIp; return; }
    return fromEthertype(d, e.ethertype, e.offset, st);
  }
  return fromEthertype(d, type, o, st);
}

// -> { layers: [{version, src, dst, numbers[], final, fragment, ports?}], tunnels[], nonIp?, innerNonIp?, encrypted?, truncated?, unsupported?, vlans? }
export function decodePacket(packet) {
  const st = { layers: [], tunnels: [] };
  const d = packet.data;
  const link = linkLayer(d, packet.linktype);
  if (link.unsupported !== undefined) { st.unsupported = link.unsupported; return st; }
  if (link.truncated) { st.truncated = true; return st; }
  if (link.vlans?.length) st.vlans = link.vlans;
  if (link.nonIp) { st.nonIp = link.nonIp; return st; }
  fromEthertype(d, link.ethertype, link.offset, st);
  if (packet.origLen > d.length && !st.truncated) st.snapped = true;
  return st;
}

// Every protocol number in the packet, outermost first.
export const numbersOf = st => st.layers.flatMap(l => l.numbers);
// The innermost upper-layer protocol: what the packet ultimately carries.
export const finalOf = st => (st.layers.length ? st.layers[st.layers.length - 1].final ?? st.layers[st.layers.length - 1].numbers.at(-1) : null);
