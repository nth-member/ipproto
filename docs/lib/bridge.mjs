// Teletype-to-packet bridge: a 1971 Teletype Model 33 or 37 stream (teletype.mjs,
// the byte-exact port of tools/asr33_gen.py and asr37_gen.py) cut into packets,
// each carried by one IP protocol number, written as a pcap file.
//
// Where a protocol has a structure, the packet has it: TCP to port 23 (Telnet),
// UDP, ICMP and ICMPv6 echo; IP-in-IP, IPv6-in-IP, GRE, EtherIP, Ethernet and
// MPLS tunnels around an inner UDP packet; ESP and AH; IPv6 packets with real
// extension-header chains for the IPv6 machinery and mobility numbers. Every
// other number carries the teletype bytes directly after an IPv4 header.
// Addresses are from the documentation ranges (RFC 5737, RFC 3849).

import { generate } from "./teletype.mjs";
import { ipv4, ipv6, udp, tcp, icmpEcho, ipv6Ext, ipv6Routing, ipv6Fragment, ah, esp, gre, ethernet, mplsLabel, writePcap, concat } from "./pcapwrite.mjs";

const A = "192.0.2.10", B = "198.51.100.20";           // outer IPv4 (TEST-NET-1, TEST-NET-2)
const IA = "203.0.113.10", IB = "203.0.113.20";        // inner IPv4 (TEST-NET-3)
const A6 = "2001:db8::10", B6 = "2001:db8::20";         // IPv6 documentation prefix
const PORT = 1971, TELNET = 23;
const CPS = { asr33: 10, asr37: 15 };                   // characters per second: 110 and 150 baud
export const START = Date.UTC(1971, 5, 1, 9, 0, 0) / 1000;   // 1 June 1971, 09:00 UTC

// One number per category, for a compact capture that still covers all 13.
export const REPRESENTATIVES = { core: 1, transport: 6, routing: 89, multicast: 103, tunnel: 47, security: 50, mobility: 135, qos: 46, resolution: 54, monitoring: 20, arpa: 11, vendor: 16, special: 253 };

const innerUdp4 = payload => ipv4({ src: IA, dst: IB, proto: 17, payload: udp({ src: IA, dst: IB, sport: PORT, dport: PORT, payload }) });
const innerUdp6 = payload => ipv6({ src: A6, dst: B6, next: 17, payload: udp({ src: A6, dst: B6, sport: PORT, dport: PORT, payload, v6: true }) });

// The IP packet that carries `chunk` with protocol number n.
export function frame(n, chunk, ctx) {
  const id = ctx.id++;
  const v4 = (proto, payload) => ipv4({ src: A, dst: B, proto, payload, id });
  const v6 = (next, payload) => ipv6({ src: A6, dst: B6, next, payload });
  const u6 = () => udp({ src: A6, dst: B6, sport: PORT, dport: PORT, payload: chunk, v6: true });
  switch (n) {
    case 1: return v4(1, icmpEcho({ id: 1971, seq: id & 0xffff, payload: chunk }));
    case 6: {
      const seg = tcp({ src: A, dst: B, sport: 49152, dport: TELNET, seq: ctx.seq, ack: 1, payload: chunk });
      ctx.seq = (ctx.seq + chunk.length) >>> 0;
      return v4(6, seg);
    }
    case 17: return v4(17, udp({ src: A, dst: B, sport: PORT, dport: PORT, payload: chunk }));
    case 4: case 94: return v4(n, innerUdp4(chunk));
    case 41: return v4(41, innerUdp6(chunk));
    case 47: return v4(47, gre(0x0800, innerUdp4(chunk)));
    case 97: return v4(97, concat(Uint8Array.of(0x30, 0x00), ethernet(0x0800, innerUdp4(chunk))));
    case 143: return v4(143, ethernet(0x0800, innerUdp4(chunk)));
    case 137: return v4(137, mplsLabel(1971, innerUdp4(chunk)));
    case 50: return v4(50, esp(0x1971, id, chunk));
    case 51: return v4(51, concat(ah(17, 0x1971, id), udp({ src: A, dst: B, sport: PORT, dport: PORT, payload: chunk })));
    // IPv6 machinery and mobility: genuine extension-header chains in IPv6
    case 0: case 60: case 140: return v6(n, concat(ipv6Ext(17), u6()));
    // With a Routing header, the upper-layer checksum uses the final destination,
    // the address in the header (RFC 8200, 8.1).
    case 43: return v6(43, concat(ipv6Routing(17), udp({ src: A6, dst: "2001:db8::99", sport: PORT, dport: PORT, payload: chunk, v6: true })));
    case 44: return v6(44, concat(ipv6Fragment(17, id), u6()));
    case 58: return v6(58, icmpEcho({ id: 1971, seq: id & 0xffff, payload: chunk, v6: true, src: A6, dst: B6 }));
    case 59: return v6(59, chunk);
    case 135: case 139: return v6(n, ipv6Ext(59, chunk));       // Mobility Header and HIP carry "no next header"
    default: return v4(n, chunk);
  }
}

// numbers: the protocol numbers to cycle through, in order.
export function buildCapture({ model = "asr33", seed, size = 65536, chunk = 72, numbers }) {
  if (!numbers?.length) throw new Error("Choose at least one protocol number");
  if (!Number.isInteger(chunk) || chunk < 1 || chunk > 2000) throw new RangeError("Packet payload must be 1 to 2,000 bytes");
  const stream = generate(model, { seed, size });
  const ctx = { id: 1, seq: 1000 };
  const packets = [], counts = new Map();
  let ts = START;
  for (let off = 0, i = 0; off < stream.bytes.length; off += chunk, i += 1) {
    const part = stream.bytes.subarray(off, off + chunk);
    const n = numbers[i % numbers.length];
    packets.push({ ts, data: frame(n, part, ctx) });
    counts.set(n, (counts.get(n) ?? 0) + 1);
    ts += part.length / CPS[model];
  }
  return { pcap: writePcap(packets), packets: packets.length, counts, seed: stream.seed, sessions: stream.sessions.length };
}
