// Turns a read capture into the Capture tab's figures: counts per protocol number
// and per category, tunnels, IPv6 extension headers, non-IP traffic, the busiest
// address pairs, a timeline, and flags for anything unusual.
//
// A packet is counted once under every protocol number it contains (a GRE packet
// carrying UDP counts under 47 and under 17) and once under every category those
// numbers belong to; "carried" counts only its innermost protocol.

import { decodePacket, numbersOf, finalOf } from "./decode.mjs";
import { LINKTYPE_NAMES } from "./pcap.mjs";

const TUNNEL_NUMBERS = new Set([4, 41, 47, 94, 97, 137, 143]);
const EXT6 = new Set([0, 43, 44, 51, 60, 135, 139, 140, 253, 254]);

export function analyze(capture, registry, { bins = 60, topTalkers = 12 } = {}) {
  const info = n => registry.numbers[n];
  const perNumber = new Map();                         // n -> { packets, bytes, carried }
  const perCategory = new Map(registry.categories.map(c => [c.id, 0]));
  const nonIp = new Map(), unsupported = new Map(), innerNonIp = new Map(), ext6 = new Map(), tunnelUse = new Map();
  const talkers = new Map();
  let ipPackets = 0, bytes = 0, truncated = 0, snapped = 0, encrypted = 0, fragments = 0, tunnelled = 0, nested = 0, vlanTagged = 0;
  let start = Infinity, end = -Infinity;
  const decoded = [];
  const sequence = [];                                 // carried protocol of each IP packet, in order

  for (const p of capture.packets) {
    bytes += p.origLen;
    if (p.ts !== null) { start = Math.min(start, p.ts); end = Math.max(end, p.ts); }
    const st = decodePacket(p);
    if (st.unsupported !== undefined) { unsupported.set(st.unsupported, (unsupported.get(st.unsupported) ?? 0) + 1); decoded.push(null); continue; }
    if (st.vlans) vlanTagged += 1;
    if (st.truncated) truncated += 1;
    if (st.snapped) snapped += 1;
    if (st.nonIp) { nonIp.set(st.nonIp, (nonIp.get(st.nonIp) ?? 0) + 1); decoded.push(null); continue; }
    if (st.innerNonIp) innerNonIp.set(st.innerNonIp, (innerNonIp.get(st.innerNonIp) ?? 0) + 1);
    if (!st.layers.length) { decoded.push(null); continue; }
    ipPackets += 1;
    if (st.encrypted) encrypted += 1;
    if (st.layers.some(l => l.fragment)) fragments += 1;
    if (st.tunnels.length) tunnelled += 1;
    if (st.tunnels.length > 1) nested += 1;
    for (const t of st.tunnels) tunnelUse.set(t, (tunnelUse.get(t) ?? 0) + 1);

    const nums = new Set(numbersOf(st));
    const fin = finalOf(st);
    const cats = new Set();
    for (const n of nums) {
      const e = perNumber.get(n) ?? { packets: 0, bytes: 0, carried: 0 };
      e.packets += 1; e.bytes += p.origLen;
      perNumber.set(n, e);
      cats.add(info(n).category);
      if (st.layers.some(l => l.version === 6) && EXT6.has(n) && n !== fin) ext6.set(n, (ext6.get(n) ?? 0) + 1);
    }
    if (fin !== null && fin !== undefined) { perNumber.get(fin).carried += 1; sequence.push(fin); }
    for (const c of cats) perCategory.set(c, perCategory.get(c) + 1);

    const outer = st.layers[0];
    const key = `${outer.src} → ${outer.dst}`;
    const t = talkers.get(key) ?? { pair: key, packets: 0, bytes: 0, numbers: new Set() };
    t.packets += 1; t.bytes += p.origLen; nums.forEach(n => t.numbers.add(n));
    talkers.set(key, t);
    decoded.push({ ts: p.ts, cats });
  }

  // Timeline: packets per bin, split by category.
  const span = end > start ? end - start : 0;
  const timeline = { start: Number.isFinite(start) ? start : null, end: Number.isFinite(end) ? end : null, bins: [] };
  if (Number.isFinite(start)) {
    const n = span ? bins : 1;
    for (let i = 0; i < n; i += 1) timeline.bins.push(new Map());
    for (const d of decoded) {
      if (!d || d.ts === null) continue;
      const i = span ? Math.min(n - 1, Math.floor(((d.ts - start) / span) * n)) : 0;
      timeline.bins[i].set("*", (timeline.bins[i].get("*") ?? 0) + 1);   // all packets
      for (const c of d.cats) timeline.bins[i].set(c, (timeline.bins[i].get(c) ?? 0) + 1);
    }
  }

  // Flags.
  const seen = [...perNumber.keys()].sort((a, b) => a - b);
  const label = n => `${n}${info(n).keyword ? ` ${info(n).keyword}` : ""}`;
  const pick = test => seen.filter(n => test(info(n)));
  const flags = [];
  const flag = (level, text, numbers = []) => flags.push({ level, text, numbers });
  const unassigned = pick(x => x.status === "unassigned");
  if (unassigned.length) flag("warn", `Unassigned protocol numbers in use: ${unassigned.join(", ")}. No registered protocol has these numbers.`, unassigned);
  const reserved = pick(x => x.status === "reserved");
  if (reserved.length) flag("warn", "Reserved number 255 in use.", reserved);
  const deprecated = pick(x => x.status === "deprecated");
  if (deprecated.length) flag("warn", `Deprecated protocols: ${deprecated.map(label).join(", ")}.`, deprecated);
  const experimental = pick(x => x.status === "experimental");
  if (experimental.length) flag("note", `Experimental numbers (RFC 3692): ${experimental.join(", ")}. Valid for testing, not for deployed protocols.`, experimental);
  const placeholder = pick(x => x.status === "placeholder");
  if (placeholder.length) flag("note", `Placeholder numbers ("any …" protocols): ${placeholder.map(label).join(", ")}.`, placeholder);
  const historic = pick(x => x.status === "historic");
  if (historic.length) flag("note", `Historic protocols, rarely seen on present-day networks: ${historic.map(label).join(", ")}.`, historic);
  if (nested) flag("note", `${nested} packet(s) carry a tunnel inside a tunnel.`);
  if (perNumber.has(43)) flag("note", "IPv6 Routing headers (43) present. Type 0 routing headers are deprecated (RFC 5095) and commonly filtered.", [43]);
  if (encrypted) flag("info", `${encrypted} packet(s) are ESP-encrypted: nothing inside them can be read.`);
  if (fragments) flag("info", `${fragments} packet(s) are fragments.`);
  if (truncated) flag("info", `${truncated} packet(s) end before their headers do.`);
  if (snapped) flag("info", `${snapped} packet(s) were captured shorter than sent (snap length).`);
  for (const [lt, c] of unsupported) flag("info", `${c} packet(s) use link type ${lt}${LINKTYPE_NAMES[lt] ? ` (${LINKTYPE_NAMES[lt]})` : ""}, which this page does not decode.`);

  return {
    format: capture.format, linktypes: capture.linktypes, truncatedFile: capture.truncatedFile,
    packets: capture.packets.length, ipPackets, bytes, start: timeline.start, end: timeline.end,
    perNumber, perCategory, nonIp, innerNonIp, unsupported, ext6, tunnelUse,
    tunnelled, nested, encrypted, fragments, truncated, snapped, vlanTagged,
    talkers: [...talkers.values()].sort((a, b) => b.bytes - a.bytes).slice(0, topTalkers),
    timeline, flags, sequence
  };
}

export { TUNNEL_NUMBERS };
