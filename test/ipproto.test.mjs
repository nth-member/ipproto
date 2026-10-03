import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { readCapture } from "../docs/lib/pcap.mjs";
import { decodePacket, numbersOf, finalOf } from "../docs/lib/decode.mjs";
import { analyze } from "../docs/lib/analyze.mjs";
import { buildCapture, REPRESENTATIVES } from "../docs/lib/bridge.mjs";
import { ipv4, ipv6, udp, tcp, icmpEcho, ah, gre, ethernet, writePcap, concat, checksum } from "../docs/lib/pcapwrite.mjs";
import { colors8, document8, decode8 } from "../docs/lib/colour8.mjs";
import { grammar } from "../docs/lib/grammar.mjs";

const reg = JSON.parse(readFileSync(new URL("../docs/data/protocols.json", import.meta.url)));
const hasTcpdump = (() => { try { execFileSync("tcpdump", ["--version"], { stdio: "ignore" }); return true; } catch { return false; } })();
const dir = mkdtempSync(join(tmpdir(), "ipproto-test-"));
test.after(() => rmSync(dir, { recursive: true, force: true }));
const tcpdump = (file, filter = "") => execFileSync("tcpdump", ["-nn", "-r", file, ...(filter ? [filter] : [])], { stdio: ["ignore", "pipe", "ignore"] }).toString().split("\n").filter(Boolean);
const capOf = bytes => readCapture(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));

const A = "192.0.2.1", B = "198.51.100.2";
const udp4 = payload => ipv4({ src: A, dst: B, proto: 17, payload: udp({ src: A, dst: B, sport: 5000, dport: 53, payload }) });
const P = Uint8Array.from("HELLO", c => c.charCodeAt(0));

// ---------- registry ----------
test("registry: 256 numbers, 13 categories, every number in exactly one", () => {
  assert.equal(reg.numbers.length, 256);
  assert.equal(reg.categories.length, 13);
  const ids = new Set(reg.categories.map(c => c.id));
  for (const x of reg.numbers) assert.ok(ids.has(x.category), `${x.n}`);
  assert.equal(reg.numbers.filter(x => x.status === "unassigned").length, 105);
  assert.deepEqual([6, 17, 47, 50, 253].map(n => reg.numbers[n].category), ["transport", "transport", "tunnel", "security", "special"]);
  assert.ok(reg.numbers.every(x => !("references" in x)), "registrants' names are not republished");
});

// ---------- capture formats and link layers ----------
function pcapBigEndianNano(packets, linktype) {
  const total = 24 + packets.reduce((n, p) => n + 16 + p.length, 0);
  const out = new Uint8Array(total), v = new DataView(out.buffer);
  v.setUint32(0, 0xa1b23c4d, false); v.setUint16(4, 2, false); v.setUint16(6, 4, false);
  v.setUint32(16, 65535, false); v.setUint32(20, linktype, false);
  let o = 24;
  packets.forEach((p, i) => { v.setUint32(o, 100 + i, false); v.setUint32(o + 4, 500000000, false); v.setUint32(o + 8, p.length, false); v.setUint32(o + 12, p.length, false); out.set(p, o + 16); o += 16 + p.length; });
  return out;
}
function pcapng(packets, linktype) {
  const blocks = [];
  const block = (type, body) => {
    const len = 12 + Math.ceil(body.length / 4) * 4;
    const b = new Uint8Array(len), v = new DataView(b.buffer);
    v.setUint32(0, type, true); v.setUint32(4, len, true); b.set(body, 8); v.setUint32(len - 4, len, true);
    blocks.push(b);
  };
  const shb = new Uint8Array(16), sv = new DataView(shb.buffer);
  sv.setUint32(0, 0x1a2b3c4d, true); sv.setUint16(4, 1, true); sv.setUint16(6, 0, true); sv.setInt32(8, -1, true); sv.setInt32(12, -1, true);
  block(0x0a0d0d0a, shb);
  const idb = new Uint8Array(16), iv = new DataView(idb.buffer);              // if_tsresol = 9 (nanoseconds)
  iv.setUint16(0, linktype, true); iv.setUint32(4, 65535, true); iv.setUint16(8, 9, true); iv.setUint16(10, 1, true); idb[12] = 9;
  block(0x00000001, idb);
  packets.forEach((p, i) => {
    const body = new Uint8Array(20 + p.length), bv = new DataView(body.buffer);
    const ts = BigInt(1_000_000_000 + i) * 1_000_000_000n;
    bv.setUint32(0, 0, true); bv.setUint32(4, Number(ts >> 32n), true); bv.setUint32(8, Number(ts & 0xffffffffn), true);
    bv.setUint32(12, p.length, true); bv.setUint32(16, p.length, true); body.set(p, 20);
    block(0x00000006, body);
  });
  return concat(...blocks);
}
const sll = (type, payload) => { const h = new Uint8Array(16); h[15 - 1] = type >> 8; h[15] = type & 0xff; return concat(h, payload); };
const sll2 = (type, payload) => { const h = new Uint8Array(20); h[0] = type >> 8; h[1] = type & 0xff; return concat(h, payload); };
const vlan = (id, type, payload) => {
  const h = new Uint8Array(18);
  h.set([2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2], 0); h[12] = 0x81; h[13] = 0x00; h[14] = id >> 8; h[15] = id & 0xff; h[16] = type >> 8; h[17] = type & 0xff;
  return concat(h, payload);
};
const nullLE = payload => concat(Uint8Array.of(2, 0, 0, 0), payload);
const arp = ethernet(0x0806, new Uint8Array(28));

const FORMATS = [
  { name: "Ethernet with VLAN, and ARP", linktype: 1, packets: [vlan(42, 0x0800, udp4(P)), arp], expect: [{ final: 17, vlan: true }, { nonIp: "ARP" }] },
  { name: "Linux SLL", linktype: 113, packets: [sll(0x0800, ipv4({ src: A, dst: B, proto: 6, payload: tcp({ src: A, dst: B, sport: 40000, dport: 443, seq: 1, payload: P }) }))], expect: [{ final: 6 }] },
  { name: "Linux SLL2 with IPv6 ICMPv6", linktype: 276, packets: [sll2(0x86dd, ipv6({ src: "2001:db8::1", dst: "2001:db8::2", next: 58, payload: icmpEcho({ id: 1, seq: 1, payload: P, v6: true, src: "2001:db8::1", dst: "2001:db8::2" }) }))], expect: [{ final: 58 }] },
  { name: "BSD loopback", linktype: 0, packets: [nullLE(udp4(P))], expect: [{ final: 17 }] },
  { name: "GRE with a key, around IPv4", linktype: 101, packets: [ipv4({ src: A, dst: B, proto: 47, payload: concat(Uint8Array.of(0x20, 0, 0x08, 0, 0, 0, 0, 7), udp4(P)) })], expect: [{ final: 17, numbers: [47, 17], tunnels: [47] }] },
  { name: "IPv4 AH then UDP", linktype: 101, packets: [ipv4({ src: A, dst: B, proto: 51, payload: concat(ah(17, 1, 1), udp({ src: A, dst: B, sport: 1, dport: 2, payload: P })) })], expect: [{ final: 17, numbers: [51, 17] }] }
];

for (const f of FORMATS) {
  for (const [kind, bytes] of [["pcap", writePcap(f.packets.map((data, i) => ({ ts: 10 + i, data })), { linktype: f.linktype })], ["pcap big-endian ns", pcapBigEndianNano(f.packets, f.linktype)], ["pcapng ns", pcapng(f.packets, f.linktype)]]) {
    test(`${f.name}: ${kind}`, () => {
      const cap = capOf(bytes);
      assert.equal(cap.packets.length, f.packets.length);
      cap.packets.forEach((p, i) => {
        const st = decodePacket(p), e = f.expect[i];
        if (e.nonIp) { assert.equal(st.nonIp, e.nonIp); return; }
        assert.equal(finalOf(st), e.final);
        if (e.numbers) assert.deepEqual(numbersOf(st), e.numbers);
        if (e.tunnels) assert.deepEqual(st.tunnels, e.tunnels);
        if (e.vlan) assert.deepEqual(st.vlans, [42]);
      });
      if (kind !== "pcap") assert.ok(cap.packets[0].ts > 99, "timestamps read");
      if (hasTcpdump) {
        const file = join(dir, `${f.linktype}-${kind.replace(/\W/g, "")}.cap`);
        writeFileSync(file, bytes);
        assert.equal(tcpdump(file).length, f.packets.length, "tcpdump reads the same number of packets");
      }
    });
  }
}

test("a non-first IPv4 fragment stops decoding; ESP is not looked into", () => {
  const frag = ipv4({ src: A, dst: B, proto: 17, payload: P });
  frag[6] = 0x00; frag[7] = 0x10;                                   // offset 16 octets
  frag[10] = frag[11] = 0; const c = checksum(frag.subarray(0, 20)); frag[10] = c >> 8; frag[11] = c & 0xff;
  const st = decodePacket({ data: frag, linktype: 101, origLen: frag.length });
  assert.equal(st.layers[0].fragment, true);
  assert.equal(st.layers[0].ports, undefined);
  const esp = decodePacket({ data: ipv4({ src: A, dst: B, proto: 50, payload: P }), linktype: 101, origLen: 25 });
  assert.equal(esp.encrypted, true);
});

test("non-capture files are refused", () => {
  assert.throws(() => readCapture(new Uint8Array(64).buffer), /Not a pcap/);
  assert.throws(() => readCapture(new Uint8Array(4).buffer), /too short/);
});

// ---------- bridge: all 13 categories, checked against tcpdump ----------
test("bridge: every number 0-255 decodes as tcpdump reads it, and covers all 13 categories", { timeout: 120000 }, () => {
  const r = buildCapture({ model: "asr33", seed: 7, size: 256 * 72, numbers: reg.numbers.map(x => x.n) });
  assert.equal(r.packets, 256);
  const cap = capOf(r.pcap);
  const a = analyze(cap, reg);
  assert.equal([...a.perCategory.values()].filter(v => v > 0).length, 13);
  assert.deepEqual([...a.tunnelUse.keys()].sort((x, y) => x - y), [4, 41, 47, 94, 97, 137, 143]);
  assert.deepEqual([...a.ext6.keys()].sort((x, y) => x - y), [0, 43, 44, 60, 135, 139, 140]);
  assert.equal(a.encrypted, 1);
  if (!hasTcpdump) return;
  const file = join(dir, "all256.pcap");
  writeFileSync(file, r.pcap);
  const v4 = new Map(), v6 = new Map();
  for (const p of cap.packets) { const l = decodePacket(p).layers[0]; const m = l.version === 4 ? v4 : v6; m.set(l.numbers[0], (m.get(l.numbers[0]) ?? 0) + 1); }
  for (let n = 0; n < 256; n += 1) {
    assert.equal(tcpdump(file, `ip[9] == ${n}`).length, v4.get(n) ?? 0, `IPv4 protocol ${n}`);
    assert.equal(tcpdump(file, `ip6[6] == ${n}`).length, v6.get(n) ?? 0, `IPv6 next header ${n}`);
  }
  const bad = execFileSync("tcpdump", ["-nn", "-vv", "-r", file], { stdio: ["ignore", "pipe", "ignore"] }).toString()
    .split("\n").filter(l => /bad|incorrect/i.test(l));
  // Only the raw-payload protocols (IGMP 2, DCCP 33, Minimal IPv4 55) are read by tcpdump as headers with "checksums".
  assert.ok(bad.length <= 3 && bad.every(l => /igmp|DCCP|mobile/.test(l)), bad.join("\n"));
});

test("bridge: one number per category gives all 13 categories", () => {
  const nums = reg.categories.map(c => REPRESENTATIVES[c.id]);
  assert.equal(new Set(nums.map(n => reg.numbers[n].category)).size, 13);
  const a = analyze(capOf(buildCapture({ model: "asr37", seed: 3, size: 13 * 72 * 2, numbers: nums }).pcap), reg);
  assert.equal([...a.perCategory.values()].filter(v => v > 0).length, 13);
});

test("bridge: packets are paced at the teletype's speed, from 1 June 1971", () => {
  const cap = capOf(buildCapture({ model: "asr33", seed: 1, size: 720, chunk: 72, numbers: [17] }).pcap);
  assert.equal(new Date(cap.packets[0].ts * 1000).toISOString(), "1971-06-01T09:00:00.000Z");
  assert.ok(Math.abs(cap.packets[1].ts - cap.packets[0].ts - 7.2) < 1e-6, "72 characters at 10 per second");
});

test("analysis flags unassigned, deprecated, experimental and historic numbers", () => {
  const a = analyze(capOf(buildCapture({ model: "asr33", seed: 2, size: 5 * 72, numbers: [200, 13, 253, 16, 6] }).pcap), reg);
  const text = a.flags.map(f => f.text).join("\n");
  assert.match(text, /Unassigned protocol numbers in use: 200/);
  assert.match(text, /Deprecated protocols: 13 ARGUS/);
  assert.match(text, /Experimental numbers.*253/);
  assert.match(text, /Historic.*16 CHAOS/);
  assert.equal(a.sequence.length, 5);
});

// ---------- colours ----------
test("8-bit colours: 0-127 equal Gigaspeak's Calc28, all 256 distinct, round-trip", () => {
  const g = grammar("calc28-span");
  for (let n = 0; n < 128; n += 1) {
    const a = colors8(n), b = g.colorsForByte(n);
    assert.deepEqual([a.foreground, a.background], [b.foreground, b.background]);
  }
  assert.equal(new Set(reg.numbers.map(x => JSON.stringify(colors8(x.n)))).size, 256);
  const all = reg.numbers.map(x => x.n);
  assert.deepEqual(decode8(document8(all)), all);
  assert.throws(() => colors8(256), RangeError);
});

test("the copied Gigaspeak grammar matches Gigaspeak's own, when it is beside this repository", { skip: (() => { try { readFileSync(new URL("../../gigaspeak/docs/lib/grammar.mjs", import.meta.url)); return false; } catch { return "gigaspeak not beside this repository"; } })() }, async () => {
  const theirs = await import(new URL("../../gigaspeak/docs/lib/grammar.mjs", import.meta.url));
  for (const g of theirs.GRAMMARS) for (let b = 0; b < 128; b += 1) assert.equal(grammar(g.id).tokenForByte(b), theirs.grammar(g.id).tokenForByte(b));
});
