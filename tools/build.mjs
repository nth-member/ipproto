#!/usr/bin/env node
// Builds docs/data/protocols.json from IANA's "Assigned Internet Protocol Numbers".
//
//   node tools/build.mjs            fetch the registry from iana.org
//   node tools/build.mjs FILE.csv   use a saved copy of the CSV
//
// The build is idempotent: the file records IANA's own "updated" date, not the
// time of the run, so an unchanged registry rebuilds to an identical file.
// The 13 categories are this site's grouping; IANA publishes the numbers without one.

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const CSV_URL = "https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv";
const XML_URL = "https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml";

export const CATEGORIES = [
  { id: "core", title: "Core control and IPv6 machinery", numbers: [0, 1, 2, 43, 44, 58, 59, 60] },
  { id: "transport", title: "Transport protocols", numbers: [6, 17, 18, 27, 28, 29, 30, 33, 34, 36, 39, 40, 81, 82, 92, 105, 113, 118, 121, 123, 126, 127, 132, 136, 146] },
  { id: "routing", title: "Routing and router redundancy", numbers: [3, 8, 9, 35, 38, 42, 45, 48, 85, 86, 88, 89, 112, 124, 138] },
  { id: "multicast", title: "Multicast", numbers: [7, 103, 122] },
  { id: "tunnel", title: "Tunnelling and encapsulation", numbers: [4, 41, 47, 55, 93, 94, 97, 98, 102, 111, 115, 131, 133, 137, 143, 144, 145, 147] },
  { id: "security", title: "Security and encryption", numbers: [50, 51, 52, 53, 56, 57, 65, 70, 96, 130, 141] },
  { id: "mobility", title: "Mobility and multihoming", numbers: [95, 135, 139, 140] },
  { id: "qos", title: "Quality of service, label switching, compression", numbers: [46, 84, 101, 104, 108, 134, 142] },
  { id: "resolution", title: "Address resolution", numbers: [54, 91] },
  { id: "monitoring", title: "Monitoring and measurement", numbers: [10, 13, 15, 19, 20, 21, 69, 73, 76, 78] },
  { id: "arpa", title: "Early ARPA/DARPA research networks", numbers: [5, 11, 14, 23, 24, 25, 26, 31, 32, 62, 64, 67, 71, 75, 79] },
  { id: "vendor", title: "Vendor and non-IP network stacks", numbers: [12, 16, 22, 37, 49, 66, 72, 74, 77, 80, 83, 87, 90, 100, 106, 107, 109, 110, 116, 117, 119, 120, 125, 128, 129] },
  { id: "special", title: "Placeholders, experiments, reserved, unassigned", numbers: [61, 63, 68, 99, 114, 253, 254, 255] }
];

// Seen on present-day networks: this site's judgement, shown as such.
export const COMMON = [0, 1, 2, 4, 6, 17, 41, 43, 44, 47, 50, 51, 58, 59, 60, 88, 89, 103, 112, 115, 132, 137];
const HISTORIC = new Set(["arpa", "vendor", "monitoring"]);

// A small CSV reader: quoted fields may hold commas, quotes ("") and newlines.
function parseCsv(text) {
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i += 1; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i += 1;
      row.push(field); rows.push(row); row = []; field = "";
    } else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows.filter(r => r.some(f => f.trim() !== ""));
}

const clean = s => s.replace(/\s+/g, " ").trim();

export function buildData(csvText, updated) {
  const rows = parseCsv(csvText);
  const header = rows.shift().map(h => h.trim());
  const col = name => header.indexOf(name);
  const [cDec, cKey, cProto, cExt, cRef] = ["Decimal", "Keyword", "Protocol", "IPv6 Extension Header", "Reference"].map(col);
  if ([cDec, cKey, cProto, cExt, cRef].some(i => i < 0)) throw new Error(`Unexpected CSV header: ${header.join(",")}`);

  const category = new Map();
  for (const c of CATEGORIES) for (const n of c.numbers) {
    if (category.has(n)) throw new Error(`Number ${n} is in two categories`);
    category.set(n, c.id);
  }
  const common = new Set(COMMON);
  const numbers = [];
  for (const r of rows) {
    const dec = r[cDec].trim();
    const range = dec.match(/^(\d+)-(\d+)$/);
    const [lo, hi] = range ? [Number(range[1]), Number(range[2])] : [Number(dec), Number(dec)];
    if (!Number.isInteger(lo) || !Number.isInteger(hi)) throw new Error(`Bad Decimal field: ${dec}`);
    for (let n = lo; n <= hi; n += 1) {
      const keywordRaw = clean(r[cKey]);
      const description = clean(r[cProto]);
      const deprecated = /\(deprecated\)/i.test(keywordRaw);
      const keyword = keywordRaw.replace(/\s*\(deprecated\)/i, "");
      const refs = clean(r[cRef]);
      const rfcs = [...new Set([...refs.matchAll(/RFC\s?(\d{3,5})/g)].map(m => Number(m[1])))];
      const unassigned = /^unassigned$/i.test(description) && !keyword;
      let cat = category.get(n);
      if (unassigned) cat = "special";                     // the 13th category holds the unassigned block
      if (!cat) throw new Error(`Number ${n} (${keyword || description}) has no category; add it to CATEGORIES`);
      const status = unassigned ? "unassigned"
        : n === 253 || n === 254 ? "experimental"
        : n === 255 ? "reserved"
        : cat === "special" ? "placeholder"
        : deprecated ? "deprecated"
        : common.has(n) ? "common"
        : HISTORIC.has(cat) ? "historic"
        : "assigned";
      numbers.push({
        n, keyword, description: description || keyword, category: cat, status,
        ipv6ExtensionHeader: clean(r[cExt]).toUpperCase() === "Y",
        rfcs                                 // IANA's other references name individuals; not republished
      });
    }
  }
  numbers.sort((a, b) => a.n - b.n);
  if (numbers.length !== 256 || numbers.some((x, i) => x.n !== i)) throw new Error(`Expected numbers 0-255 exactly once; got ${numbers.length}`);
  for (const c of CATEGORIES) {
    for (const n of c.numbers) if (numbers[n].category !== c.id || numbers[n].status === "unassigned") throw new Error(`Number ${n} is listed under ${c.id} but IANA marks it unassigned`);
  }
  return {
    source: "IANA, Assigned Internet Protocol Numbers",
    url: "https://www.iana.org/assignments/protocol-numbers/",
    updated,
    csvSha256: createHash("sha256").update(csvText).digest("hex"),
    categories: CATEGORIES.map(({ id, title }) => ({ id, title })),
    numbers
  };
}

async function fetchText(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url} returned HTTP ${r.status}`);
  return r.text();
}

const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop());
if (isMain) {
  const csv = process.argv[2] ? await readFile(process.argv[2], "utf8") : await fetchText(CSV_URL);
  let updated = null;
  try { updated = (await fetchText(XML_URL)).match(/<updated>([^<]+)<\/updated>/)?.[1] ?? null; } catch { /* offline: no date */ }
  const data = buildData(csv, updated);
  const out = new URL("../docs/data/protocols.json", import.meta.url);
  const text = JSON.stringify(data, null, 1) + "\n";
  let old = "";
  try { old = await readFile(out, "utf8"); } catch { /* first build */ }
  if (old === text) console.log(`unchanged (IANA updated ${updated})`);
  else { await writeFile(out, text); console.log(`wrote docs/data/protocols.json: 256 numbers, IANA updated ${updated}`); }
}
