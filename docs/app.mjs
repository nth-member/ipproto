import { readCapture, LINKTYPE_NAMES } from "./lib/pcap.mjs";
import { analyze } from "./lib/analyze.mjs";
import { buildCapture, REPRESENTATIVES } from "./lib/bridge.mjs";
import { colors8, token8, document8 } from "./lib/colour8.mjs";
import { grammar } from "./lib/grammar.mjs";

const $ = id => document.getElementById(id);
const fmt = n => n.toLocaleString("en-US");
const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const store = {
  get(k) { try { return localStorage.getItem(`ipproto:${k}`); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(`ipproto:${k}`, v); } catch { /* storage unavailable */ } }
};
function status(id, text, kind = "") { $(id).textContent = text; $(id).className = `status ${kind}`; }
function save(name, blob) {
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
}
const bytesText = n => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MiB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KiB` : `${n} B`);

const CODES = { core: "CO", transport: "TR", routing: "RO", multicast: "MC", tunnel: "TU", security: "SE", mobility: "MO", qos: "QS", resolution: "AR", monitoring: "MN", arpa: "AP", vendor: "VN", special: "SP" };
const STATUS = [
  ["common", "In common use"], ["assigned", "Assigned"], ["historic", "Historic"],
  ["deprecated", "Deprecated"], ["special", "Placeholder, experimental, reserved"], ["unassigned", "Unassigned"]
];
const STATUS_TEXT = { common: "In common use today", assigned: "Assigned", historic: "Historic: rarely seen on present-day networks", deprecated: "Deprecated", placeholder: "Placeholder (any protocol of a kind)", experimental: "Experimental and testing (RFC 3692)", reserved: "Reserved", unassigned: "Unassigned" };
const statusClass = s => (["placeholder", "experimental", "reserved"].includes(s) ? "special" : s);

let reg = null, analysis = null, selectedCat = store.get("cat") || null, selectedNum = Number(store.get("num") ?? 6);
const catTitle = id => reg.categories.find(c => c.id === id)?.title ?? id;

// ---------- tabs ----------
const tabs = [...document.querySelectorAll("[role=tab]")];
function show(name) {
  for (const t of tabs) t.setAttribute("aria-selected", String(t.dataset.tab === name));
  for (const p of document.querySelectorAll("[data-panel]")) p.hidden = p.dataset.panel !== name;
  store.set("tab", name);
  if (location.hash.slice(1) !== name) history.replaceState(null, "", `#${name}`);
}
tabs.forEach(t => t.addEventListener("click", () => show(t.dataset.tab)));
const tabFromHash = () => (tabs.some(t => t.dataset.tab === location.hash.slice(1)) ? location.hash.slice(1) : null);
addEventListener("hashchange", () => { const t = tabFromHash(); if (t) show(t); });
show(tabFromHash() ?? store.get("tab") ?? "map");

// ---------- category chips (shared by every tab) ----------
function renderChips() {
  const counts = new Map(reg.categories.map(c => [c.id, reg.numbers.filter(x => x.category === c.id).length]));
  const chip = (id, label, code, extra) => `<button class="chip" data-cat="${id}" aria-pressed="${String(selectedCat === id || (!selectedCat && id === ""))}" title="${esc(label)}">${code ? `<b>${code}</b>` : ""}${esc(label)}${extra ? `<span class="n">${extra}</span>` : ""}</button>`;
  $("chips").innerHTML = chip("", "All 13 categories", "", "") + reg.categories.map(c => {
    const pk = analysis ? analysis.perCategory.get(c.id) : null;
    return chip(c.id, c.title, CODES[c.id], analysis ? `${fmt(pk)} pkt` : counts.get(c.id));
  }).join("");
}
$("chips").addEventListener("click", e => {
  const b = e.target.closest(".chip");
  if (!b) return;
  setCategory(b.dataset.cat || null);
});
function setCategory(id) {
  selectedCat = selectedCat === id ? null : id;
  store.set("cat", selectedCat ?? "");
  renderChips(); renderGrid(); renderRegTable();
  if (analysis) renderCapture();
}

// ---------- map ----------
function renderLegend() {
  $("statusLegend").innerHTML = STATUS.map(([k, t]) => `<span><i class="st-${k}"></i>${t}</span>`).join("") + (analysis ? `<span><i class="found"></i>Found in the capture</span>` : "");
}
function matchesSearch(x, q) {
  if (!q) return true;
  if (/^\d+$/.test(q)) return String(x.n) === q;
  q = q.toLowerCase();
  return x.keyword.toLowerCase().includes(q) || x.description.toLowerCase().includes(q);
}
function renderGrid() {
  const q = $("search").value.trim();
  $("grid").innerHTML = reg.numbers.map(x => {
    const dim = (selectedCat && x.category !== selectedCat) || !matchesSearch(x, q);
    const found = analysis?.perNumber.get(x.n);
    const cls = ["cell", `st-${statusClass(x.status)}`, dim ? "dim" : "", found ? "found" : "", x.n === selectedNum ? "sel" : ""].join(" ");
    const tip = `${x.n} ${x.keyword || x.description} · ${catTitle(x.category)} · ${STATUS_TEXT[x.status]}${found ? ` · ${fmt(found.packets)} packets` : ""}`;
    return `<button class="${cls}" data-n="${x.n}" title="${esc(tip)}" aria-label="${esc(tip)}"><em>${CODES[x.category]}</em>${x.n}<small>${esc(x.keyword || (x.status === "unassigned" ? "" : x.description))}</small>${found ? `<span class="cnt">${found.packets > 999 ? "1k+" : found.packets}</span>` : ""}</button>`;
  }).join("");
}
$("grid").addEventListener("click", e => { const c = e.target.closest(".cell"); if (c) selectNumber(Number(c.dataset.n)); });
$("search").addEventListener("input", renderGrid);
function selectNumber(n) {
  selectedNum = n; store.set("num", String(n));
  renderGrid(); renderDetail();
}
function renderDetail() {
  const x = reg.numbers[selectedNum];
  const found = analysis?.perNumber.get(x.n);
  const rfcs = x.rfcs.length ? x.rfcs.map(r => `<a href="https://www.rfc-editor.org/rfc/rfc${r}" target="_blank" rel="noopener">RFC ${r}</a>`).join(", ") : "—";
  const filter = x.n === 6 ? "tcp" : x.n === 17 ? "udp" : x.n === 1 ? "icmp" : `ip proto ${x.n} or ip6 proto ${x.n}`;
  $("detail").innerHTML = `<h2>${x.n} · ${esc(x.keyword || x.description)}</h2>
    <dl>
      <dt>Protocol</dt><dd>${esc(x.description)}</dd>
      <dt>Category</dt><dd><b>${CODES[x.category]}</b> ${esc(catTitle(x.category))}</dd>
      <dt>Status</dt><dd>${esc(STATUS_TEXT[x.status])}</dd>
      <dt>IPv6 extension header</dt><dd>${x.ipv6ExtensionHeader ? "Yes: can appear in an IPv6 header chain" : "No"}</dd>
      <dt>Specification</dt><dd>${rfcs} · <a href="https://www.iana.org/assignments/protocol-numbers/" target="_blank" rel="noopener">IANA registry</a></dd>
      <dt>Hex · binary</dt><dd><code>0x${x.n.toString(16).toUpperCase().padStart(2, "0")} · ${x.n.toString(2).padStart(8, "0")}</code></dd>
      <dt>tcpdump filter</dt><dd><code>sudo tcpdump -i any -nn '${filter}'</code></dd>
      ${analysis ? `<dt>In the capture</dt><dd>${found ? `${fmt(found.packets)} packets contain it; ${fmt(found.carried)} carry it as their innermost protocol; ${bytesText(found.bytes)}` : "Not present"}</dd>` : ""}
    </dl>`;
}
function renderRegTable() {
  const rows = reg.numbers.filter(x => !selectedCat || x.category === selectedCat);
  $("regTable").innerHTML = `<thead><tr><th class="num">No.</th><th>Keyword</th><th>Protocol</th><th>Category</th><th>Status</th><th>RFC</th></tr></thead><tbody>${
    rows.map(x => `<tr class="clickable" data-n="${x.n}"><td class="num">${x.n}</td><td>${esc(x.keyword || "—")}</td><td>${esc(x.description)}</td><td>${CODES[x.category]} ${esc(catTitle(x.category))}</td><td>${esc(STATUS_TEXT[x.status])}</td><td>${x.rfcs.join(", ") || "—"}</td></tr>`).join("")
  }</tbody>`;
}
$("regTable").addEventListener("click", e => { const r = e.target.closest("tr[data-n]"); if (r) { selectNumber(Number(r.dataset.n)); $("grid").scrollIntoView({ behavior: "smooth" }); } });

// ---------- capture ----------
async function loadCapture(buffer, name) {
  status("capStatus", "Reading…");
  await new Promise(r => setTimeout(r, 20));
  try {
    const t0 = performance.now();
    const cap = readCapture(buffer);
    analysis = analyze(cap, reg);
    $("capName").textContent = name;
    status("capStatus", `${fmt(analysis.packets)} packets read in ${fmt(Math.round(performance.now() - t0))} ms. Nothing was uploaded.`, "good");
    $("capOut").hidden = false;
    $("cSource").querySelector("[value=capture]").disabled = false;
    renderChips(); renderLegend(); renderGrid(); renderDetail(); renderCapture(); renderColours();
  } catch (error) {
    status("capStatus", error.message, "error");
  }
}
$("capFile").addEventListener("change", async e => {
  const f = e.target.files[0];
  e.target.value = "";
  if (f) loadCapture(await f.arrayBuffer(), f.name);
});

function renderCapture() {
  const a = analysis;
  const dur = a.start !== null && a.end !== null ? a.end - a.start : null;
  const catsSeen = [...a.perCategory.values()].filter(v => v > 0).length;
  const when = a.start !== null ? new Date(a.start * 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC") : "no timestamps";
  $("capTiles").innerHTML = [
    ["Packets", fmt(a.packets), `${fmt(a.ipPackets)} IP`],
    ["Bytes", bytesText(a.bytes), `${fmt(a.bytes)} bytes on the wire`],
    ["Duration", dur === null ? "—" : dur < 120 ? `${dur.toFixed(1)} s` : `${(dur / 60).toFixed(1)} min`, when],
    ["Protocol numbers", fmt(a.perNumber.size), "distinct numbers seen"],
    ["Categories", `${catsSeen} of 13`, "with traffic"]
  ].map(([b, s, m]) => `<div class="tile"><b>${b}</b><span>${s}</span><small>${esc(m)}</small></div>`).join("");

  const LEVEL = { warn: "Warning", note: "Note", info: "Info" };
  $("capFlags").innerHTML = a.flags.length ? a.flags.map(f => `<li class="f-${f.level}"><b>${LEVEL[f.level]}</b>${esc(f.text)}</li>`).join("") : `<li class="f-info"><b>Info</b>Nothing unusual: every protocol number seen is assigned and in common use.</li>`;

  const max = Math.max(1, ...a.perCategory.values());
  $("capCats").innerHTML = reg.categories.map(c => {
    const v = a.perCategory.get(c.id);
    const pct = a.ipPackets ? (100 * v / a.ipPackets) : 0;
    return `<button class="bar${v ? "" : " zero"}" data-cat="${c.id}" aria-pressed="${String(selectedCat === c.id)}"><span class="label"><b>${CODES[c.id]}</b> ${esc(c.title)}</span><span class="track"><span class="fill" style="width:${(100 * v / max).toFixed(2)}%"></span></span><span class="val">${fmt(v)} · ${pct.toFixed(pct && pct < 1 ? 1 : 0)}%</span></button>`;
  }).join("");

  renderTimeline();

  const rows = [...a.perNumber.entries()].filter(([n]) => !selectedCat || reg.numbers[n].category === selectedCat).sort((x, y) => y[1].packets - x[1].packets || x[0] - y[0]);
  $("capProtos").innerHTML = `<thead><tr><th class="num">No.</th><th>Keyword</th><th>Category</th><th>Status</th><th class="num">Packets</th><th class="num">Carried</th><th class="num">Bytes</th></tr></thead><tbody>${
    rows.length ? rows.map(([n, e]) => { const x = reg.numbers[n]; return `<tr class="clickable" data-n="${n}"><td class="num">${n}</td><td>${esc(x.keyword || x.description)}</td><td>${CODES[x.category]} ${esc(catTitle(x.category))}</td><td>${esc(STATUS_TEXT[x.status])}</td><td class="num">${fmt(e.packets)}</td><td class="num">${fmt(e.carried)}</td><td class="num">${bytesText(e.bytes)}</td></tr>`; }).join("")
    : `<tr><td colspan="7" class="note">No packets in this category.</td></tr>`
  }</tbody>`;

  const list = (map, label) => (map.size ? [...map.entries()].sort((x, y) => y[1] - x[1]).map(([k, v]) => `<li>${label(k)} · ${fmt(v)}</li>`).join("") : `<li class="note">None</li>`);
  const kw = n => `${n} ${esc(reg.numbers[n].keyword || reg.numbers[n].description)}`;
  $("capTunnels").innerHTML = list(a.tunnelUse, kw) + (a.nested ? `<li>Tunnel inside tunnel · ${fmt(a.nested)}</li>` : "");
  $("capExt").innerHTML = list(a.ext6, kw);
  $("capNonIp").innerHTML = list(a.nonIp, esc) + [...a.innerNonIp.entries()].map(([k, v]) => `<li>Inside a tunnel: ${esc(k)} · ${fmt(v)}</li>`).join("");
  $("capMeta").innerHTML = [
    `Format: ${esc(a.format)}`,
    `Link types: ${a.linktypes.map(l => `${l}${LINKTYPE_NAMES[l] ? ` (${LINKTYPE_NAMES[l]})` : ""}`).join(", ") || "—"}`,
    a.vlanTagged ? `VLAN-tagged packets: ${fmt(a.vlanTagged)}` : "",
    a.truncatedFile ? "The file ends in the middle of a packet." : ""
  ].filter(Boolean).map(t => `<li>${t}</li>`).join("");

  $("capTalkers").innerHTML = `<thead><tr><th>Source → destination</th><th class="num">Packets</th><th class="num">Bytes</th><th>Protocol numbers</th></tr></thead><tbody>${
    a.talkers.map(t => `<tr><td><code>${esc(t.pair)}</code></td><td class="num">${fmt(t.packets)}</td><td class="num">${bytesText(t.bytes)}</td><td>${[...t.numbers].sort((x, y) => x - y).slice(0, 12).map(kw).join(", ")}${t.numbers.size > 12 ? " …" : ""}</td></tr>`).join("") || `<tr><td colspan="4" class="note">No IP packets.</td></tr>`
  }</tbody>`;
}
$("capCats").addEventListener("click", e => { const b = e.target.closest(".bar"); if (b) setCategory(b.dataset.cat); });
$("capProtos").addEventListener("click", e => { const r = e.target.closest("tr[data-n]"); if (r) { selectNumber(Number(r.dataset.n)); show("map"); } });

function renderTimeline() {
  const t = analysis.timeline;
  const key = selectedCat ?? "*";
  $("tlNote").textContent = selectedCat ? `packets containing ${catTitle(selectedCat).toLowerCase()} · hover for values` : "all IP packets · hover for values";
  if (!t.bins.length) { $("capTimeline").innerHTML = `<p class="note">The capture has no timestamps.</p>`; return; }
  const vals = t.bins.map(b => b.get(key) ?? 0);
  const max = Math.max(1, ...vals);
  const W = 600, H = 150, gap = 2, bw = W / vals.length;
  const bars = vals.map((v, i) => {
    const h = v ? Math.max(2, (v / max) * (H - 6)) : 0;
    return `<rect x="${(i * bw + gap / 2).toFixed(2)}" y="${(H - h).toFixed(2)}" width="${Math.max(1, bw - gap).toFixed(2)}" height="${h.toFixed(2)}" rx="${Math.min(4, (bw - gap) / 2).toFixed(1)}" fill="var(--bar)"/>`
      + `<rect x="${(i * bw).toFixed(2)}" y="0" width="${bw.toFixed(2)}" height="${H}" fill="transparent" data-i="${i}"/>`;
  }).join("");
  const span = (t.end - t.start) || 0;
  const label = s => (span < 120 ? `${s.toFixed(1)} s` : `${(s / 60).toFixed(1)} min`);
  $("capTimeline").innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Packets over time"><line x1="0" y1="${H}" x2="${W}" y2="${H}" stroke="var(--axis)" stroke-width="1"/>${bars}</svg><div class="axis"><span>${label(0)}</span><span>peak ${fmt(max)} per bin</span><span>${label(span)}</span></div><div class="tip" hidden></div>`;
  const svg = $("capTimeline").querySelector("svg"), tip = $("capTimeline").querySelector(".tip");
  svg.addEventListener("mousemove", e => {
    const i = e.target.dataset?.i;
    if (i === undefined) { tip.hidden = true; return; }
    const from = (span * i) / vals.length, to = (span * (Number(i) + 1)) / vals.length;
    tip.textContent = `${fmt(vals[i])} packets · ${label(from)}–${label(to)}`;
    const r = $("capTimeline").getBoundingClientRect();
    tip.style.left = `${e.clientX - r.left}px`; tip.style.top = `${e.clientY - r.top}px`;
    tip.hidden = false;
  });
  svg.addEventListener("mouseleave", () => { tip.hidden = true; });
}

// ---------- bridge ----------
let bridgeOut = null;
function fillWhich() {
  $("bWhich").innerHTML = [
    `<option value="all">All 13 categories: every number 0–255</option>`,
    `<option value="reps">All 13 categories: one number each</option>`,
    ...reg.categories.map(c => `<option value="cat:${c.id}">${CODES[c.id]} · ${esc(c.title)}</option>`),
    `<option value="single">One number…</option>`
  ].join("");
}
$("bWhich").addEventListener("change", () => { $("bNumWrap").hidden = $("bWhich").value !== "single"; });
function chosenNumbers() {
  const v = $("bWhich").value;
  if (v === "all") return reg.numbers.map(x => x.n);
  if (v === "reps") return reg.categories.map(c => REPRESENTATIVES[c.id]);
  if (v === "single") {
    const n = Number($("bNum").value);
    if (!Number.isInteger(n) || n < 0 || n > 255) throw new RangeError("The number must be 0 to 255");
    return [n];
  }
  return reg.numbers.filter(x => x.category === v.slice(4)).map(x => x.n);
}
$("bGo").addEventListener("click", async () => {
  $("bGo").disabled = true; $("bOut").hidden = true;
  status("bStatus", "Building…");
  await new Promise(r => setTimeout(r, 20));
  try {
    const numbers = chosenNumbers();
    const seedText = $("bSeed").value.trim();
    const seed = seedText === "" ? undefined : Number(seedText);
    if (seed !== undefined && (!Number.isSafeInteger(seed) || seed < 0)) throw new RangeError("The seed must be a whole number");
    const model = $("bModel").value;
    const r = buildCapture({ model, seed, size: Number($("bSize").value), chunk: Number($("bChunk").value), numbers });
    const cats = new Set(numbers.map(n => reg.numbers[n].category));
    const name = `${model}_1971_${r.seed}_${$("bWhich").value.replace(":", "-")}.pcap`;
    bridgeOut = { pcap: r.pcap, name };
    status("bStatus", `${fmt(r.packets)} packets · ${bytesText(r.pcap.length)} · ${numbers.length} protocol number(s) from ${cats.size} of 13 categories · seed ${r.seed}`, "good");
    $("bCmd").textContent = `tcpdump -nn -r ${name}`;
    $("bOut").hidden = false;
  } catch (error) {
    status("bStatus", error.message, "error");
  } finally { $("bGo").disabled = false; }
});
$("bSave").addEventListener("click", () => { if (bridgeOut) save(bridgeOut.name, new Blob([bridgeOut.pcap], { type: "application/vnd.tcpdump.pcap" })); });
$("bAnalyse").addEventListener("click", () => {
  if (!bridgeOut) return;
  show("capture");
  loadCapture(bridgeOut.pcap.buffer.slice(0), bridgeOut.name);
});

// ---------- colours ----------
function renderKey8() {
  $("key8").innerHTML = reg.numbers.map(x => {
    const { foreground, background } = colors8(x.n);
    return `<div style="color:${foreground};background:${background}" title="${x.n} ${esc(x.keyword || x.description)} · ${foreground} on ${background}">${x.n}</div>`;
  }).join("");
}
function sequenceNow() {
  return $("cSource").value === "capture" && analysis ? analysis.sequence : reg.numbers.map(x => x.n);
}
function renderColours() {
  const seq = sequenceNow();
  $("cPreview").innerHTML = seq.slice(0, 1500).map(token8).join("");
  status("cStatus", `${fmt(seq.length)} token(s)${seq.length > 1500 ? " · first 1,500 shown" : ""}`);
  $("cGigaNote").textContent = "";
}
$("cSource").addEventListener("change", renderColours);
$("cSave").addEventListener("click", () => {
  const seq = sequenceNow();
  save(`ipproto_${$("cSource").value}.HTM`, new Blob([document8(seq)], { type: "application/octet-stream" }));
});
$("cGiga").addEventListener("click", () => {
  const seq = sequenceNow();
  const text = seq.map(n => reg.numbers[n].keyword || String(n)).join(" ");
  const url = `https://nth-member.github.io/gigaspeak/render.html?g=span-transparent#html=${encodeURIComponent(grammar("span-transparent").encodeText(text))}`;
  $("cGigaNote").textContent = `${fmt(url.length)} characters${url.length > 1_048_572 ? ": longer than Firefox opens by default (1,048,572)" : ""}`;
  try { const w = window.open(url, "_blank"); if (w) w.opener = null; }
  catch { $("cGigaNote").textContent += " · the browser refused the address"; }
});

// ---------- start ----------
fetch("data/protocols.json").then(r => r.json()).then(data => {
  reg = data;
  $("footUpdated").textContent = data.updated ? `(registry updated ${data.updated})` : "";
  $("regNote").textContent = `Source: IANA, updated ${data.updated ?? "—"}. Status "in common use" is this site's judgement; the 13 categories are this site's grouping. Cells carry a two-letter category code; colour shows status.`;
  if (selectedCat && !reg.categories.some(c => c.id === selectedCat)) selectedCat = null;
  if (!(selectedNum >= 0 && selectedNum <= 255)) selectedNum = 6;
  fillWhich();
  renderChips(); renderLegend(); renderGrid(); renderDetail(); renderRegTable(); renderKey8(); renderColours();
}).catch(error => { document.querySelector(".sub").textContent = `Could not load the registry: ${error.message}`; });
