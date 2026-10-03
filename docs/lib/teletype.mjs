// Teletype Model 33 and Model 37 ASR test streams, 1971 style: the browser port
// of tools/asr33_gen.py and tools/asr37_gen.py.
//
// The port is exact. PyRandom reproduces Python's random.Random (MT19937 with
// Python's integer seeding, getrandbits, _randbelow, random, randint, choice,
// sample, uniform), and the generators make the same calls in the same order,
// so a seed gives the same bytes here as `python3 asr33_gen.py --seed N`.
// test/teletype.test.mjs checks this against the Python scripts.

// ---------- Python's random.Random ----------
export class PyRandom {
  constructor(seed) {
    const mt = this.mt = new Uint32Array(624);
    // init_genrand(19650218)
    mt[0] = 19650218;
    for (let i = 1; i < 624; i += 1) mt[i] = (Math.imul(1812433253, mt[i - 1] ^ (mt[i - 1] >>> 30)) + i) >>> 0;
    // init_by_array(key): the key is |seed| in 32-bit words, least significant first
    let s = BigInt(seed < 0 ? -seed : seed);
    const key = [];
    do { key.push(Number(s & 0xffffffffn)); s >>= 32n; } while (s > 0n);
    let i = 1, j = 0;
    for (let k = Math.max(624, key.length); k > 0; k -= 1) {
      mt[i] = ((mt[i] ^ Math.imul(mt[i - 1] ^ (mt[i - 1] >>> 30), 1664525)) + key[j] + j) >>> 0;
      i += 1; j += 1;
      if (i >= 624) { mt[0] = mt[623]; i = 1; }
      if (j >= key.length) j = 0;
    }
    for (let k = 623; k > 0; k -= 1) {
      mt[i] = ((mt[i] ^ Math.imul(mt[i - 1] ^ (mt[i - 1] >>> 30), 1566083941)) - i) >>> 0;
      i += 1;
      if (i >= 624) { mt[0] = mt[623]; i = 1; }
    }
    mt[0] = 0x80000000;
    this.index = 624;
  }

  uint32() {
    const mt = this.mt;
    if (this.index >= 624) {
      for (let k = 0; k < 624; k += 1) {
        const y = (mt[k] & 0x80000000) | (mt[(k + 1) % 624] & 0x7fffffff);
        mt[k] = mt[(k + 397) % 624] ^ (y >>> 1) ^ (y & 1 ? 0x9908b0df : 0);
      }
      this.index = 0;
    }
    let y = mt[this.index++];
    y ^= y >>> 11;
    y ^= (y << 7) & 0x9d2c5680;
    y ^= (y << 15) & 0xefc60000;
    y ^= y >>> 18;
    return y >>> 0;
  }

  getrandbits(k) { return this.uint32() >>> (32 - k); }            // 1 <= k <= 32 here
  randbelow(n) {
    const k = 32 - Math.clz32(n);                                    // n.bit_length()
    let r = this.getrandbits(k);
    while (r >= n) r = this.getrandbits(k);
    return r;
  }
  random() { return ((this.uint32() >>> 5) * 67108864 + (this.uint32() >>> 6)) / 9007199254740992; }
  randrange(n) { return this.randbelow(n); }
  randint(a, b) { return a + this.randbelow(b - a + 1); }
  choice(seq) { return seq[this.randbelow(seq.length)]; }
  uniform(a, b) { return a + (b - a) * this.random(); }
  sample(population, k) {                                            // the pool method: n <= setsize here
    const pool = Array.from(population), n = pool.length, result = new Array(k);
    for (let i = 0; i < k; i += 1) {
      const j = this.randbelow(n - i);
      result[i] = pool[j];
      pool[j] = pool[n - i - 1];
    }
    return result;
  }
}

// ---------- Python %-formatting, as the scripts use it ----------
const pad = (s, width, ch = " ") => (s.length >= width ? s : ch.repeat(width - s.length) + s);
const d = (v, width = 0, zero = false) => pad(String(v), width, zero ? "0" : " ");
const f = (v, digits, width = 0) => pad(v.toFixed(digits), width);
const E = (v, digits) => v.toExponential(digits).replace(/e([+-])(\d)$/, "e$10$2").replace("e", "E");

// ---------- byte buffers ----------
const NUL = 0x00, SOH = 0x01, ETX = 0x03, EOT = 0x04, ENQ = 0x05, BEL = 0x07, BS = 0x08, HT = 0x09, LF = 0x0a;
const VT = 0x0b, FF = 0x0c, CR = 0x0d, SO = 0x0e, SI = 0x0f, DC1 = 0x11, DC2 = 0x12, DC3 = 0x13, DC4 = 0x14;
const NAK = 0x15, SUB = 0x1a, ESC = 0x1b, DEL = 0x7f;
const STX = 0x02, ETB = 0x17, SYN = 0x16, DLE = 0x10, CAN = 0x18;

class Buf {
  constructor() { this.a = []; }
  b(...bytes) { for (const x of bytes) this.a.push(x); return this; }
  s(text) { for (let i = 0; i < text.length; i += 1) this.a.push(text.charCodeAt(i)); return this; }
  zeros(n) { for (let i = 0; i < n; i += 1) this.a.push(0); return this; }
  cat(other) { for (const x of other.a) this.a.push(x); return this; }
  get length() { return this.a.length; }
}

function wrap(text, width) {
  const lines = [];
  let cur = "";
  for (const w of text.split(/\s+/).filter(Boolean)) {
    if (cur && cur.length + 1 + w.length > width) { lines.push(cur); cur = w; }
    else cur = cur ? `${cur} ${w}` : w;
  }
  return cur ? [...lines, cur] : lines;
}

function tick(g) {
  g.t[2] += g.r.randint(1, 90);
  if (g.t[2] >= 1440) { g.t[2] -= 1440; g.t[1] += 1; }
  if (g.t[1] >= 28) { g.t[1] = 0; g.t[0] = (g.t[0] + 1) % 12; }
  return [g.t[1] + 1, Math.floor(g.t[2] / 60), g.t[2] % 60];
}

// ---------- Model 33 ----------
const M33 = {
  MONTHS: "JAN FEB MAR APR MAY JUN JUL AUG SEP OCT NOV DEC".split(" "),
  PLACES: ["NSUKKA", "ENUGU", "LAGOS", "KANO", "IBADAN", "PORT HARCOURT", "KADUNA", "JOS", "CALABAR", "ONITSHA", "ACCRA", "LONDON"],
  ICAO: ["DNMM", "DNKN", "DNEN", "DNPO", "DNIB", "DNKA", "DNJO", "DNCA"],
  WORDS: ("THE AND OF TO IN FOR ON AT BY WITH FROM REPORT PLANT PUMP VALVE LINE PRESSURE " +
    "FLOW BEARING SHAFT MOTOR SUPPLY CARGO SHIPMENT DELAY ARRIVED DISPATCHED CONFIRM " +
    "REQUEST APPROVED PENDING INSPECTION MAINTENANCE OVERHAUL SPARES ORDER UNITS " +
    "COMPRESSOR TURBINE BOILER GENERATOR TRANSFORMER TEST RESULTS WITHIN LIMITS ADVISE " +
    "IMMEDIATELY SCHEDULE WEEK MONTH ENGINEER CREW SHIFT OUTPUT RATED DRAWING REVISION " +
    "ISSUED RECEIVED PORT CUSTOMS RAIL ROAD TRUCK VESSEL PAYMENT INVOICE STORES").split(" "),
  PROGS: ["PAYROL", "STRESS", "BEAM", "SURVEY", "HEAT", "FLOWNT", "GRADES", "INVTRY"],
  EXTS: ["F4", "MAC", "DAT", "TXT", "BAS", "REL"]
};

class Gen33 {
  constructor(rng) {
    this.r = rng;
    this.t = [rng.randrange(12), rng.randrange(28), rng.randrange(1440)];
  }
  clock() { return tick(this); }
  stamp() { const [dd, h, m] = this.clock(); return `${d(dd, 2, true)}${d(h, 2, true)}${d(m, 2, true)}Z ${M33.MONTHS[this.t[0]]} 71`; }
  words(lo = 6, hi = 16) {
    const n = this.r.randint(lo, hi), out = [];
    for (let i = 0; i < n; i += 1) out.push(this.r.choice(M33.WORDS));
    return out.join(" ");
  }
  eol(b, fill = true) {
    b.b(CR, LF);
    if (fill) b.b(...this.r.choice([[DEL], [DEL], [NUL], [DEL, DEL], [NUL, NUL]]));
  }
  typed(b, line) {
    let room = 72 - line.length;
    for (const ch of line) {
      if (room > 0 && this.r.random() < 0.005) { room -= 1; b.s(this.r.choice("QWERTYUIOPASDFGHJKL")).b(DEL); }
      b.s(ch);
    }
    this.eol(b);
  }
  answerback() { return `${d(this.r.randint(10000, 99999), 5, true)} ${this.r.choice(M33.PLACES).slice(0, 8)} NG`; }

  tape_message() {
    const b = new Buf();
    b.zeros(this.r.randint(30, 80));
    b.b(ENQ); const ab = this.answerback();
    this.eol(b, false); b.s(ab); this.eol(b, false);
    if (this.r.random() < 0.3) b.b(...new Array(this.r.randint(1, 5)).fill(BEL));
    b.b(DC2, DC1);
    const [src, dst] = this.r.sample(M33.PLACES, 2);
    this.typed(b, `ZCZC ${src.slice(0, 3)}${d(this.r.randint(1, 999), 3, true)}`);
    this.typed(b, `${this.stamp()} FROM ${src} TO ${dst}`);
    const n = this.r.randint(2, 6), parts = [];
    for (let i = 0; i < n; i += 1) parts.push(this.words());
    for (const ln of wrap(parts.join(" STOP ") + " STOP ENDS", 72)) this.typed(b, ln);
    this.typed(b, "NNNN");
    b.b(DC3, DC4);
    b.s(ab); this.eol(b, false);
    b.zeros(this.r.randint(20, 60));
    if (this.r.random() < 0.5) b.b(EOT);
    return ["tape_message", b];
  }

  wmo_bulletin() {
    const b = new Buf();
    b.zeros(this.r.randint(10, 40));
    const [dd, h] = this.clock();
    b.b(SOH).s("\r\r\n");
    b.s(`${d(this.r.randint(0, 999), 3, true)}\r\r\n`);
    b.s(`SMNI${d(this.r.randint(1, 99), 2, true)} ${this.r.choice(M33.ICAO)} ${d(dd, 2, true)}${d(h, 2, true)}00\r\r\n`);
    const lines = this.r.randint(4, 14);
    for (let i = 0; i < lines; i += 1) {
      const groups = [`652${d(this.r.randint(0, 99), 2, true)}`];
      const n = this.r.randint(5, 10);
      for (let k = 0; k < n; k += 1) groups.push(d(this.r.randint(0, 99999), 5, true));
      b.s(`${groups.join(" ")}=`).s("\r\r\n");
    }
    b.s("\r\r\n\n\n\n\n\n\n\n").b(ETX);
    b.zeros(this.r.randint(10, 40));
    return ["wmo_bulletin", b];
  }

  console() {
    const b = new Buf(), r = this.r;
    const user = `[${r.randint(10, 99)},${r.randint(100, 999)}]`;
    b.s("."); b.s(`LOGIN ${user}`); this.eol(b);
    b.s(`JOB ${r.randint(1, 40)}  UNN SYS 5.03  TTY${r.randint(0, 17)}`); this.eol(b);
    b.s("PASSWORD: "); this.eol(b);
    const steps = r.randint(3, 9);
    for (let s = 0; s < steps; s += 1) {
      const act = r.random();
      const prog = r.choice(M33.PROGS), ext = r.choice(M33.EXTS);
      b.s(".");
      if (act < 0.2) {
        b.s(`RUN ${prog.slice(0, 3)}`).b(NAK).s("^U"); this.eol(b); b.s(".");
        b.s(`RUN ${prog}`); this.eol(b);
        const n = r.randint(2, 8);
        for (let i = 0; i < n; i += 1) {
          const v = [r.uniform(0, 999), r.uniform(0, 999), r.uniform(0, 999)];
          b.s(`${f(v[0], 3, 8)} ${f(v[1], 3, 8)} ${f(v[2], 3, 8)}`); this.eol(b);
        }
        b.s("EXIT"); this.eol(b);
      } else if (act < 0.4) {
        b.s(`TYPE ${prog}.${ext}`); this.eol(b);
        const n = r.randint(2, 6);
        for (let i = 0; i < n; i += 1) { b.s(wrap(this.words(8, 14), 72)[0]); this.eol(b); }
        b.b(SI).s("^O"); this.eol(b);
      } else if (act < 0.6) {
        b.s(`EXECUTE ${prog}.${ext}`); this.eol(b);
        const n = r.randint(3, 12);
        for (let i = 0; i < n; i += 1) { b.s(`ITER ${d(i, 4)}  RESID ${E(r.uniform(1e-6, 1), 5)}`); this.eol(b); }
        b.b(ETX).s("^C"); this.eol(b);
      } else if (act < 0.8) {
        b.s(`COPY ${prog}.DAT=TTY:`); this.eol(b);
        const n = r.randint(2, 6);
        for (let i = 0; i < n; i += 1) {
          const nums = [];
          for (let k = 0; k < 6; k += 1) nums.push(String(r.randint(0, 9999)));
          this.typed(b, nums.join(" "));
        }
        b.b(SUB).s("^Z"); this.eol(b);
      } else {
        b.s(`TECO ${prog}.${ext}`); this.eol(b);
        b.s("*");
        for (const c of [`S${r.choice(M33.WORDS)}`, "-D", `I${r.choice(M33.WORDS)}`, "0TT"]) b.s(c).b(ESC);
        b.b(ESC); this.eol(b);
        b.s(r.choice(M33.WORDS)).s(" ").s(this.words(3, 6)); this.eol(b);
        b.s("*EX").b(ESC, ESC); this.eol(b);
      }
    }
    if (r.random() < 0.25) { b.b(BEL).s("?QUOTA EXCEEDED"); this.eol(b); b.s("."); }
    b.s("K/F"); this.eol(b);
    const [, h, m] = this.clock();
    b.s(`JOB LOGGED OFF TTY AT ${d(h, 2, true)}${d(m, 2, true)}`); this.eol(b);
    return ["console", b];
  }

  local_tape() {
    const b = new Buf();
    b.b(DC2).zeros(this.r.randint(20, 50));
    const n = this.r.randint(3, 8), parts = [];
    for (let i = 0; i < n; i += 1) parts.push(this.words());
    for (const ln of wrap(parts.join(" "), 72)) this.typed(b, ln);
    b.zeros(this.r.randint(20, 50)).b(DC4);
    return ["local_tape", b];
  }

  bisync_block() {
    const r = this.r, b = new Buf(), syn = [SYN, SYN];
    const lead = r.randint(2, 4);
    for (let i = 0; i < lead; i += 1) b.b(...syn);           // sync idle, then bid for the line
    b.b(ENQ);
    b.b(...syn).b(DLE, 0x30);                                // ACK0: ready to receive
    const n = r.randint(2, 5); let ack = 1;
    for (let i = 0; i < n; i += 1) {
      const src = r.choice(M33.PLACES);
      const header = `${src.slice(0, 3)}${d(r.randint(0, 99999), 5, true)}`;
      const text = this.words();
      const transparent = r.random() < 0.3;
      const corrupt = r.random() < 0.2;
      const end = i === n - 1 ? ETX : ETB;
      const body = new Buf().b(SOH).s(header);
      if (transparent) {                                     // DLE STX ... DLE ETX, data DLE doubled
        body.b(DLE, STX);
        for (let k = 0; k < text.length; k += 1) { const c = text.charCodeAt(k); if (c === DLE) body.b(DLE, DLE); else body.b(c); }
        body.b(DLE, end);
      } else {
        body.b(STX).s(text).b(end);
      }
      let lrc = 0;
      for (let k = 1; k < body.a.length; k += 1) lrc ^= body.a[k];
      b.b(...syn).cat(body);
      if (corrupt) {                                         // bad check byte, NAK, then a clean resend
        b.b(lrc ^ r.randint(1, 127));
        b.b(...syn).b(NAK);
        b.b(...syn).cat(body).b(lrc);
      } else {
        b.b(lrc);
      }
      b.b(...syn).b(DLE, 0x30 + ack);                        // ACK0 / ACK1, alternating
      ack ^= 1;
    }
    if (r.random() < 0.3) b.b(...syn).b(DLE, 0x3b);          // WACK
    if (r.random() < 0.2) b.b(...syn).b(CAN);                // block abandoned
    b.b(...syn).b(EOT);                                      // end of transmission
    if (r.random() < 0.4) b.b(DLE, EOT);                     // disconnect
    return ["bisync_block", b];
  }

  kinds() { return [() => this.tape_message(), () => this.tape_message(), () => this.wmo_bulletin(), () => this.console(), () => this.local_tape(), () => this.bisync_block()]; }
}

// ---------- Model 37 ----------
const REV_LF = [ESC, 0x37], HALF_UP = [ESC, 0x38], HALF_DOWN = [ESC, 0x39];
const M37 = {
  MONTHS: "January February March April May June July August September October November December".split(" "),
  PLACES: ["Nsukka", "Enugu", "Lagos", "Kano", "Ibadan", "Port Harcourt", "Kaduna", "Jos", "Accra", "London"],
  WORDS: ("the and of to in for on at by with from report plant pump valve line pressure flow bearing " +
    "shaft motor supply shipment delay arrived dispatched confirm request approved pending " +
    "inspection maintenance overhaul spares order units compressor turbine boiler generator " +
    "transformer test results within limits advise schedule week month engineer crew shift " +
    "output rated drawing revision issued received stress strain load beam deflection heat " +
    "transfer coefficient conduction boundary layer velocity profile specimen measured").split(" "),
  NAMES: ["Okafor", "Eze", "Adeyemi", "Bello", "Nwosu", "Okonkwo", "Hassan", "Obi", "Smith", "Brown"],
  FILES: ["beam", "stress", "heat", "flow", "grades", "survey", "notes", "memo", "table", "calc"]
};

class Gen37 {
  constructor(rng, width) {
    this.r = rng; this.W = width;
    this.t = [rng.randrange(12), rng.randrange(28), rng.randrange(1440)];
  }
  clock() { return tick(this); }
  date() { const [dd, h, m] = this.clock(); return `${dd} ${M37.MONTHS[this.t[0]]} 1971  ${d(h, 2, true)}:${d(m, 2, true)}`; }
  words(lo = 6, hi = 16) {
    const n = this.r.randint(lo, hi), out = [];
    for (let i = 0; i < n; i += 1) out.push(this.r.choice(M37.WORDS));
    return out.join(" ");
  }
  sentence() { const w = this.words(); return `${w[0].toUpperCase()}${w.slice(1).toLowerCase()}.`; }
  nl(b, style) {
    if (style === "nl") b.b(LF);
    else b.b(CR, LF).b(...this.r.choice([[], [], [NUL], [DEL]]));
  }
  typed(b, line, style) {
    let room = this.W - line.length;
    for (const ch of line) {
      if (room > 0 && this.r.random() < 0.005) { room -= 1; b.s(this.r.choice("qwertyuiopasdfghjkl")).b(DEL); }
      b.s(ch);
    }
    this.nl(b, style);
  }
  answerback() { return `${d(this.r.randint(10000, 99999), 5, true)} ${this.r.choice(M37.PLACES).slice(0, 8).toUpperCase()} NG`; }
  underline(word) { const b = new Buf(); for (const c of word) b.s(c).b(BS).s("_"); return b; }
  greek(letters) { return new Buf().b(SO).s(letters).b(SI); }

  equation() {
    const r = this.r;
    const k = r.choice(["Nu", "Re", "Pr", "q", "h", "k"]);
    const n1 = r.randint(2, 3), n2 = r.randint(1, 9);
    // The five forms are built eagerly, in order, as Python builds its list.
    const forms = [];
    forms.push(new Buf().s("(a + b)").b(...HALF_UP).s("2").b(...HALF_DOWN).s(" = a").b(...HALF_UP).s("2").b(...HALF_DOWN)
      .s(" + 2ab + b").b(...HALF_UP).s("2").b(...HALF_DOWN));
    forms.push(new Buf().s(k).b(...HALF_DOWN).s("x").b(...HALF_UP).s(` = 0.${d(r.randint(1, 999), 3, true)} Re`)
      .b(...HALF_DOWN).s("x").b(...HALF_UP).b(...HALF_UP).s(`0.${r.randint(5, 8)}`).b(...HALF_DOWN)
      .s(" Pr").b(...HALF_UP).s("1/3").b(...HALF_DOWN));
    forms.push(new Buf().cat(this.greek("s")).s(" = ").cat(this.greek("e")).s(` E,  E = ${r.randint(69, 210)} GPa`));
    const f4 = new Buf().s("H").b(...HALF_DOWN).s("2").b(...HALF_UP).s(`O at ${r.randint(20, 99)}`).b(...HALF_UP).s("o")
      .b(...HALF_DOWN).s("C,  ").cat(this.greek("r")).s(` = ${r.randint(958, 998)} kg/m`).b(...HALF_UP).s("3").b(...HALF_DOWN);
    forms.push(f4);
    forms.push(new Buf().s("x").b(...HALF_UP).s(`${n1}`).b(...HALF_DOWN).s(` - ${n2}x + ${r.randint(1, 20)} = 0`));
    return r.choice(forms);
  }

  tape_message() {
    const b = new Buf(), st = "crlf", r = this.r;
    b.zeros(r.randint(30, 80));
    b.b(ENQ); const ab = this.answerback();
    this.nl(b, st); b.s(ab); this.nl(b, st);
    if (r.random() < 0.3) b.b(...new Array(r.randint(1, 4)).fill(BEL));
    b.b(DC2, DC1);
    const [src, dst] = r.sample(M37.PLACES, 2);
    this.typed(b, `ZCZC ${src.slice(0, 3).toUpperCase()}${d(r.randint(1, 999), 3, true)}`, st);
    this.typed(b, `${this.date()}  From ${src} to ${dst}`, st);
    const n = r.randint(2, 6), s = [];
    for (let i = 0; i < n; i += 1) s.push(this.sentence());
    for (const ln of wrap(s.join(" "), this.W)) this.typed(b, ln, st);
    this.typed(b, "NNNN", st);
    b.b(DC3, DC4); b.s(ab); this.nl(b, st);
    b.zeros(r.randint(20, 60));
    if (r.random() < 0.5) b.b(EOT);
    return ["tape_message", b];
  }

  report_page() {
    const b = new Buf(), r = this.r, st = r.choice(["crlf", "nl"]);
    b.b(FF);
    const title = `${r.choice(["Beam", "Pump", "Boiler", "Specimen", "Turbine"])} test sheet`;
    b.cat(this.underline(title.toUpperCase())); b.s("     ").s(this.date()); this.nl(b, st); this.nl(b, st);
    const n = r.randint(1, 3), s = [];
    for (let i = 0; i < n; i += 1) s.push(this.sentence());
    for (const ln of wrap(s.join(" "), this.W)) { b.s(ln); this.nl(b, st); }
    this.nl(b, st);
    b.s("Item\tLoad\tStrain\tRemark"); this.nl(b, st);
    let tot = 0;
    const rows = r.randint(3, 9);
    for (let i = 0; i < rows; i += 1) {
      const v = r.randint(10, 999); tot += v;
      b.s(`${i + 1}\t${v}\t${f(r.uniform(0, 0.01), 4)}\t`);
      if (r.random() < 0.7) b.cat(this.underline("ok")); else b.s("re").b(BS, BS).s("__test");
      this.nl(b, st);
    }
    b.s(`Total\t${tot}`);
    b.b(CR).b(...REV_LF).s("\t____").b(LF);
    if (st === "crlf") b.b(CR);
    this.nl(b, st);
    const eqs = r.randint(1, 4);
    for (let i = 0; i < eqs; i += 1) { b.cat(this.equation()); this.nl(b, st); }
    if (r.random() < 0.5) { b.b(VT).s(`Checked by ${r.choice(M37.NAMES)}`); this.nl(b, st); }
    return ["report_page", b];
  }

  unix_session() {
    const b = new Buf(), st = "nl", r = this.r;
    const user = r.choice(M37.NAMES).toLowerCase();
    b.s("login: ").s(user); this.nl(b, st);
    b.s("Password:"); this.nl(b, st);
    const steps = r.randint(3, 8);
    for (let s = 0; s < steps; s += 1) {
      b.s("% ");
      const act = r.random();
      const fl = r.choice(M37.FILES);
      if (act < 0.25) {
        b.s(r.random() < 0.5 ? "ctat#" : "cay#t");
        b.s(` ${fl}`); this.nl(b, st);
        const n = r.randint(1, 4), ss = [];
        for (let i = 0; i < n; i += 1) ss.push(this.sentence());
        for (const ln of wrap(ss.join(" "), this.W)) { b.s(ln); this.nl(b, st); }
      } else if (act < 0.45) {
        b.s(`ls -l ${fl}`).s("@"); this.nl(b, st); b.s("ls"); this.nl(b, st);
        for (const g of r.sample(M37.FILES, r.randint(2, 6))) { b.s(g); this.nl(b, st); }
      } else if (act < 0.7) {
        b.s(`nroff ${fl}`); this.nl(b, st);
        const paras = r.randint(1, 3);
        for (let p = 0; p < paras; p += 1) {
          const ss = [this.sentence(), this.sentence(), this.sentence()];
          for (const ln of wrap(ss.join(" "), this.W - 8)) { b.s("        ").s(ln); this.nl(b, st); }
          b.s("        ").cat(this.equation()); this.nl(b, st);
        }
      } else if (act < 0.85) {
        b.s(`cat ${fl}`); this.nl(b, st);
        const n = r.randint(2, 6);
        for (let i = 0; i < n; i += 1) { b.s(wrap(this.sentence(), this.W)[0]); this.nl(b, st); }
        b.b(DEL); this.nl(b, st);
      } else {
        b.s(`ed ${fl}`); this.nl(b, st);
        b.s(`${r.randint(100, 4000)}`); this.nl(b, st);
        b.s("a"); this.nl(b, st);
        const n = r.randint(1, 4);
        for (let i = 0; i < n; i += 1) { b.s(wrap(this.sentence(), this.W)[0]); this.nl(b, st); }
        b.s("."); this.nl(b, st); b.s("w"); this.nl(b, st);
        b.s(`${r.randint(100, 4000)}`); this.nl(b, st); b.s("q"); this.nl(b, st);
      }
    }
    if (r.random() < 0.2) b.b(BEL);
    b.s("% ").b(EOT);
    this.nl(b, st);
    return ["unix_session", b];
  }

  dec_console() {
    const b = new Buf(), st = "crlf", r = this.r;
    b.s(`.LOGIN ${r.randint(10, 99)},${r.randint(100, 999)}`); this.nl(b, st);
    const steps = r.randint(2, 6);
    for (let s = 0; s < steps; s += 1) {
      b.s(".");
      const fl = r.choice(M37.FILES).toUpperCase();
      const act = r.random();
      if (act < 0.3) {
        b.s("RUN ").s(fl.slice(0, 2)).b(NAK).s("^U"); this.nl(b, st);
        b.s(".RUN ").s(fl); this.nl(b, st);
        const n = r.randint(2, 8);
        for (let i = 0; i < n; i += 1) { b.s(`Iter ${d(i, 3)}  resid ${E(r.uniform(1e-6, 1), 4)}`); this.nl(b, st); }
        b.b(ETX).s("^C"); this.nl(b, st);
      } else if (act < 0.6) {
        b.s(`TYPE ${fl}.TXT`); this.nl(b, st);
        const n = r.randint(2, 5);
        for (let i = 0; i < n; i += 1) { b.s(wrap(this.sentence(), this.W)[0]); this.nl(b, st); }
        b.b(SI).s("^O"); this.nl(b, st);
      } else {
        b.s(`TECO ${fl}.TXT`); this.nl(b, st); b.s("*");
        for (const c of [`S${r.choice(M37.WORDS)}`, "-D", `I${r.choice(M37.WORDS)}`, "0TT"]) b.s(c).b(ESC);
        b.b(ESC); this.nl(b, st);
        b.s(wrap(this.sentence(), this.W)[0]); this.nl(b, st);
        b.s("*EX").b(ESC, ESC); this.nl(b, st);
      }
    }
    b.s(".K/F"); this.nl(b, st);
    return ["dec_console", b];
  }

  local_tape() {
    const b = new Buf().b(DC2).zeros(this.r.randint(20, 50));
    const n = this.r.randint(3, 8), s = [];
    for (let i = 0; i < n; i += 1) s.push(this.sentence());
    for (const ln of wrap(s.join(" "), this.W)) this.typed(b, ln, "crlf");
    b.zeros(this.r.randint(20, 50)).b(DC4);
    return ["local_tape", b];
  }

  bisync_block() {
    const r = this.r, b = new Buf(), syn = [SYN, SYN];
    const lead = r.randint(2, 4);
    for (let i = 0; i < lead; i += 1) b.b(...syn);
    b.b(ENQ);
    b.b(...syn).b(DLE, 0x30);
    const n = r.randint(2, 5); let ack = 1;
    for (let i = 0; i < n; i += 1) {
      const src = r.choice(M37.PLACES);
      const header = `${src.slice(0, 3).toUpperCase()}${d(r.randint(0, 99999), 5, true)}`;
      const text = this.sentence();
      const transparent = r.random() < 0.3;
      const corrupt = r.random() < 0.2;
      const end = i === n - 1 ? ETX : ETB;
      const body = new Buf().b(SOH).s(header);
      if (transparent) {
        body.b(DLE, STX);
        for (let k = 0; k < text.length; k += 1) { const c = text.charCodeAt(k); if (c === DLE) body.b(DLE, DLE); else body.b(c); }
        body.b(DLE, end);
      } else {
        body.b(STX).s(text).b(end);
      }
      let lrc = 0;
      for (let k = 1; k < body.a.length; k += 1) lrc ^= body.a[k];
      b.b(...syn).cat(body);
      if (corrupt) {
        b.b(lrc ^ r.randint(1, 127));
        b.b(...syn).b(NAK);
        b.b(...syn).cat(body).b(lrc);
      } else {
        b.b(lrc);
      }
      b.b(...syn).b(DLE, 0x30 + ack);
      ack ^= 1;
    }
    if (r.random() < 0.3) b.b(...syn).b(DLE, 0x3b);
    if (r.random() < 0.2) b.b(...syn).b(CAN);
    b.b(...syn).b(EOT);
    if (r.random() < 0.4) b.b(DLE, EOT);
    return ["bisync_block", b];
  }

  kinds() {
    return [() => this.tape_message(), () => this.report_page(), () => this.report_page(),
      () => this.unix_session(), () => this.dec_console(), () => this.local_tape(), () => this.bisync_block()];
  }
}

// ---------- the common driver (main() in both scripts) ----------
export const MODELS = Object.freeze({
  asr33: { title: "Teletype Model 33 ASR", file: "asr33_1971.txt", script: "asr33_gen.py" },
  asr37: { title: "Teletype Model 37 ASR", file: "asr37_1971.txt", script: "asr37_gen.py" }
});

export function randomSeed() {
  return globalThis.crypto.getRandomValues(new Uint32Array(1))[0];
}

// Returns { bytes: Uint8Array, seed, sessions: [{offset, length, type}] }.
export function generate(model, { seed = randomSeed(), size = 1_048_576, width = 72, parity = "space" } = {}) {
  if (!Number.isSafeInteger(size) || size < 2) throw new RangeError("size must be at least 2 bytes");
  const rng = new PyRandom(seed);
  let g;
  if (model === "asr33") g = new Gen33(rng);
  else if (model === "asr37") {
    if (!Number.isInteger(width) || width < 56 || width > 80) throw new RangeError("width must be 56 to 80");
    g = new Gen37(rng, width);
  } else throw new RangeError(`Unknown model: ${model}`);
  const kinds = g.kinds();
  const out = new Uint8Array(size);
  const sessions = [];
  let length = 0;
  for (;;) {
    const [type, chunk] = g.r.choice(kinds)();
    if (length + chunk.length > size - 2) break;
    sessions.push({ offset: length, length: chunk.length, type });
    out.set(chunk.a, length);
    length += chunk.length;
  }
  out[length] = EOT;                                   // then NUL to the exact size
  if (parity !== "space") {
    for (let i = 0; i < size; i += 1) {
      let ones = 0;
      for (let v = out[i]; v; v >>= 1) ones += v & 1;
      const bit = { mark: 1, even: ones & 1, odd: 1 - (ones & 1) }[parity];
      if (bit === undefined) throw new RangeError(`Unknown parity: ${parity}`);
      out[i] |= bit << 7;
    }
  }
  return { bytes: out, seed, sessions };
}

