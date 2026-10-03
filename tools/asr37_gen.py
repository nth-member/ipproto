#!/usr/bin/env python3
"""
asr37_gen.py - random 1971-style Teletype Model 37 ASR line/tape capture generator.

Each run produces a different byte stream unless you pass --seed. The seed is always
printed, so any run can be reproduced exactly.

The Model 37 (introduced 1968): 150 baud / 15 characters per second, full 128-code
ASCII, 94 printing graphics including lower case, 72 columns at 10 per inch
(craftsman-adjustable up to 80: see --width), even parity as shipped.

Every byte is 00-7F with bit 8 = 0 by default (--parity even gives the set's own
transmission format).

Control codes used, and what they did on or around a Model 37 in 1971:
  00 NUL  blank tape (leader/trailer), fill
  03 ETX  ^C interrupt on DEC-style timesharing consoles
  04 EOT  end of transmission / disconnect; ^D end-of-input on Unix
  05 ENQ  WRU: trips the remote answerback
  07 BEL  bell
  08 BS   on-line backspace: underlining (x BS _) and overstrike
  09 HT   horizontal tab (option; stops assumed every 8 columns)
  0A LF   line feed; with the NEW LINE option also returns the carriage (Unix style)
  0B VT   vertical tab to the next form stop (option)
  0C FF   form feed to top of the next page (option)
  0D CR   carriage return
  0E SO   shift out to the alternate type set (e.g. Greek)
  0F SI   shift in to the normal set; ^O output suppression on DEC consoles
  11 DC1  X-ON:  tape reader on
  12 DC2  TAPE:  tape punch on
  13 DC3  X-OFF: tape reader off
  14 DC4  TAPE-OFF: tape punch off
  15 NAK  ^U line delete on DEC consoles
  1B ESC  ESC 7 reverse line feed, ESC 8 half reverse, ESC 9 half forward (option);
          also the ALT MODE key for TECO on DEC systems
  7F DEL  RUB OUT on tape; interrupt key on Unix

The bisync_block session adds the synchronous ASCII Bisync (BSC) framing layer
(SYN, SOH, STX, ETB, DLE, CAN and the DLE 0/1 ACKs) around the same data, as a
synchronous link would have carried it.

Usage:
  python3 asr37_gen.py                      # 1 MiB file, new random content
  python3 asr37_gen.py -o test.txt --size 65536
  python3 asr37_gen.py --seed 1234          # reproduce a run
  python3 asr37_gen.py --width 80           # craftsman-adjusted carriage
  python3 asr37_gen.py --index              # also write a JSON map of sessions
  python3 asr37_gen.py --parity even        # the Model 37's own transmitted parity
"""
import argparse, json, os, random

NUL, ETX, EOT, ENQ, BEL, BS, HT, LF, VT, FF, CR, SO, SI = 0, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15
DC1, DC2, DC3, DC4, NAK, ESC, DEL = 0x11, 0x12, 0x13, 0x14, 0x15, 0x1B, 0x7F
SOH, STX, ETB, SYN, DLE, CAN = 0x01, 0x02, 0x17, 0x16, 0x10, 0x18
REV_LF, HALF_UP, HALF_DOWN = b"\x1b7", b"\x1b8", b"\x1b9"

MONTHS = "January February March April May June July August September October November December".split()
PLACES = ["Nsukka", "Enugu", "Lagos", "Kano", "Ibadan", "Port Harcourt", "Kaduna", "Jos", "Accra", "London"]
WORDS = ("the and of to in for on at by with from report plant pump valve line pressure flow bearing "
         "shaft motor supply shipment delay arrived dispatched confirm request approved pending "
         "inspection maintenance overhaul spares order units compressor turbine boiler generator "
         "transformer test results within limits advise schedule week month engineer crew shift "
         "output rated drawing revision issued received stress strain load beam deflection heat "
         "transfer coefficient conduction boundary layer velocity profile specimen measured").split()
NAMES = ["Okafor", "Eze", "Adeyemi", "Bello", "Nwosu", "Okonkwo", "Hassan", "Obi", "Smith", "Brown"]
FILES = ["beam", "stress", "heat", "flow", "grades", "survey", "notes", "memo", "table", "calc"]

class Gen:
    def __init__(self, rng, width):
        self.r, self.W = rng, width
        self.t = [rng.randrange(12), rng.randrange(28), rng.randrange(1440)]

    # ---------- helpers ----------
    def clock(self):
        self.t[2] += self.r.randint(1, 90)
        if self.t[2] >= 1440: self.t[2] -= 1440; self.t[1] += 1
        if self.t[1] >= 28: self.t[1] = 0; self.t[0] = (self.t[0] + 1) % 12
        return self.t[1] + 1, self.t[2] // 60, self.t[2] % 60

    def date(self):
        d, h, m = self.clock()
        return "%d %s 1971  %02d:%02d" % (d, MONTHS[self.t[0]], h, m)

    def words(self, lo=6, hi=16):
        return " ".join(self.r.choice(WORDS) for _ in range(self.r.randint(lo, hi)))

    def sentence(self):
        return self.words().capitalize() + "."

    def wrap(self, text, width=None):
        width = width or self.W
        lines, cur = [], ""
        for w in text.split():
            if cur and len(cur) + 1 + len(w) > width: lines.append(cur); cur = w
            else: cur = (cur + " " + w) if cur else w
        return lines + ([cur] if cur else [])

    def nl(self, b, style):
        """style 'crlf' = CR LF plus fill; 'nl' = LF alone (NEW LINE option, Unix)."""
        if style == "nl":
            b += bytes([LF])
        else:
            b += bytes([CR, LF]) + bytes(self.r.choice([[], [], [NUL], [DEL]]))

    def typed(self, b, line, style):
        room = self.W - len(line)
        for ch in line:
            if room > 0 and self.r.random() < 0.005:
                room -= 1
                b += self.r.choice("qwertyuiopasdfghjkl").encode() + bytes([DEL])
            b += ch.encode()
        self.nl(b, style)

    def answerback(self):
        return "%05d %s NG" % (self.r.randint(10000, 99999), self.r.choice(PLACES)[:8].upper())

    def underline(self, word):
        return b"".join(bytes([ord(c), BS]) + b"_" for c in word)

    def greek(self, letters):
        return bytes([SO]) + letters.encode() + bytes([SI])

    def equation(self):
        """A line using half-line motion, Greek shift and backspace overstrike."""
        r = self.r
        k = r.choice(["Nu", "Re", "Pr", "q", "h", "k"])
        n1, n2 = r.randint(2, 3), r.randint(1, 9)
        forms = [
            b"(a + b)" + HALF_UP + b"2" + HALF_DOWN + b" = a" + HALF_UP + b"2" + HALF_DOWN +
            b" + 2ab + b" + HALF_UP + b"2" + HALF_DOWN,
            k.encode() + HALF_DOWN + b"x" + HALF_UP + b" = 0.%03d Re" % r.randint(1, 999) +
            HALF_DOWN + b"x" + HALF_UP + HALF_UP + b"0.%d" % r.randint(5, 8) + HALF_DOWN +
            b" Pr" + HALF_UP + b"1/3" + HALF_DOWN,
            self.greek("s") + b" = " + self.greek("e") + b" E,  E = %d GPa" % r.randint(69, 210),
            b"H" + HALF_DOWN + b"2" + HALF_UP + b"O at %d" % r.randint(20, 99) + HALF_UP + b"o" +
            HALF_DOWN + b"C,  " + self.greek("r") + b" = %d kg/m" % r.randint(958, 998) +
            HALF_UP + b"3" + HALF_DOWN,
            b"x" + HALF_UP + b"%d" % n1 + HALF_DOWN + b" - %dx + %d = 0" % (n2, r.randint(1, 20)),
        ]
        return r.choice(forms)

    # ---------- session types ----------
    def tape_message(self):
        """ASR 37 message prepared on tape, sent under reader/punch control."""
        b, st = bytearray(), "crlf"
        b += bytes(self.r.randint(30, 80))
        b += bytes([ENQ]); ab = self.answerback()
        self.nl(b, st); b += ab.encode(); self.nl(b, st)
        if self.r.random() < 0.3: b += bytes([BEL] * self.r.randint(1, 4))
        b += bytes([DC2, DC1])
        src, dst = self.r.sample(PLACES, 2)
        self.typed(b, "ZCZC %s%03d" % (src[:3].upper(), self.r.randint(1, 999)), st)
        self.typed(b, "%s  From %s to %s" % (self.date(), src, dst), st)
        for ln in self.wrap(" ".join(self.sentence() for _ in range(self.r.randint(2, 6)))):
            self.typed(b, ln, st)
        self.typed(b, "NNNN", st)
        b += bytes([DC3, DC4]); b += ab.encode(); self.nl(b, st)
        b += bytes(self.r.randint(20, 60))
        if self.r.random() < 0.5: b += bytes([EOT])
        return "tape_message", b

    def report_page(self):
        """Formatted page: FF, underlined heading, HT table, VT, equations, ESC 7 ruling."""
        b, st = bytearray(), self.r.choice(["crlf", "nl"])
        b += bytes([FF])
        title = "%s test sheet" % self.r.choice(["Beam", "Pump", "Boiler", "Specimen", "Turbine"])
        b += self.underline(title.upper()); b += b"     " + self.date().encode(); self.nl(b, st); self.nl(b, st)
        for ln in self.wrap(" ".join(self.sentence() for _ in range(self.r.randint(1, 3)))):
            b += ln.encode(); self.nl(b, st)
        self.nl(b, st)
        b += b"Item\tLoad\tStrain\tRemark"; self.nl(b, st)
        tot = 0
        for i in range(self.r.randint(3, 9)):
            v = self.r.randint(10, 999); tot += v
            b += ("%d\t%d\t%.4f\t" % (i + 1, v, self.r.uniform(0, 0.01))).encode()
            b += self.underline("ok") if self.r.random() < 0.7 else b"re" + bytes([BS, BS]) + b"__test"
            self.nl(b, st)
        b += ("Total\t%d" % tot).encode()
        b += bytes([CR]) + REV_LF + b"\t____" + bytes([LF])      # rule drawn above the total
        if st == "crlf": b += bytes([CR])
        self.nl(b, st)
        for _ in range(self.r.randint(1, 4)):
            b += self.equation(); self.nl(b, st)
        if self.r.random() < 0.5:
            b += bytes([VT]) + ("Checked by %s" % self.r.choice(NAMES)).encode(); self.nl(b, st)
        return "report_page", b

    def unix_session(self):
        """Unix-style session on a 37: LF newline, # erase, @ kill, DEL interrupt, ^D."""
        b, st = bytearray(), "nl"
        user = self.r.choice(NAMES).lower()
        b += b"login: "; b += user.encode(); self.nl(b, st)
        b += b"Password:"; self.nl(b, st)
        for _ in range(self.r.randint(3, 8)):
            b += b"% "
            act = self.r.random()
            f = self.r.choice(FILES)
            if act < 0.25:                                   # typing mistakes: # erases, @ kills
                b += ("ctat#" if self.r.random() < 0.5 else "cay#t").encode()
                b += (" %s" % f).encode(); self.nl(b, st)
                for ln in self.wrap(" ".join(self.sentence() for _ in range(self.r.randint(1, 4)))):
                    b += ln.encode(); self.nl(b, st)
            elif act < 0.45:
                b += ("ls -l %s" % f).encode() + b"@"; self.nl(b, st); b += b"ls"; self.nl(b, st)
                for g in self.r.sample(FILES, self.r.randint(2, 6)):
                    b += g.encode(); self.nl(b, st)
            elif act < 0.7:                                  # nroff output with 37 escapes
                b += ("nroff %s" % f).encode(); self.nl(b, st)
                for _ in range(self.r.randint(1, 3)):
                    for ln in self.wrap(" ".join(self.sentence() for _ in range(3)), self.W - 8):
                        b += b"        " + ln.encode(); self.nl(b, st)
                    b += b"        " + self.equation(); self.nl(b, st)
            elif act < 0.85:                                 # runaway output stopped with DEL
                b += ("cat %s" % f).encode(); self.nl(b, st)
                for _ in range(self.r.randint(2, 6)):
                    b += self.wrap(self.sentence())[0].encode(); self.nl(b, st)
                b += bytes([DEL]); self.nl(b, st)
            else:                                            # ed session ended with .
                b += ("ed %s" % f).encode(); self.nl(b, st)
                b += b"%d" % self.r.randint(100, 4000); self.nl(b, st)
                b += b"a"; self.nl(b, st)
                for _ in range(self.r.randint(1, 4)):
                    b += self.wrap(self.sentence())[0].encode(); self.nl(b, st)
                b += b"."; self.nl(b, st); b += b"w"; self.nl(b, st)
                b += b"%d" % self.r.randint(100, 4000); self.nl(b, st); b += b"q"; self.nl(b, st)
        if self.r.random() < 0.2: b += bytes([BEL])
        b += b"% " + bytes([EOT])
        self.nl(b, st)
        return "unix_session", b

    def dec_console(self):
        """37 on a DEC-style monitor: CR LF, ^C, ^U, ^O, TECO ALT MODE."""
        b, st = bytearray(), "crlf"
        b += b".LOGIN %d,%d" % (self.r.randint(10, 99), self.r.randint(100, 999)); self.nl(b, st)
        for _ in range(self.r.randint(2, 6)):
            b += b"."
            f = self.r.choice(FILES).upper()
            act = self.r.random()
            if act < 0.3:
                b += b"RUN " + f[:2].encode() + bytes([NAK]) + b"^U"; self.nl(b, st)
                b += b".RUN " + f.encode(); self.nl(b, st)
                for i in range(self.r.randint(2, 8)):
                    b += ("Iter %3d  resid %.4E" % (i, self.r.uniform(1e-6, 1))).encode(); self.nl(b, st)
                b += bytes([ETX]) + b"^C"; self.nl(b, st)
            elif act < 0.6:
                b += ("TYPE %s.TXT" % f).encode(); self.nl(b, st)
                for _ in range(self.r.randint(2, 5)):
                    b += self.wrap(self.sentence())[0].encode(); self.nl(b, st)
                b += bytes([SI]) + b"^O"; self.nl(b, st)
            else:
                b += ("TECO %s.TXT" % f).encode(); self.nl(b, st); b += b"*"
                for c in ["S%s" % self.r.choice(WORDS), "-D", "I%s" % self.r.choice(WORDS), "0TT"]:
                    b += c.encode() + bytes([ESC])
                b += bytes([ESC]); self.nl(b, st)
                b += self.wrap(self.sentence())[0].encode(); self.nl(b, st)
                b += b"*EX" + bytes([ESC, ESC]); self.nl(b, st)
        b += b".K/F"; self.nl(b, st)
        return "dec_console", b

    def local_tape(self):
        """Operator punching tape off-line with rubouts."""
        b = bytearray([DC2]) + bytes(self.r.randint(20, 50))
        for ln in self.wrap(" ".join(self.sentence() for _ in range(self.r.randint(3, 8)))):
            self.typed(b, ln, "crlf")
        b += bytes(self.r.randint(20, 50)) + bytes([DC4])
        return "local_tape", b

    def bisync_block(self):
        """ASCII Bisync (BSC) block traffic: the synchronous framing wrapped
        around the same data. SYN idle, an ENQ bid, SOH header and STX text
        closed by ETB/ETX with an LRC, ACK0/ACK1, the odd NAK-and-resend,
        DLE-stuffed transparent blocks, CAN, and EOT/DLE-EOT to end."""
        r = self.r
        b = bytearray()
        syn = bytes([SYN, SYN])
        b += syn * r.randint(2, 4)
        b += bytes([ENQ])
        b += syn + bytes([DLE, 0x30])
        n = r.randint(2, 5); ack = 1
        for i in range(n):
            src = r.choice(PLACES)
            header = "%s%05d" % (src[:3].upper(), r.randint(0, 99999))
            text = self.sentence()
            transparent = r.random() < 0.3
            corrupt = r.random() < 0.2
            end = ETX if i == n - 1 else ETB
            body = bytearray([SOH]) + header.encode()
            if transparent:
                body += bytes([DLE, STX]) + text.encode().replace(bytes([DLE]), bytes([DLE, DLE])) + bytes([DLE, end])
            else:
                body += bytes([STX]) + text.encode() + bytes([end])
            lrc = 0
            for c in body[1:]:
                lrc ^= c
            b += syn + body
            if corrupt:
                b += bytes([lrc ^ r.randint(1, 127)])
                b += syn + bytes([NAK])
                b += syn + body + bytes([lrc])
            else:
                b += bytes([lrc])
            b += syn + bytes([DLE, 0x30 + ack])
            ack ^= 1
        if r.random() < 0.3:
            b += syn + bytes([DLE, 0x3B])
        if r.random() < 0.2:
            b += syn + bytes([CAN])
        b += syn + bytes([EOT])
        if r.random() < 0.4:
            b += bytes([DLE, EOT])
        return "bisync_block", b

def main():
    ap = argparse.ArgumentParser(description="Random 1971 Teletype Model 37 ASR byte-stream generator")
    ap.add_argument("-o", "--output", default="asr37_1971.txt")
    ap.add_argument("--size", type=int, default=1048576, help="exact output size in bytes (default 1 MiB)")
    ap.add_argument("--seed", type=int, help="reproduce a previous run")
    ap.add_argument("--width", type=int, default=72, choices=range(56, 81), metavar="56-80",
                    help="carriage width in columns (default 72)")
    ap.add_argument("--parity", choices=["space", "even", "odd", "mark"], default="space",
                    help="bit 8: space=0 (default); the Model 37 itself sent even")
    ap.add_argument("--index", action="store_true", help="also write <output>.index.json")
    a = ap.parse_args()

    seed = a.seed if a.seed is not None else int.from_bytes(os.urandom(4), "big")
    g = Gen(random.Random(seed), a.width)
    kinds = [g.tape_message, g.report_page, g.report_page, g.unix_session, g.dec_console, g.local_tape, g.bisync_block]

    out, index = bytearray(), []
    while True:
        name, chunk = g.r.choice(kinds)()
        if len(out) + len(chunk) > a.size - 2:
            break
        index.append({"offset": len(out), "length": len(chunk), "type": name})
        out += chunk
    out += bytes([EOT])
    out += bytes(a.size - len(out))
    del out[a.size:]

    if a.parity != "space":
        for i, c in enumerate(out):
            ones = bin(c).count("1")
            bit = {"mark": 1, "even": ones & 1, "odd": 1 - (ones & 1)}[a.parity]
            out[i] = c | (bit << 7)

    with open(a.output, "wb") as f:
        f.write(out)
    if a.index:
        with open(a.output + ".index.json", "w") as f:
            json.dump({"seed": seed, "size": a.size, "width": a.width, "sessions": index}, f, indent=1)
    print("wrote %s  %d bytes  seed=%d  sessions=%d  width=%d  parity=%s"
          % (a.output, len(out), seed, len(index), a.width, a.parity))

if __name__ == "__main__":
    main()
