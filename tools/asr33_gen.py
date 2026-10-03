#!/usr/bin/env python3
"""
asr33_gen.py - random 1971-style Teletype Model 33 ASR line/tape capture generator.

Each run produces a different byte stream unless you pass --seed. The seed is always
printed, so any run can be reproduced exactly.

Every byte is 00-7F with bit 8 = 0 by default (--parity lets you change that).
Printable text is limited to the Model 33's 64-character upper-case set (20-5F),
with lines of at most 72 columns.

Control codes used, and what they did on or around an ASR-33 in 1971:
  00 NUL  blank tape (feed holes only): leader, trailer, CR fill time
  01 SOH  start of a WMO IA5 weather bulletin (punched on tape as a character)
  03 ETX  end of a WMO bulletin; also ^C = interrupt on DEC timesharing consoles
  04 EOT  end of transmission / disconnect on switched lines
  05 ENQ  WRU "Who Are You": trips the remote answerback drum
  07 BEL  bell (attention)
  0A LF   line feed
  0D CR   carriage return (followed by fill bytes: the carriage needs time)
  0F SI   ^O = suppress output (DEC TOPS-10 convention)
  11 DC1  X-ON:  tape reader on
  12 DC2  TAPE:  tape punch on
  13 DC3  X-OFF: tape reader off
  14 DC4  TAPE-OFF: tape punch off
  15 NAK  ^U = delete input line (DEC convention)
  1A SUB  ^Z = end of terminal input file (DEC convention)
  1B ESC  ALT MODE key: TECO command terminator (echoed by TECO as $)
  7F DEL  RUB OUT: all 7 holes punched over a mistake; readers skip it

The bisync_block session adds the synchronous ASCII Bisync (BSC) framing that a
communications link wrapped around the same 1971 data: SYN idle, SOH header, STX
text, ETB/ETX with an LRC, the DLE 0/1 ACKs, NAK-and-resend, DLE-stuffed
transparent blocks, CAN and EOT/DLE-EOT. SO/SI (alternate set) stay unused here.

Usage:
  python3 asr33_gen.py                      # 1 MiB file, new random content
  python3 asr33_gen.py -o test.txt --size 65536
  python3 asr33_gen.py --seed 1234          # reproduce a run
  python3 asr33_gen.py --index              # also write a JSON map of sessions
  python3 asr33_gen.py --parity even        # set bit 8 as real ASR-33 traffic did
"""
import argparse, json, os, random

NUL, SOH, ETX, EOT, ENQ, BEL, LF, CR = 0x00, 0x01, 0x03, 0x04, 0x05, 0x07, 0x0A, 0x0D
SI, DC1, DC2, DC3, DC4, NAK, SUB, ESC, DEL = 0x0F, 0x11, 0x12, 0x13, 0x14, 0x15, 0x1A, 0x1B, 0x7F
STX, ETB, SYN, DLE, CAN = 0x02, 0x17, 0x16, 0x10, 0x18

MONTHS = "JAN FEB MAR APR MAY JUN JUL AUG SEP OCT NOV DEC".split()
PLACES = ["NSUKKA", "ENUGU", "LAGOS", "KANO", "IBADAN", "PORT HARCOURT", "KADUNA",
          "JOS", "CALABAR", "ONITSHA", "ACCRA", "LONDON"]
ICAO = ["DNMM", "DNKN", "DNEN", "DNPO", "DNIB", "DNKA", "DNJO", "DNCA"]
WORDS = ("THE AND OF TO IN FOR ON AT BY WITH FROM REPORT PLANT PUMP VALVE LINE PRESSURE "
         "FLOW BEARING SHAFT MOTOR SUPPLY CARGO SHIPMENT DELAY ARRIVED DISPATCHED CONFIRM "
         "REQUEST APPROVED PENDING INSPECTION MAINTENANCE OVERHAUL SPARES ORDER UNITS "
         "COMPRESSOR TURBINE BOILER GENERATOR TRANSFORMER TEST RESULTS WITHIN LIMITS ADVISE "
         "IMMEDIATELY SCHEDULE WEEK MONTH ENGINEER CREW SHIFT OUTPUT RATED DRAWING REVISION "
         "ISSUED RECEIVED PORT CUSTOMS RAIL ROAD TRUCK VESSEL PAYMENT INVOICE STORES").split()
PROGS = ["PAYROL", "STRESS", "BEAM", "SURVEY", "HEAT", "FLOWNT", "GRADES", "INVTRY"]
EXTS = ["F4", "MAC", "DAT", "TXT", "BAS", "REL"]

class Gen:
    def __init__(self, rng):
        self.r = rng
        self.t = [rng.randrange(12), rng.randrange(28), rng.randrange(1440)]  # month, day, minute

    # ---------- helpers ----------
    def clock(self):
        self.t[2] += self.r.randint(1, 90)
        if self.t[2] >= 1440:
            self.t[2] -= 1440; self.t[1] += 1
        if self.t[1] >= 28:
            self.t[1] = 0; self.t[0] = (self.t[0] + 1) % 12
        return self.t[1] + 1, self.t[2] // 60, self.t[2] % 60

    def stamp(self):
        d, h, m = self.clock()
        return "%02d%02d%02dZ %s 71" % (d, h, m, MONTHS[self.t[0]])

    def words(self, lo=6, hi=16):
        return " ".join(self.r.choice(WORDS) for _ in range(self.r.randint(lo, hi)))

    def wrap(self, text, width=72):
        lines, cur = [], ""
        for w in text.split():
            if cur and len(cur) + 1 + len(w) > width:
                lines.append(cur); cur = w
            else:
                cur = (cur + " " + w) if cur else w
        return lines + ([cur] if cur else [])

    def eol(self, buf, fill=True):
        buf += bytes([CR, LF])
        if fill:
            buf += bytes(self.r.choice([[DEL], [DEL], [NUL], [DEL, DEL], [NUL, NUL]]))

    def typed(self, buf, line):
        """Operator typing on the ASR-33 keyboard, with rubout corrections."""
        room = 72 - len(line)                    # typo + rubout must not overrun column 72
        for ch in line:
            if room > 0 and self.r.random() < 0.005:
                room -= 1
                buf += self.r.choice("QWERTYUIOPASDFGHJKL").encode() + bytes([DEL])
            buf += ch.encode()
        self.eol(buf)

    def answerback(self):
        return "%05d %s NG" % (self.r.randint(10000, 99999), self.r.choice(PLACES)[:8])

    # ---------- session types ----------
    def tape_message(self):
        """Message prepared off-line on tape, then sent under reader/punch control."""
        b = bytearray()
        b += bytes(self.r.randint(30, 80))                       # NUL leader
        b += bytes([ENQ]); ab = self.answerback()
        self.eol(b, False); b += ab.encode(); self.eol(b, False)  # remote answerback
        if self.r.random() < 0.3:
            b += bytes([BEL] * self.r.randint(1, 5))
        b += bytes([DC2, DC1])                                   # punch on, reader on
        src, dst = self.r.sample(PLACES, 2)
        self.typed(b, "ZCZC %s%03d" % (src[:3], self.r.randint(1, 999)))
        self.typed(b, "%s FROM %s TO %s" % (self.stamp(), src, dst))
        text = " STOP ".join(self.words() for _ in range(self.r.randint(2, 6))) + " STOP ENDS"
        for ln in self.wrap(text):
            self.typed(b, ln)
        self.typed(b, "NNNN")
        b += bytes([DC3, DC4])                                   # reader off, punch off
        b += ab.encode(); self.eol(b, False)                     # HERE IS: own answerback
        b += bytes(self.r.randint(20, 60))                       # NUL trailer
        if self.r.random() < 0.5:
            b += bytes([EOT])
        return "tape_message", b

    def wmo_bulletin(self):
        """WMO IA5-format weather bulletin: SOH, lines ending CR CR LF, ETX."""
        b = bytearray()
        b += bytes(self.r.randint(10, 40))
        d, h, _ = self.clock()
        b += bytes([SOH]) + b"\r\r\n"
        b += b"%03d\r\r\n" % self.r.randint(0, 999)
        b += ("SMNI%02d %s %02d%02d00\r\r\n" % (self.r.randint(1, 99), self.r.choice(ICAO), d, h)).encode()
        for _ in range(self.r.randint(4, 14)):
            groups = ["652%02d" % self.r.randint(0, 99)] + \
                     ["%05d" % self.r.randint(0, 99999) for _ in range(self.r.randint(5, 10))]
            b += (" ".join(groups) + "=").encode() + b"\r\r\n"
        b += b"\r\r\n\n\n\n\n\n\n\n" + bytes([ETX])
        b += bytes(self.r.randint(10, 40))
        return "wmo_bulletin", b

    def console(self):
        """ASR-33 as a timesharing console on a DEC-style monitor."""
        b = bytearray()
        user = "[%d,%d]" % (self.r.randint(10, 99), self.r.randint(100, 999))
        b += b"."; b += ("LOGIN %s" % user).encode(); self.eol(b)
        b += ("JOB %d  UNN SYS 5.03  TTY%d" % (self.r.randint(1, 40), self.r.randint(0, 17))).encode(); self.eol(b)
        b += b"PASSWORD: "; self.eol(b)
        for _ in range(self.r.randint(3, 9)):
            act = self.r.random()
            prog = self.r.choice(PROGS); ext = self.r.choice(EXTS)
            b += b"."
            if act < 0.2:                                # line typed, then deleted with ^U
                b += ("RUN %s" % prog[:3]).encode() + bytes([NAK]) + b"^U"; self.eol(b); b += b"."
                b += ("RUN %s" % prog).encode(); self.eol(b)
                for _ in range(self.r.randint(2, 8)):
                    b += ("%8.3f %8.3f %8.3f" % tuple(self.r.uniform(0, 999) for _ in range(3))).encode(); self.eol(b)
                b += b"EXIT"; self.eol(b)
            elif act < 0.4:                              # long listing cut off with ^O
                b += ("TYPE %s.%s" % (prog, ext)).encode(); self.eol(b)
                for _ in range(self.r.randint(2, 6)):
                    b += self.wrap(self.words(8, 14))[0].encode(); self.eol(b)
                b += bytes([SI]) + b"^O"; self.eol(b)
            elif act < 0.6:                              # runaway program stopped with ^C
                b += ("EXECUTE %s.%s" % (prog, ext)).encode(); self.eol(b)
                for i in range(self.r.randint(3, 12)):
                    b += ("ITER %4d  RESID %.5E" % (i, self.r.uniform(1e-6, 1))).encode(); self.eol(b)
                b += bytes([ETX]) + b"^C"; self.eol(b)
            elif act < 0.8:                              # typing a file, ended with ^Z
                b += ("COPY %s.DAT=TTY:" % prog).encode(); self.eol(b)
                for _ in range(self.r.randint(2, 6)):
                    self.typed(b, " ".join(str(self.r.randint(0, 9999)) for _ in range(6)))
                b += bytes([SUB]) + b"^Z"; self.eol(b)
            else:                                        # TECO edit, ALT MODE = ESC
                b += ("TECO %s.%s" % (prog, ext)).encode(); self.eol(b)
                b += b"*"
                for c in ["S%s" % self.r.choice(WORDS), "-D", "I%s" % self.r.choice(WORDS), "0TT"]:
                    b += c.encode() + bytes([ESC])
                b += bytes([ESC]); self.eol(b)
                b += self.r.choice(WORDS).encode() + b" " + self.words(3, 6).encode(); self.eol(b)
                b += b"*EX" + bytes([ESC, ESC]); self.eol(b)
        if self.r.random() < 0.25:
            b += bytes([BEL]) + b"?QUOTA EXCEEDED"; self.eol(b); b += b"."
        b += b"K/F"; self.eol(b)
        b += ("JOB LOGGED OFF TTY AT %02d%02d" % self.clock()[1:]).encode(); self.eol(b)
        return "console", b

    def local_tape(self):
        """Operator punching tape off-line: punch on, typing, rubouts, punch off."""
        b = bytearray()
        b += bytes([DC2]) + bytes(self.r.randint(20, 50))
        for ln in self.wrap(" ".join(self.words() for _ in range(self.r.randint(3, 8)))):
            self.typed(b, ln)
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
        b += syn * r.randint(2, 4)                      # sync idle, then bid for the line
        b += bytes([ENQ])
        b += syn + bytes([DLE, 0x30])                   # ACK0: ready to receive
        n = r.randint(2, 5); ack = 1
        for i in range(n):
            src = r.choice(PLACES)
            header = "%s%05d" % (src[:3], r.randint(0, 99999))
            text = self.words()
            transparent = r.random() < 0.3
            corrupt = r.random() < 0.2
            end = ETX if i == n - 1 else ETB
            body = bytearray([SOH]) + header.encode()
            if transparent:                             # DLE STX ... DLE ETX, data DLE doubled
                body += bytes([DLE, STX]) + text.encode().replace(bytes([DLE]), bytes([DLE, DLE])) + bytes([DLE, end])
            else:
                body += bytes([STX]) + text.encode() + bytes([end])
            lrc = 0
            for c in body[1:]:
                lrc ^= c
            b += syn + body
            if corrupt:                                 # bad check byte, NAK, then a clean resend
                b += bytes([lrc ^ r.randint(1, 127)])
                b += syn + bytes([NAK])
                b += syn + body + bytes([lrc])
            else:
                b += bytes([lrc])
            b += syn + bytes([DLE, 0x30 + ack])         # ACK0 / ACK1, alternating
            ack ^= 1
        if r.random() < 0.3:
            b += syn + bytes([DLE, 0x3B])               # WACK: wait before send
        if r.random() < 0.2:
            b += syn + bytes([CAN])                     # block abandoned
        b += syn + bytes([EOT])                         # end of transmission
        if r.random() < 0.4:
            b += bytes([DLE, EOT])                      # disconnect
        return "bisync_block", b

def main():
    ap = argparse.ArgumentParser(description="Random 1971 Teletype Model 33 ASR byte-stream generator")
    ap.add_argument("-o", "--output", default="asr33_1971.txt")
    ap.add_argument("--size", type=int, default=1048576, help="exact output size in bytes (default 1 MiB)")
    ap.add_argument("--seed", type=int, help="reproduce a previous run")
    ap.add_argument("--parity", choices=["space", "even", "odd", "mark"], default="space",
                    help="bit 8: space=0 (default), or as real line traffic")
    ap.add_argument("--index", action="store_true", help="also write <output>.index.json")
    a = ap.parse_args()

    seed = a.seed if a.seed is not None else int.from_bytes(os.urandom(4), "big")
    g = Gen(random.Random(seed))
    kinds = [g.tape_message, g.tape_message, g.wmo_bulletin, g.console, g.local_tape, g.bisync_block]

    out, index = bytearray(), []
    while True:
        name, chunk = g.r.choice(kinds)()
        if len(out) + len(chunk) > a.size - 2:
            break
        index.append({"offset": len(out), "length": len(chunk), "type": name})
        out += chunk
    out += bytes([EOT])
    out += bytes(a.size - len(out))                  # NUL trailer to exact size
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
            json.dump({"seed": seed, "size": a.size, "sessions": index}, f, indent=1)
    print("wrote %s  %d bytes  seed=%d  sessions=%d  parity=%s"
          % (a.output, len(out), seed, len(index), a.parity))

if __name__ == "__main__":
    main()
