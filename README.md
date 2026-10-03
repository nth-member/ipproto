# IPPROTO

**The 256 IP protocol numbers, in 13 categories.** Served at https://nth-member.github.io/ipproto/.
Everything runs in the page; `docs/` is the site.

The Protocol field of an IPv4 header, and the Next Header field of an IPv6 header, is one byte that
names what the packet carries: 6 is TCP, 17 is UDP, 50 is IPsec ESP, and so on to 255. IANA keeps the
registry; IPPROTO shows it, reads captures against it, and generates captures from it.

| tab | what it does |
|---|---|
| **Map** | all 256 numbers on a 16 × 16 grid: colour shows status (in common use, assigned, historic, deprecated, placeholder/experimental/reserved, unassigned), a two-letter code shows the category; each number's protocol, RFCs, IPv6 extension-header flag and a tcpdump filter |
| **Capture** | reads a `.pcap` or `.pcapng` file made with tcpdump or Wireshark, in the browser, and counts the traffic by protocol number and by category, with flags, a timeline, tunnels, IPv6 extension headers, non-IP traffic and the busiest address pairs |
| **Bridge** | builds a `.pcap` file from a 1971 Teletype Model 33 or 37 test stream, cut into packets carried by the protocol numbers chosen: every number, one per category, one category, or one number |
| **Colours** | each protocol number as a coloured SPAN, by an 8-bit extension of Gigaspeak's Calc28 scheme |

A row of 13 category chips filters every tab.

## The 13 categories

IANA publishes the numbers without categories; these are IPPROTO's grouping. Every number is in
exactly one.

| code | category | numbers |
|---|---|---:|
| CO | Core control and IPv6 machinery | 8 |
| TR | Transport protocols | 25 |
| RO | Routing and router redundancy | 15 |
| MC | Multicast | 3 |
| TU | Tunnelling and encapsulation | 18 |
| SE | Security and encryption | 11 |
| MO | Mobility and multihoming | 4 |
| QS | Quality of service, label switching, compression | 7 |
| AR | Address resolution | 2 |
| MN | Monitoring and measurement | 10 |
| AP | Early ARPA/DARPA research networks | 15 |
| VN | Vendor and non-IP network stacks | 25 |
| SP | Placeholders, experiments, reserved, unassigned | 113 |

"In common use" marks the numbers seen on present-day networks; it is this site's judgement.

## Data

`docs/data/protocols.json` is built from IANA's CSV by `node tools/build.mjs`. The build is idempotent:
it records IANA's own "updated" date, so an unchanged registry rebuilds to an identical file. Only RFC
numbers are kept from IANA's references, which otherwise name individual registrants.

## Capture reader

`docs/lib/pcap.mjs` reads classic pcap (either byte order, micro- or nanosecond timestamps) and pcapng
(sections, interfaces, enhanced, simple and obsolete packet blocks, `if_tsresol`). `docs/lib/decode.mjs`
decodes Ethernet (with 802.1Q/802.1ad tags), Linux SLL and SLL2, raw IP and BSD/OpenBSD loopback; IPv4,
including AH and fragments; the IPv6 Next Header chain (0, 43, 44, 51, 60, 135, 139, 140, 253, 254);
and the tunnels IP-in-IP (4, 94), IPv6-in-IP (41), GRE (47), EtherIP (97), MPLS-in-IP (137) and
Ethernet (143), whose inner packets are decoded in turn. ESP (50) is encrypted and is not looked into.
A packet is counted under every protocol number it contains and every category those numbers belong
to; "carried" counts its innermost protocol only.

The file is read in the browser and never uploaded. A web page cannot capture traffic itself;
`sudo tcpdump -i any -nn -w capture.pcap` makes a file to open.

## Bridge

`docs/lib/bridge.mjs` cuts a stream from `docs/lib/teletype.mjs` (the byte-exact port of
`tools/asr33_gen.py` and `tools/asr37_gen.py`, shared with Gigaspeak) into packets and writes raw-IP
pcap. Protocols with a structure have it: TCP to port 23 (Telnet), UDP, ICMP and ICMPv6 echo; tunnels
around an inner UDP packet; ESP and AH; IPv6 packets with real extension-header chains. Every other
number carries the teletype bytes directly. Packets are timed at 10 characters a second (Model 33) or
15 (Model 37) from 1 June 1971, 09:00 UTC, between addresses from the documentation ranges.

## Colours

Gigaspeak's Calc28 scheme carries seven bits: foreground R, G, B are bits 6, 5, 4 (`00`/`AA`), and the
background has base `00`/`55` from bit 3 plus `AA` on R, G, B for bits 2, 1, 0. IPPROTO adds bit 7 as
the foreground's base, as bit 3 is the background's. Numbers 0–127 therefore have exactly Gigaspeak's
colours, and all 256 pairs are distinct. This extension is IPPROTO's own, not part of MDQNM. The
Colours tab can also open a capture's protocol keywords in Gigaspeak.

## Local use and verification

```bash
cd docs && python3 -m http.server 8000     # the site, as GitHub Pages serves it
npm test                                   # Node 20 or later; uses tcpdump when installed
node tools/build.mjs                       # rebuild the registry data from IANA
```

`npm test` checks the registry (256 numbers, 13 categories, every number once); every capture format
and link layer above, each also read by `tcpdump -r`; that for a bridge capture of all 256 numbers the
decoder reads the same protocol number as tcpdump for every packet (`ip[9] == n`, `ip6[6] == n`), and
that all 13 categories, all seven tunnels and all seven IPv6 extension headers are present; the 1971
timing; the flags; the colour extension against Gigaspeak's colours; and the teletype streams against
the Python scripts.

## The nth-member sites

| site | repository | what it is |
|---|---|---|
| https://nth-member.github.io/revott/ | nth-member/revott | REVOTT atop GDELT: the field at every node of an instance |
| https://nth-member.github.io/gdelt/ | nth-member/gdelt | what GDELT was reading on a given day |
| https://nth-member.github.io/member/ | nth-member/member | the nth member: REVOTT's numerator, its introspection and its journal |
| https://nth-member.github.io/gematria/ | nth-member/gematria | H-Gematria/ASCII: the two name-value programs in the browser |
| https://nth-member.github.io/alien-corridor/ | nth-member/alien-corridor | the Alien Corridor Support System (MDQNM engine) in the browser |
| https://nth-member.github.io/gigaspeak/ | nth-member/gigaspeak | Gigaspeak: ASCII carried in colour, the speaker, the URL builder and the Communicator |
| https://nth-member.github.io/tsots_value_equation/ | nth-member/tsots_value_equation | the TSOTS value equation: a synthetic simulation of the Shula, run in the browser |
| https://nth-member.github.io/ipproto/ | nth-member/ipproto | IPPROTO: the 256 IP protocol numbers in 13 categories, a capture reader and a packet bridge |
