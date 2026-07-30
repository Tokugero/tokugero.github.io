---
layout: post
title: "What the Shard Displayed"
date: 2026-07-25 00:00:00 -0700
categories: ctfs
description: A 2-channel/2MHz sigrok logic capture of an unlabeled bus is identified as I2C, decoded with sigrok-cli, and reversed — via its SSD1306 OLED init sequence and framebuffer layout — into three rendered frames, the last of which is the flag.
parent: HackTheBox - Apocalypse '26
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
  - "hardware"
  - "i2c"
  - "logic-analyzer"
  - "sigrok"
  - "ssd1306"
  - "oled"
  - "cyberapocalypse"
---

## Engagement Notes

`what-the-shard-displayed` is a hardware-category challenge from Cyberapocalypse
2026. The provided evidence is a single sigrok capture file with no other context —
no schematic, no chip labels, no protocol hint beyond the two channels that were
recorded. The whole challenge is protocol identification from a blind logic
capture: figure out what bus is on the wire, what device is listening, and what
that device was being told to display.

The chain leans hard on search-driven identification rather than protocol
expertise going in — both the initial I2C guess and the eventual SSD1306 chip
match came from search tooling, not from recognizing the trace on sight — and
on reading a real display driver's source to invert its pixel-write logic into a
decoder. It is a clean, linear solve with no real dead-ends, just two loose
threads (other addresses briefly visible on the bus) that were noticed and set
aside because they didn't bear on the flag.

## Attack path

1. Unzip the provided `capture.sr` logic capture; `metadata` shows a 2-channel,
   2 MHz sigrok capture (`D0`/`D1`).
2. Open it in PulseView — a mostly-idle-high, 2-wire trace with dense burst
   regions. Search tooling suggested I2C as the candidate bus for a "high rest"
   2-wire signal.
3. Apply PulseView's I2C decoder to D0=SCL/D1=SDA — clean Start/Address/Data
   annotations confirm the read; the device address is `0x3C`.
4. Look up `0x3C` on i2cdevices.org — narrows to a handful of OLED/EEPROM-class
   parts, two of them Adafruit OLEDs with public GitHub drivers.
5. Re-run the same I2C decode with `sigrok-cli` to get a full text dump, then
   collapse it into one line per I2C transaction with `awk`.
6. Filter out the six transactions that aren't the repeating 17-byte pixel-data
   pattern — they contain a 26-byte init block and a 7-byte block, both to `0x3C`.
7. Search for the 26-byte init string verbatim; a Google AI-mode query on it names
   the SSD1306 driver chip and cites the Adafruit_SSD1306 library as one of the
   libraries that emits that exact init sequence.
8. Read `Adafruit_SSD1306::drawPixel()`'s buffer-indexing line to recover the
   framebuffer layout (page-major, one byte = 8 vertical pixels), and confirm
   the 128×64 dimensions directly from two of the init bytes.
9. Write a numpy/PIL decoder that filters the transaction dump down to pixel-data
   payloads, strips the control byte, and unpacks the concatenated stream against
   that layout — it divides evenly into exactly 3 frames.
10. Render and save the 3 frames. The third is the flag, rendered as pixel text.

## Reading the capture

```
[global]
sigrok version=0.5.2

[device 1]
capturefile=logic-1
total probes=8
samplerate=2 MHz
total analog=0
probe1=D0
probe2=D1
unitsize=1
```

Opened in PulseView, the raw trace on `D0`/`D1` is mostly idle-high with dense
burst regions — no protocol markers, no obvious clock/data split from the shape
alone:

![Raw D0/D1 trace in PulseView, showing two mostly-idle-high digital lines with dense burst regions](/assets/images/ctf/events/hackthebox-apocalypse-26/what-the-shard-displayed/pulseview-raw-d0-d1-trace.png)

> 🧠 Identifying this as I2C, before any decoder was applied, came from a Google AI
> search hint on the "high rest" 2-wire signal shape — not from recognizing the
> pattern as characteristically I2C from prior experience.

PulseView's I2C decoder applied to `D0`=SCL / `D1`=SDA turns the raw trace into
readable Start/Address/Data annotations:

![PulseView I2C decoder overlay showing Bits and Address/data annotation rows over the D0/D1 trace](/assets/images/ctf/events/hackthebox-apocalypse-26/what-the-shard-displayed/pulseview-i2c-decoder-annotations.png)

Zooming into one annotation gives the device address:

![PulseView zoomed annotation reading "Address write: 3C"](/assets/images/ctf/events/hackthebox-apocalypse-26/what-the-shard-displayed/pulseview-address-write-3c.png)

`0x3C` on i2cdevices.org/addresses narrows the candidate parts:

![i2cdevices.org address lookup for 0x3c listing SSD1305, SSD1306, PCF8578, PCF8569, SH1106, PCF8574AP](/assets/images/ctf/events/hackthebox-apocalypse-26/what-the-shard-displayed/i2cdevices-org-0x3c-matches.png)

> the first two are adafruit oled devices with links to github - the others are
> properietary with datasheets it looks like

Looking at the overall waveform shape at this point, three visually distinct
bursts of data stand out:

![PulseView view showing three visually distinct bursts of I2C activity separated by gaps](/assets/images/ctf/events/hackthebox-apocalypse-26/what-the-shard-displayed/pulseview-three-data-bursts.png)

## Getting a full transaction dump

The same decode was re-run through `sigrok-cli` to get the I2C stream as text:

```console
$ nix-shell -p sigrok-cli --run 'sigrok-cli -i artifacts/capture.sr -P i2c:scl=D0:sda=D1 -A i2c=address-write:address-read:data-write:data-read:start:stop > artifacts/i2c.txt'
$ wc -l artifacts/i2c.txt
4169 artifacts/i2c.txt
```

An `awk` script collapses the raw Start/Address/Data-write annotation lines into
one line per I2C transaction:

```console
$ awk '
    /: Start/                  { if (n) printf "txn %-4d addr=%s n=%-3d | %s\n", i++, a, n, out; out=""; n=0; a="??" }
    /: Address (read|write): / { a=$NF }
    /: Data write: /           { out = out (n?" ":"") $NF; n++ }
    END                        { if (n) printf "txn %-4d addr=%s n=%-3d | %s\n", i++, a, n, out }
  ' artifacts/i2c.txt > artifacts/txns.txt
$ head -8 artifacts/txns.txt
txn 0    addr=3C n=26  | 00 AE D5 80 A8 3F D3 00 40 8D 14 20 00 A1 C8 DA 12 81 CF D9 F1 DB 40 A4 A6 AF
txn 1    addr=3C n=7   | 00 21 00 7F 22 00 07
txn 2    addr=3C n=17  | 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
txn 3    addr=3C n=17  | 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
txn 4    addr=3C n=17  | 40 00 00 80 80 80 C0 C0 C0 60 60 60 30 30 30 30 30
txn 5    addr=3C n=17  | 40 18 18 18 18 18 18 18 0C 0C 0C 0C 0C 0C 0C 0C 0C
txn 6    addr=3C n=17  | 40 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 18 18 18 18 18 18
txn 7    addr=3C n=17  | 40 18 30 30 30 30 30 60 60 60 C0 C0 C0 80 80 80 00
```

Aggregating over the full transaction list makes the shape of the traffic
obvious:

```console
$ echo "=== addresses ===";          awk '{print $3}' artifacts/txns.txt | sort | uniq -c | sort -rn
=== addresses ===
    196 addr=3C
      1 addr=68
      1 addr=50
$ echo "=== control byte (pos0) ==="; awk '{print $6}' artifacts/txns.txt | sort | uniq -c | sort -rn
=== control byte (pos0) ===
    192 40
      6 00
$ echo "=== lengths ===";            awk '{print $4}' artifacts/txns.txt | sort -t= -k2 -n | uniq -c
=== lengths ===
      1 n=1
      1 n=2
      3 n=7
    192 n=17
      1 n=26
```

192 of the 196 transactions to `0x3C` are 17-byte writes starting with control
byte `0x40` — pixel data. The 6 outliers are the real command traffic:

```console
$ awk '$4 != "n=17"' artifacts/txns.txt
txn 0    addr=3C n=26  | 00 AE D5 80 A8 3F D3 00 40 8D 14 20 00 A1 C8 DA 12 81 CF D9 F1 DB 40 A4 A6 AF
txn 1    addr=3C n=7   | 00 21 00 7F 22 00 07
txn 66   addr=68 n=1   | 00
txn 67   addr=3C n=7   | 00 21 00 7F 22 00 07
txn 132  addr=50 n=2   | 00 00
txn 133  addr=3C n=7   | 00 21 00 7F 22 00 07
```

The 7-byte `0x3C` block repeats three times, each pair sandwiching a single
transaction to a different address (`0x68`, then `0x50`).

> 🧠 The `addr=68`/`addr=50` transactions were surfaced only by filtering for
> "whatever wasn't part of the normal stream of data" — no specific theory was
> formed about what those two addresses are; they were noted and set aside since
> they didn't bear on the OLED render or the flag.

## Identifying the chip and its framebuffer layout

Searching for the 26-byte init string verbatim turns up other hardware projects
using the identical byte sequence to bring up an OLED:

![Google search results for the 26-byte init hex string, showing Waveshare wiki pages with matching bytes](/assets/images/ctf/events/hackthebox-apocalypse-26/what-the-shard-displayed/google-search-init-string-hits.png)

A Google AI-mode query on the same string went further and named the specific
driver chip and the libraries that emit that init sequence:

![Google AI-mode result identifying the SSD1306 display driver chip and naming the Adafruit_SSD1306, u8glib/u8g2, and Tasmota libraries as sources of the init string](/assets/images/ctf/events/hackthebox-apocalypse-26/what-the-shard-displayed/google-ai-mode-ssd1306-identification.png)

> 🧠 As with the initial I2C guess, Google AI search — not the earlier
> i2cdevices.org shortlist on its own — is what actually narrowed the device down
> to SSD1306. The i2cdevices.org lookup produced candidates; the init-string
> search is what settled which one it was.

With the chip identified, [Adafruit_SSD1306](https://github.com/adafruit/Adafruit_SSD1306)'s
`drawPixel()` gives the memory layout directly:

```cpp
void Adafruit_SSD1306::drawPixel(int16_t x, int16_t y, uint16_t color) {
  if ((x >= 0) && (x < width()) && (y >= 0) && (y < height())) {
    // Pixel is in-bounds. Rotate coordinates if needed.
    switch (getRotation()) {
    case 1:
      ssd1306_swap(x, y);
      x = WIDTH - x - 1;
      break;
    case 2:
      x = WIDTH - x - 1;
      y = HEIGHT - y - 1;
      break;
    case 3:
      ssd1306_swap(x, y);
      y = HEIGHT - y - 1;
      break;
    }
    switch (color) {
    case SSD1306_WHITE:
      buffer[x + (y / 8) * WIDTH] |= (1 << (y & 7));
      break;
    case SSD1306_BLACK:
      buffer[x + (y / 8) * WIDTH] &= ~(1 << (y & 7));
      break;
    case SSD1306_INVERSE:
      buffer[x + (y / 8) * WIDTH] ^= (1 << (y & 7));
      break;
    }
  }
}
```

`A8 3F` in the init sequence says 64 rows; `21 00 7F` says 128 columns. One byte
in the buffer is a **vertical** run of 8 pixels (`buffer[x + (y/8)*WIDTH] |= (1
<< (y & 7))`), page-major over a 128-pixel-wide screen. Inverting that write into
a read is the entire decode.

> 🧠 The C++-to-Python translation of that buffer-indexing line — turning the
> write expression into the numpy reshape/unpack used below — was done with
> Claude Code's assistance.

## Decoding the framebuffer

```python
import numpy as np
from PIL import Image

W, H  = 128, 64
ADDR  = "3C"
FRAME = W * H // 8          # 1024 bytes per frame

# keep only 0x40 ("pixel data") transactions addressed to the display,
# strip the control byte, concatenate into one flat stream
stream = []
for line in open("artifacts/txns.txt"):
    head, _, payload = line.partition("|")
    b = payload.split()
    if f"addr={ADDR}" not in head or not b or b[0] != "40":
        continue
    stream += [int(x, 16) for x in b[1:]]

buf = np.frombuffer(bytes(stream), dtype=np.uint8)
n_frames, rem = divmod(buf.size, FRAME)
print(f"{buf.size} payload bytes = {n_frames} frames + {rem} leftover bytes")
assert rem == 0, "not a whole number of frames — check W/H or the 0x40 filter"

pages  = buf.reshape(-1, H // 8, W)                                   # (frame, page, x)
bits   = np.unpackbits(pages[..., None], axis=3, bitorder="little")   # + bit axis
frames = bits.transpose(0, 1, 3, 2).reshape(-1, H, W)                 # (frame, y, x)
print("frames array:", frames.shape)
```

```console
3072 payload bytes = 3 frames + 0 leftover bytes
frames array: (3, 64, 128)
```

The stream divides evenly into exactly 3 frames — no leftover bytes, confirming
the 128×64/8-per-frame layout is right. Rendered and saved:

![Frame 0: a pixel-art eye icon rendered from the decoded SSD1306 framebuffer](/assets/images/ctf/events/hackthebox-apocalypse-26/what-the-shard-displayed/frame0-eye-icon.png)

![Frame 1: a pixel-art clock face reading 05:17](/assets/images/ctf/events/hackthebox-apocalypse-26/what-the-shard-displayed/frame1-clock-0517.png)

![Frame 2: the flag rendered as pixel text — HTB open-brace, 3v3ry_crow_w3ars_h3r_3y3s, close-brace](/assets/images/ctf/events/hackthebox-apocalypse-26/what-the-shard-displayed/frame2-flag-text.png)

The third frame is the flag, read directly off the rendered image:

```
HTB{3v3ry_crow_w3ars_h3r_3y3s}
```

## What didn't work

No abandoned approaches — this was a single linear solve. The only loose threads
were the `addr=68` / `addr=50` transactions noted above, which were surfaced by
outlier-filtering the transaction dump and set aside once it was clear they
weren't part of the OLED write stream.

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| PulseView | Opened `capture.sr`, applied the I2C decoder, and visually confirmed the address/data structure and the 3-burst shape | [sigrok.org/wiki/PulseView](https://sigrok.org/wiki/PulseView) |
| `sigrok-cli` | Re-decoded the same capture to a full text transaction dump | [sigrok.org/wiki/Sigrok-cli](https://sigrok.org/wiki/Sigrok-cli) |
| i2cdevices.org | Looked up the `0x3C` device address to shortlist candidate chips | [i2cdevices.org/addresses](https://i2cdevices.org/addresses) |
| Google AI-mode search | Identified I2C as the candidate protocol from the raw trace shape, and named the SSD1306 chip from the init-string bytes | — |
| Claude Code | Assisted translating `Adafruit_SSD1306::drawPixel()`'s C++ buffer-indexing logic into the Python framebuffer decoder | [claude.com/claude-code](https://claude.com/claude-code) |

## Tactics (MITRE ATT&CK)

Not applicable. This is passive protocol reverse-engineering of a captured
hardware bus trace, not an attack against a live system — there is no MITRE
ATT&CK enterprise technique that matches the shape of what happened here.

## Lessons

> 🧠 Hardware specs are pretty simple to source: identify the first few
> distinctive bytes and just search for them directly — chances are it turns up
> a hint at the control protocol, and further distinctive byte sequences can
> narrow down the specific implementation. Once matching documentation is found,
> it was likely sourced from one real implementation, which makes any driver or
> library source for that chip a lot easier to read and adapt — especially when
> that source is open on GitHub.

## Further reading

**Used during the engagement:**
- [PulseView](https://sigrok.org/wiki/PulseView) — logic analyzer GUI used to view and decode the capture
- [sigrok-cli](https://sigrok.org/wiki/Sigrok-cli) — command-line decode used to produce the full transaction dump
- [i2cdevices.org/addresses](https://i2cdevices.org/addresses) — I2C device-address reference used to shortlist candidate chips
- [open-the-file.com/how-to/open-sr-on-linux](https://open-the-file.com/how-to/open-sr-on-linux) — reference used for opening/converting the `.sr` capture file
- [Adafruit_SSD1306](https://github.com/adafruit/Adafruit_SSD1306) — driver library whose `drawPixel()` gave the framebuffer layout

Claude Code assisted with the C++-to-Python translation of the framebuffer decode
(named by the operator, not in the notebook itself) — see the Tools used table above.

---

*Provenance: commands, outputs, credentials, and flags are transcribed from the
engagement notebook (credential material partially redacted). External facts (MITRE
technique definitions, CVEs, error semantics) are linked to their source and were
fetched, not recalled.*
