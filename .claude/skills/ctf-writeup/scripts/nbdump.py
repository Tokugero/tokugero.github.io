#!/usr/bin/env python3
"""Reconstruct an HTB/THM engagement notebook for writeup authoring.

Usage:
  nbdump.py <engagement.ipynb> summary            # cell counts, richness, Final-chain detection
  nbdump.py <engagement.ipynb> cells [maxout]     # every cell: type + source + truncated output
  nbdump.py <engagement.ipynb> urls               # every URL embedded in the notebook (verbatim)
  nbdump.py <engagement.ipynb> attachments <dir>  # dump embedded images to <dir>, print manifest

Notes for the author/agent:
  - "cells" truncates each code cell's output to `maxout` chars (default 1500) to keep
    context small. Re-run a single cell's full output with your own tooling only if a
    decisive line was cut.
  - A markdown cell titled "## Final chain" (or similar) is the author's own cleaned-up
    replay — prefer it to disambiguate the working path from exploration/dead-ends.
"""
import base64
import json
import os
import re
import sys


def load(path):
    with open(path) as f:
        return json.load(f)


def cell_text(c):
    return "".join(c.get("source", []))


def cell_output_text(c):
    out = []
    for o in c.get("outputs", []):
        if o.get("output_type") == "stream":
            out.append("".join(o.get("text", [])))
        elif "text/plain" in o.get("data", {}):
            out.append("".join(o["data"]["text/plain"]))
    return "".join(out)


def cmd_summary(nb):
    cells = nb["cells"]
    md = sum(1 for c in cells if c["cell_type"] == "markdown")
    code = sum(1 for c in cells if c["cell_type"] == "code")
    with_out = sum(1 for c in cells if c["cell_type"] == "code" and c.get("outputs"))
    src = sum(len(cell_text(c)) for c in cells)
    print(f"cells={len(cells)} markdown={md} code={code} code_with_output={with_out} source_bytes={src}")
    # Final-chain / summary sections
    for i, c in enumerate(cells):
        t = cell_text(c).strip().lower()
        if c["cell_type"] == "markdown" and re.match(r"#+\s*(final chain|summary|tl;?dr|the chain)", t):
            print(f"AUTHOR-SUMMARY cell [{i}]: {cell_text(c).strip().splitlines()[0]}")
    # attachment count
    n_att = sum(len(c.get("attachments") or {}) for c in cells)
    if n_att:
        print(f"attachments={n_att} (run 'attachments <dir>' to extract)")


def cmd_cells(nb, maxout=1500):
    for i, c in enumerate(nb["cells"]):
        print(f"===== CELL {i} [{c['cell_type']}] =====")
        print(cell_text(c).rstrip())
        if c["cell_type"] == "code":
            txt = cell_output_text(c)
            if txt:
                print("--- OUTPUT ---")
                print(txt[:maxout])
                if len(txt) > maxout:
                    print(f"[... {len(txt) - maxout} more chars of output truncated ...]")
        print()


def cmd_urls(nb):
    urls = set()
    for c in nb["cells"]:
        for m in re.findall(r"https?://[^\s\)\"'>]+", cell_text(c)):
            urls.add(m.rstrip(".,"))
    for u in sorted(urls):
        print(u)


def cmd_attachments(nb, outdir):
    os.makedirs(outdir, exist_ok=True)
    n = 0
    for i, c in enumerate(nb["cells"]):
        for name, att in (c.get("attachments") or {}).items():
            for mime, data in att.items():
                ext = mime.split("/")[-1]
                p = os.path.join(outdir, f"cell{i}_{n}.{ext}")
                with open(p, "wb") as f:
                    f.write(base64.b64decode(data))
                print(f"cell {i}: {mime} -> {p}")
                n += 1
    print(f"total attachments: {n}")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    nb = load(sys.argv[1])
    cmd = sys.argv[2]
    if cmd == "summary":
        cmd_summary(nb)
    elif cmd == "cells":
        cmd_cells(nb, int(sys.argv[3]) if len(sys.argv) > 3 else 1500)
    elif cmd == "urls":
        cmd_urls(nb)
    elif cmd == "attachments":
        cmd_attachments(nb, sys.argv[3])
    else:
        print(f"unknown command: {cmd}\n{__doc__}")
        sys.exit(1)


if __name__ == "__main__":
    main()
