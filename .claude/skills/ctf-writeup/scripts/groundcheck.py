#!/usr/bin/env python3
"""Read-only grounding gate for a CTF writeup.

Every load-bearing token in the post must trace back to the engagement notebook.
Prints violations and exits 1 if any; edits nothing. Targeted + high-signal (not a
full-text diff), so it stays quiet on prose and only fires on the three recurring
fabrication classes:

  1. Redaction fragments  — any `a…b` token's visible parts must be a verbatim
     substring of the notebook (catches invented redaction chars, e.g. `…b2c3`).
  2. "Used during the engagement" — each tool/link under that heading must appear in
     the notebook (catches room-template bookmarks mislabeled as used).
  3. Flags — every 32-hex flag printed in the post must appear in the notebook.

Usage: groundcheck.py <post.md> <engagement.ipynb> [<evidence-file> ...]

Extra evidence files (beyond the first, which is always parsed as an .ipynb)
are read as plain text and appended to the corpus verbatim. Use this only for
boxes whose engagement.ipynb is documented as empty/boilerplate and whose
real evidence lives in artifacts/ instead — list the specific artifact files
the post actually cites, not whole directories (some artifact trees contain
multi-GB binaries that don't belong in a text corpus).
"""
import json, re, sys


def notebook_corpus(path):
    nb = json.load(open(path))
    buf = []
    for c in nb.get("cells", []):
        buf.append("".join(c.get("source", [])))
        for o in c.get("outputs", []):
            if "text" in o:
                buf.append("".join(o["text"]))
            data = o.get("data", {})
            if "text/plain" in data:
                buf.append("".join(data["text/plain"]))
    return "".join(buf)


def text_corpus(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def norm(s):
    # alphanumeric-only, lowercased — so line-wraps, prompts, quotes and
    # underscores in the source don't cause false mismatches
    return re.sub(r"[^a-z0-9]", "", s.lower())


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    post = open(sys.argv[1]).read()
    raw = notebook_corpus(sys.argv[2])
    for extra in sys.argv[3:]:
        raw += "\n" + text_corpus(extra)
    corpus = norm(raw)          # alnum-only, for tool/flag membership checks
    corpus_lc = raw.lower()     # structure-preserving, for redaction contiguity
    v = []

    # 1. redaction — a `prefix…suffix` token must be the two ends of ONE contiguous
    #    value in the notebook (the elided middle spans only secret-ish chars, so a
    #    coincidental match of a short fragment elsewhere doesn't count as grounded).
    mid = r"[A-Za-z0-9+/=_.\-]*"
    for tok in re.findall(r"[^\s`\"']*…[^\s`\"']*", post):
        frags = [f for f in re.split(r"…+", tok) if f.strip()]
        if len(frags) < 2:
            f = norm(frags[0]) if frags else ""
            if len(f) >= 3 and f not in corpus:
                v.append(f"redaction fragment not in notebook: {tok!r}")
            continue
        pattern = mid.join(re.escape(f.lower()) for f in frags)
        if not re.search(pattern, corpus_lc):
            v.append(f"redaction not grounded as one contiguous value: {tok!r}")

    # 2. tools/links asserted as "used during the engagement"
    m = re.search(r"used during the engagement.*?(?=\n\s*\n|\n\s*\*\*|\Z)",
                  post, re.S | re.I)
    if m:
        for name in re.findall(r"\[([^\]]+)\]", m.group(0)):
            key = norm(name.split()[0]) if name.split() else ""
            if key and key not in corpus:
                v.append(f"'used during engagement' tool not in notebook: {name!r}")

    # 3. 32-hex flags printed in the post
    for flag in sorted(set(re.findall(r"\b[0-9a-f]{32}\b", post))):
        if norm(flag) not in corpus:
            v.append(f"flag not in notebook: {flag}")

    if v:
        print("GROUNDCHECK FAILED:")
        for x in v:
            print("  -", x)
        sys.exit(1)
    print("GROUNDCHECK OK")


if __name__ == "__main__":
    main()
