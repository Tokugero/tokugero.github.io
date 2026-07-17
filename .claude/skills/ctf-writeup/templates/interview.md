---
box: <box-slug>
event: <event-slug>
notebook: <absolute path to engagement.ipynb>
status: interviewing        # interviewing → answered → verifying → drafted → published
---

# Interview ledger — <box>

**How to use this file.** Answer inline under each `**A:**` line, in any order,
whenever you like. This is the interview: the scribe wrote the questions here
instead of asking in chat so several boxes can be worked at once. When you've
answered what you can for this box, tell the orchestrator "<box> done" and it
resumes the scribe, which reads your answers straight from this file.

- Blank or "don't recall" / "didn't check" is a **valid answer** — it maps to
  `⚠️ observed-only` (state what the output shows, omit the why). Never a prompt
  to invent something.
- If a question needs more context before you can answer, write `NEEDS CONTEXT`
  under `**A:**`; the scribe will quote the exact notebook fragment and re-ask.
- This file is ephemeral and gitignored (`.interviews/`). It is **deleted on
  publish** — the published post is the durable record.

---

## Reconstructed chain (scribe's draft — correct anything wrong)

<numbered working path>

### Dead-end candidates
<bullets — the scribe's guess at what to file under "what didn't work">

---

## Structural rulings (defaults in _italics_ — overwrite the `**A:**` to change)

- **Dead-ends** — _keep as "what didn't work" with why_ / cut / one-line
  **A:**
- **Big blobs & log-spam** — _elide to the decisive fragment with a marker_ / `<details>` / verbatim
  **A:**
- **Credential material** — _partially redact_ (`f29e9c01…be3b`) / verbatim / fully redact
  **A:**
- **Event placement** — new `seasonN-htb-YY` event / existing `htb-machines`
  **A:**

---

## Questions

<!-- Each question is grounded: it quotes the verbatim notebook evidence, states
     the fact, and asks only the interpretation. Flip [PENDING] → [ANSWERED] is
     the scribe's job once it consumes your answer; you only fill **A:**. -->

### Q1 [PENDING] <short title>
> <verbatim command + the decisive output line(s) it's about>

<the why / what-it-meant / what-was-learned question>
**A:**

### Q2 [PENDING] <short title>
> <verbatim evidence>

<question>
**A:**
