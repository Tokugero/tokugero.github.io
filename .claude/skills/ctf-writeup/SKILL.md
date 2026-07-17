---
name: ctf-writeup
description: Turn an HTB/THM engagement notebook (~/ctf/htb/**/engagement.ipynb) into a narrow, fact-checked, tag-indexed Jekyll writeup on this blog. Reconstruct the chain, interview the operator for the reasoning that isn't in the notebook, verify every external fact and link, then assemble and build. Use when publishing a CTF/box writeup from a Jupyter engagement notebook.
allowed-tools: Read, Write, Edit, Bash, Glob, Grep, WebFetch, WebSearch, AskUserQuestion, Skill
---

# ctf-writeup

Convert a CTF engagement notebook into a published Jekyll post. The notebook is a
**command log** (what was run); the writeup adds the **reasoning log** (why) — which
lives only in the operator's head and must be drawn out by interview. The operator
answers questions; this pipeline does everything else and never invents facts.

Scripts live beside this file: `scripts/nbdump.py`, `scripts/linkcheck.sh`,
`templates/post.md`. Reference them by absolute path from the skill directory.

## Golden rules (non-negotiable)

1. **No fact from memory.** Two classes of fact:
   - *Internal* (commands, outputs, creds, flags): transcribed from the notebook.
     Do **not** annotate with `(cell N)` markers — they rot. Provenance is implicit.
   - *External* (MITRE IDs, CVEs, error semantics, exam rules, tool URLs): **fetch
     and cite the source URL**, or omit. Never recall from memory.
2. **Verify or omit — including links.** HTTP-check every URL. Harvest the operator's
   own links verbatim (see Step 1); any link you *add* must resolve or be left
   `ToolName — source not identified`. A fabricated repo URL is the #1 silent failure.
3. **Only tag techniques whose official definition matches.** Pull the ATT&CK page,
   read the definition, tag only if it fits. Add a "not tagged, and why" note for
   rejected ones. (Pilots: T1505.003 Web Shell ≠ one-shot reverse WAR; T1110.003
   Password Spraying needs many accounts, not one.)
4. **Impersonal voice.** No first person (I/we/my) and no reader-addressing "you".
   "The share was writable, so a payload was dropped" — not "I dropped a payload".
   Applies to narrative, 🧠 reflections, and lessons alike. Reflections stay honest
   and specific but read as abstract observations.
5. **Unsourceable claim → mark it,** never assert. Use `> ⚠️ UNVERIFIED:`.
6. **Verbatim or prose — never a reconstructed transcript.** Every fenced
   console/code block must be copied from a notebook cell (code source, cell output,
   or a markdown cell holding a pasted transcript). Do **not** synthesize a block, or
   re-port a block from one stage into another to fill a gap — the ports, users, and
   outputs will be wrong. If a step is evidenced only by a screenshot you cannot read
   as text, describe it in prose ("the screenshot shows …") and cite no console block.
   (Pilot: a foothold catcher on `:8888` was back-filled with the analyst-stage
   `nc -lvn 8889` block — wrong port, wrong stage.) A box's **target IP may differ
   across cells** — HTB reassigns it on respawn/reset (a solve spanning >1 box
   lifetime, or a reset of a stuck box). Keep each IP verbatim; never normalize a
   later IP to an earlier one, and never read the change as an inconsistency or a
   fabrication signal. (Pilot: paperwork — recon/foothold on `…81`, root SSH on
   `…95` after a day-2 respawn; both real.)
7. **Redaction is truncation, not substitution.** When partially redacting a secret,
   the visible characters MUST be a verbatim substring of the real value — a real
   prefix (optionally plus the real last-N chars) with the elided middle as `…`. Never
   invent, guess, or "vibe" replacement characters, and use the `…` (U+2026) ellipsis
   so the ground-check can find it. (Pilot: `opsmcp_secret_key_4f5a…b2c3` — the `b2c3`
   was fabricated; the real key ends `0f1a`.)
8. **"Used" means evidenced by a notebook cell.** A tool, link, or command counts as
   "used during the engagement" only if it appears in a notebook cell (command or
   output) or the operator named it in the interview. `site/links.md`, `utils/`,
   READMEs, and other room-template scaffolding are generic bookmarks shipped with
   every box — never assert them as used. (Pilot: pspy/linpeas/msfvenom from
   `site/links.md` were listed as "used" on a box whose chain touched none of them.)
9. **Ground the interview or the operator confabulates.** Every question quotes the
   real notebook evidence, states the fact and asks only the interpretation, stays
   non-leading (no single cause to nod at), and treats "I don't recall" as a valid
   answer → `⚠️ observed-only`. A thin one-line prompt makes the operator invent
   answers without noticing. (See Step 2.)
7. **Guardrails:** never read `~/ctf/vpn/` (cleartext VPN creds). **OSCP+ prep is
   private tuning context — never surface it in any published content.**

## Pipeline

### Step 0 — Inputs
Confirm the notebook path (`~/ctf/htb/<group>/<box>/engagement.ipynb`) and the box
name. Note the room dir alongside it (has `site/links.md`, `artifacts/`, `payloads/`).

Open the **interview ledger** for this box: `<site-root>/.interviews/<box>.md` (copy
`templates/interview.md`). It is the single source of truth for the interview —
gitignored, ephemeral, one file per box so several boxes can be interviewed at once
(see **Parallel crawl** below). Fill its frontmatter (`box`, `event`, `notebook`,
`status: interviewing`).

### Step 1 — Reconstruct & harvest
```bash
python3 <skilldir>/scripts/nbdump.py <notebook> summary        # richness + Final-chain detection
python3 <skilldir>/scripts/nbdump.py <notebook> cells          # cells + truncated outputs
python3 <skilldir>/scripts/nbdump.py <notebook> urls           # embedded URLs (operator's sources)
python3 <skilldir>/scripts/nbdump.py <notebook> attachments <scratch>/img   # extract screenshots
cat <box>/site/links.md 2>/dev/null                            # generic room-template bookmarks — NOT proof of use
# Embedded exploit repos = real tools the operator cloned & used → citation sources:
find <box> -name .git -maxdepth 4 \( -type d -o -type f \) 2>/dev/null | \
  while read g; do d=$(dirname "$g"); echo "$d → $(git -C "$d" remote get-url origin 2>/dev/null)"; done
```
- If a **`## Final chain`** (or Summary/TL;DR) cell exists, it is the operator's own
  clean replay — use it to separate the **working path** from **exploration/dead-ends**.
- **Embedded notebook URLs** (from `nbdump.py … urls`) are the operator's real
  sources — harvest verbatim, never regenerate. **`site/links.md` is generic room
  scaffolding shipped with every box — it is NOT evidence any tool was used here.**
  A tool/link is "used during the engagement" only if a notebook cell (command or
  output) shows it, or the operator names it in the interview (golden rule 8).
  Everything from `site/`, `utils/`, and READMEs is reference-bookmark material at
  most — label it as such, never assert it as used.
- **Embedded git repos** under `payloads/`/`artifacts/` are tools the operator actually
  cloned and ran — grep each for its `origin` URL and cite the **public** ones directly.
  This resolves tool provenance *mechanically* (public tool vs self-authored, credit/
  attribution): it is NOT an interview question. The operator will not remember a source
  that isn't in the notebook, so never ask them where a tool came from — check the repo.
- Read extracted screenshots (Read tool) to know what each one shows before referencing it.
- Produce a draft **attack-path reconstruction** (working chain, numbered) and a list
  of dead-ends. Show it to the operator to confirm you separated them correctly.

### Step 2 — Interview (the operator's lane)
The interview happens **in the ledger file** (`<site-root>/.interviews/<box>.md`), not
in chat. Write the reconstructed chain, the structural rulings, and every Socratic
question into that file; the operator answers inline under each `**A:**`, in any order,
at their own pace. This decouples the interview from the chat stream so 5+ boxes can be
worked in parallel without interleaving. Do **not** ask the questions conversationally
and do **not** use AskUserQuestion for the interview — the file is the source of truth.

Write into the ledger, in this order:
- The **reconstructed chain** (working path, numbered) + **dead-end candidates**, so the
  operator can correct the working-path / dead-end split.
- The **structural rulings** (defaults in *italics*):
  - Dead-ends → *keep as "what didn't work" with why* / cut / one-line.
  - Big blobs & log-spam → *elide with a marker* / collapse in `<details>` / verbatim.
  - Credential material → *partially redact* (`f29e9c01…be3b`) / verbatim / fully redact.
  - Event placement → new `seasonN-htb-YY` event vs existing `htb-machines` (see Step 4).
  - Publish timing → *publish now* vs hold until a date. Room authors dislike writeups
    within 7 days of a box's release; the post `date:` is the **solve** date, not the
    release date, so this can't be computed — ask. Default `published: true`; if held,
    the operator gives the safe date → `published: false` + `publish_after: YYYY-MM-DD`.
- The **Socratic questions**, phase by phase, each `[PENDING]`.

Then set the ledger `status: interviewing`, **stop, and hand back** — tell the
orchestrator the ledger path and that it awaits answers. When resumed, re-read the
ledger: a question with a non-empty `**A:**` is answered (flip it to `[ANSWERED]`); a
blank one or "don't recall / didn't check" maps to `⚠️ observed-only`; an `A:` of
`NEEDS CONTEXT` means quote the exact notebook fragment in a follow-up sub-question and
hand back again. Only proceed to Step 3 once no `[PENDING]` / `NEEDS CONTEXT` remains
(or the operator says to proceed with what's there). If an answer contradicts the
notebook, note the discrepancy in the ledger and resolve it before writing.

**Grounding (critical — this prevents the operator from confabulating).** A thin,
one-line question forces the operator to reconstruct from nothing, and they will
invent an answer without realizing it. Every question MUST:
- **Quote the real evidence it's about** — the exact command(s) and the decisive
  output line(s) from the notebook — so the operator reacts to artifacts, not a clue.
- **State the fact, ask only the interpretation.** The notebook already holds *what
  was done*; ask only the *why / what it meant / what was learned*. Never make the
  operator rebuild a fact that's on the page.
- **Stay open and non-leading.** Do NOT bake in a single plausible cause the operator
  can just agree with ("was it because LDAP was filtered?" invites a false yes). Ask
  "why this, here?" — and if you offer candidate explanations, offer several plus an
  explicit "…or something else, or you don't recall."
- **Make "I don't recall / I didn't check" a first-class answer.** It maps to
  `⚠️ observed-only` (state what the output shows, omit the why) or omission — never a
  fabricated fill. Apply zero pressure to produce an answer.
- **Cross-check the answer against the evidence.** If the operator's answer conflicts
  with what the notebook shows, surface the discrepancy ("the output shows X, the
  answer implies Y — which is right?") before writing either version.

Ask only what the notebook doesn't already answer. Question bank (adapt per box):
- **Tool/approach choice:** why this tool here? what was the trigger? (e.g. "ADWS port
  open → try SOAPy"). Was a more common tool tried and dropped?
- **The decisive observation:** what in the output told you to pivot? (an error, a
  share comment, a banner, a writable ACL).
- **Opportunistic vs planned:** was this a reasoned deduction or a speculative bet?
  Write it the way it happened — do not dramatize a blind drop into cleverness.
- **Dead-ends:** why did each fail? assert the why only if verifiable (else observed-only).
- **Privilege/loot decisions:** why this escalation path over an alternative (e.g.
  memory dump vs DCSync)? what constraint forced it?
- **One-line lesson:** the sentence future-you should read first.

**Never ask about sources beyond the notebook.** "Any writeup/video/blog you leaned
on?" or "where did this tool come from?" yields nothing — the operator only remembers
what's in the notebook; anything else is already forgotten. Tool/repo provenance is
resolved *mechanically* by grepping embedded git repos for their `origin` URL (Step 1),
citing the public ones — not by asking. Ask only about reasoning that genuinely lived
in the operator's head during the engagement.

The operator's answers **become the prose** of the 🧠 callouts. Do not embellish beyond
what they said.

### Step 3 — Verify & cite
For every external fact gathered in Steps 1–2:
- **MITRE:** fetch each candidate `attack.mitre.org/techniques/<ID>/`, confirm ID↔name,
  and tag only if the definition matches what happened. Prefer the most specific
  sub-technique (e.g. T1176.002 IDE Extensions, not the T1176 parent).
- **CVEs / named techniques / error codes:** WebSearch → WebFetch an authoritative
  source; cite the URL. (Pilot examples: BadSuccessor = CVE-2025-53779, Akamai;
  `KDC_ERR_PADATA_TYPE_NOSUPP` = KDC lacks Smart Card Logon EKU, Almond OffSec.)
- **Links:** operator's links pass through verbatim; each link you add is confirmed to
  resolve. Then run the whole-post check in Step 5.
Build a small **fact ledger** (fact | internal/external | source) before writing, and
drop or ⚠️-mark anything unsourced.

### Step 4 — Assemble
Copy `templates/post.md` as the skeleton. Rendering rules:
- **Event placement:** a season box → new event dir `ctf/events/seasonN-htb-YY/` with a
  `toc.md` (`layout: default`, `parent: Challenges`, `has_children: true`), matching the
  existing `season8-htb-25` pattern; a standalone machine → `ctf/events/htb-machines/`.
  Post filename `YYYY-MM-DD-<slug>.md`. Front matter: `grand_parent: Challenges`,
  `event: "htb-season-N"` (or `htb-machines`).
- **Images:** copy extracted screenshots to
  `assets/images/ctf/events/<event>/<box>/<descriptive-name>.png`; reference with an
  absolute `/assets/...` path and descriptive alt text.
- **Blobs elided**, **secrets partially redacted**, **dead-ends kept**, **impersonal
  voice**, **no cell annotations**, **no OSCP framing** — per the golden rules.
- **Further reading**: "Used during the engagement" holds ONLY tools/links evidenced
  by a notebook cell or named by the operator in the interview (golden rule 8). Generic
  `site/links.md` bookmarks go under a clearly-labeled "standard toolkit bookmarks
  (shipped with the room template — not necessarily used here)" block, or are omitted —
  never asserted as used. "Reference material (added for study)" stays its own block.
  The **Tools-used table** follows the same rule: every row maps to a notebook cell.
- Keep the provenance footer.

### Step 5 — Build & validate (local)
```bash
cd <site-root>
bundle exec jekyll build 2>&1 | grep -iE 'error|liquid|done in'    # must build clean
python3 -c "..."  # or curl: confirm the post + toc + images serve 200 if a server is up
bash <skilldir>/scripts/linkcheck.sh <post.md>                     # every link resolves
python3 <skilldir>/scripts/groundcheck.py <post.md> <notebook>    # every token traces to the notebook
# Leak sweep — none of these may appear in the built HTML:
grep -RniE '<full-nt-hash>|<cert-password>|<dpapi-masterkey>|doIF[A-Za-z0-9+/]{80}' _site/<post>.html || echo OK
```
Fix any 404 link (find the real URL or unlink). Confirm 403s are anti-bot via WebFetch.
`groundcheck.py` is a read-only gate — it edits nothing, it fails the build and lists
any redaction fragment, "used" tool, or flag that isn't in the notebook. A failure means
a fabrication slipped through golden rules 6–8; fix the post, don't silence the check.

### Step 6 — Hand back & publish
Present the rendered URLs for the operator to curate ("just the right amount of
annoying"). **Publish only on explicit confirmation** — defer to the repo's
`publish` skill (Playwright validation + conventional commit + push). Follow the
global git rules: conventional commits, no external repo URLs/PR refs in the commit
message.

On a **successful publish**, delete the interview ledger
(`<site-root>/.interviews/<box>.md`) — it is scaffolding, and the published post is the
durable record. (Before that, keep it: bump its `status` as you go — `answered` once the
operator has replied, `drafted` after Step 4, `published` at the moment you remove it.)

## Parallel crawl (5+ boxes at once)
The ledger is what makes this scale. To work a batch simultaneously, the orchestrator
spawns one scribe per box; each runs Steps 0–2 (reconstruct → write its own
`.interviews/<box>.md` → **stop**), then hands back. The orchestrator posts one
consolidated pointer listing every ledger path awaiting answers. The operator opens them
in an editor, batch-answers across all boxes in a single pass, and says which are done.
The orchestrator resumes each scribe, which reads its ledger and continues to Steps 3–6
independently. One ledger per box means no cross-talk; each box publishes (and purges its
ledger) on its own timeline.

## Notes
- This runs well on Sonnet: the operator supplies the reasoning; the pipeline is
  mechanical + verification-heavy, not open-ended reasoning. The one step that may
  benefit from a stronger model is Step 4 prose assembly on long, multi-phase boxes —
  escalate the model for that step only if the flow reads flat.
- Notebook completeness varies wildly (some boxes are near-empty templates). If
  `summary` shows almost no `code_with_output` and an empty Engagement Notes, tell the
  operator there's not enough to write and skip.
