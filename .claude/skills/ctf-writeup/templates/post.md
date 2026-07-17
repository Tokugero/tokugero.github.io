---
layout: post
title: "<Box Name>"
date: YYYY-MM-DD 00:00:00 -0700
categories: challenges
description: <one sentence — the crux of the chain, no OSCP framing>
parent: <event title — e.g. "HackTheBox - Season 11" or "HackTheBox - Machines">
grand_parent: Challenges
event: "<event-slug — e.g. htb-season-11 or htb-machines>"
tags:
  - "HackTheBox"          # platform
  - "<OS: Windows|Linux>"
  - "<difficulty>"        # if known
  - "<technique tags: kebab or CamelCase — tomcat, war-upload, dMSA, ...>"
  - "<verified MITRE IDs only: T1190, T1078.001, ...>"
---
# <Box Name>

## Engagement Notes
<!-- Impersonal-voice prose overview: what kind of box, the shape of the chain, and
     the 1-2 transferable habits it rewards. No "I/we/you". Be honest about
     opportunistic vs planned moves. -->

## Attack path
<!-- Numbered TL;DR of the WORKING chain, one line per phase. -->

## <Phase sections: Enumeration / Foothold / Privilege escalation / Loot ...>
<!-- Per phase: the decisive commands in ```console blocks (elide blobs/log-spam
     >~15 lines with a marker like `[+2KB base64 ticket elided]`; partially redact
     secrets like `f29e9c01…be3b`). Then a `> 🧠` callout carrying the interview
     answer — the *why*, impersonal, honest. -->

## What didn't work
<!-- Only if the notebook has dead-ends. Each: what was tried, and WHY it failed.
     If the "why" is an external technical claim, fetch + cite it (don't assert
     from memory); otherwise mark it observed-only. -->

## Tools used
<!-- Table: Tool | Role on this box | Reference.
     Links: harvest the author's curated links (site/links.md + inline) verbatim;
     any link ADDED here must be HTTP-verified or left "ToolName — source not identified". -->

## Tactics (MITRE ATT&CK)
<!-- Only techniques whose official definition MATCHES what happened, each verified
     against its attack.mitre.org page. Add a "not tagged, and why" note for
     techniques considered but rejected. -->

## Lessons
<!-- The author's transferable takeaways, impersonal voice. -->

## Further reading
<!-- Split: "Used during the engagement" (author's links, verbatim) vs
     "Reference material (added for study)". -->

---

*Provenance: commands, outputs, credentials, and flags are transcribed from the
engagement notebook (credential material partially redacted). External facts (MITRE
technique definitions, CVEs, error semantics) are linked to their source and were
fetched, not recalled.*
