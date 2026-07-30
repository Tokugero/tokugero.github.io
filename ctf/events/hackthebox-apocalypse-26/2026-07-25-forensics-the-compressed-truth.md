---
layout: post
title: "The Compressed Truth"
date: 2026-07-25 00:00:00 -0700
categories: ctfs
description: A Cyberapocalypse 2026 Windows registry-forensics challenge graded as six independent embedded questions — pivoting a RegRipper NTUSER.DAT sweep to the 7-Zip plugin specifically recovers five of six straight from file-manager/compression/extraction history, but the sixth, locating a KeePass master database, was never answered.
parent: HackTheBox - Apocalypse '26
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
  - "HackTheBox"
  - "Windows"
  - "forensics"
  - "registry-forensics"
  - "RegRipper"
  - "NTUSER.DAT"
  - "KeeFarce"
  - "credential-theft"
  - "cyberapocalypse"
  - "T1555.005"
  - "T1074.001"
  - "T1560.001"
---
# The Compressed Truth

## Engagement Notes

`the-compressed-truth` is a Windows registry-forensics challenge from
Cyberapocalypse 2026, graded as six independently-answered embedded questions
against a single `NTUSER.DAT` hive rather than a single flag. Five of the six
were answered; the sixth was not. This is a partial post-mortem, not a
writeup of a fully closed chain.

The provided image holds three `NTUSER.DAT` hives —
`cyberjunkie`, `Default`, and `vmarr`. The challenge's own brief names Veylen
Marr as the compromised user, which points straight at the `vmarr` hive. A
full default-plugin RegRipper sweep against it (`-a`) produces roughly 42 KB
of output across dozens of plugins — almost all of it irrelevant. Buried near
the end of that dump, though, is a short section from the `sevenzip` plugin
that alone contains the data needed for five of the six answers. Re-running
RegRipper scoped to just that plugin (`-p sevenzip`) turns the same bytes into
a short, readable report: a credential-theft tool identified by its
extraction path and timestamp, a browse into an archive before staging, a
staging folder, a compression run, and where 7-Zip activity finally stopped.

The unresolved sixth question — the challenge brief's "one file above all
others," read as pointing at a KeePass master-database path — was never
answered before the engagement ended. No flag or answer string for it exists
anywhere in the room.

## Attack path

1. **Triage the artifact image** → three `NTUSER.DAT` hives; `vmarr`'s is the
   target, per the challenge brief's named victim.
2. **Full `regripper -a` sweep** against `vmarr`'s hive → ~42 KB of mostly
   irrelevant plugin output, with the `sevenzip` section buried near the end.
3. **Scoped `regripper -p sevenzip` re-run** → the same data, isolated and
   readable.
4. **Five of six answers** read directly off the 7-Zip
   FM/Compression/Extraction history keys.
5. **Sixth question** (KeePass database path) — unresolved.

## The hive and the noisy full sweep

The image's user hives:

```console
!ls -ln artifacts/C/*/*

artifacts/C/Users/cyberjunkie:
total 2068
-rw-r--r-- 1 0 0 1835008 Jun 18 06:03 NTUSER.DAT
-rw-r--r-- 1 0 0  282624 Oct 27  2025 ntuser.dat.LOG1
-rw-r--r-- 1 0 0       0 Oct 27  2025 ntuser.dat.LOG2

artifacts/C/Users/Default:
total 348
-rw-r--r-- 1 0 0 262144 Jun 18 07:09 NTUSER.DAT
-rw-r--r-- 1 0 0  57344 Apr  1  2024 NTUSER.DAT.LOG1
-rw-r--r-- 1 0 0  36864 Apr  1  2024 NTUSER.DAT.LOG2

artifacts/C/Users/vmarr:
total 2384
-rw-r--r-- 1 0 0 1835008 Jun 18 08:27 NTUSER.DAT
-rw-r--r-- 1 0 0  606208 Jun 18 06:03 ntuser.dat.LOG1

artifacts/C/Windows/System32:
total 4
drwxr-xr-x 2 0 0 4096 Jun 18 09:08 config
```

`vmarr`'s hive is the most recently written and matches the brief's named
victim, so it's the one taken forward.

A full default-plugin sweep against it comes back noisy:

```console
!regripper -r artifacts/C/Users/vmarr/NTUSER.DAT -a
Launching adobe v.20200522
...
Launching appcompatflags v.20200525
...
Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store
  2025-09-15 19:40:04Z - C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
  2025-09-15 19:40:04Z - C:\Users\vmarr\Downloads\7z2601-x64.exe
  2025-09-15 19:40:04Z - C:\Users\vmarr\AppData\Local\Microsoft\OneDrive\25.087.0506.0001\FileSyncConfig.exe
  2025-09-15 19:40:04Z - C:\Users\vmarr\Downloads\KeePass-2.61.1-Setup.exe
  2025-09-15 19:40:04Z - C:\Program Files\7-Zip\7zFM.exe
  ...
[... dozens more plugins, ~42KB total ...]
```

That `Compatibility Assistant\Store` entry (dated 2025-09-15, well before the
incident) is baseline install history — 7-Zip and KeePass were both
legitimately installed on this machine ahead of time, not part of the
incident itself.

> 🧠 The `-a` sweep wasn't a dead end — the `sevenzip` plugin's section is
> present in that same ~42 KB dump, just buried near the end of it. Scanning
> the full output and noticing that the 7-Zip-related data already contained
> almost all the answers is what prompted calling out that one plugin
> explicitly, to get a focused view instead of reading through the rest of
> the noise.

## Reading the 7-Zip history

Re-running RegRipper scoped to just that plugin surfaces the same block, now
isolated:

```console
!regripper -r artifacts/C/Users/vmarr/NTUSER.DAT -p sevenzip
Launching 7-zip v.20210329
sevenzip v.20210329
- Gets records of histories from 7-Zip keys

FM LastWrite: [2026-06-18 13:26:47Z]

Compression LastWrite: [2026-06-18 13:25:06Z]

Extraction LastWrite: [2026-06-18 13:15:15Z]

FM\PanelPath0: c:\users\vmarr\desktop\working\

Compression\ArcHistory:
  C:\Users\Public\Pictures\shardchain.tar
  
Extraction\PathHistory:
  C:\Users\vmarr\AppData\Local\Temp\writ\KeeFarce\
  

FM\CopyHistory:
  c:\users\public\music\saltwork\
  c:\users\public\music\saltwork
  

FM\FolderHistory:
  c:\users\vmarr\desktop\working\
  c:\users\public\music\saltwork\
  c:\users\vmarr\appdata\Roaming\KeePass\
  c:\users\vmarr\appdata\Roaming\
  c:\users\vmarr\appdata\
  c:\users\vmarr\appdata\Local\
  C:\Users\vmarr\Documents\Registry\shard_references\
  C:\Users\vmarr\Documents\Registry\
  C:\Users\vmarr\Documents\Registry\shard_storage\
  C:\Users\vmarr\Documents\Registry\shard_storage\ShardKeepass_FirstMark\
  C:\Users\vmarr\Documents\Registry\shard_ref\
  C:\Users\vmarr\Documents\Registry\internal_reports\
  C:\Users\vmarr\Documents\Registry\custody_chains\
  C:\Users\vmarr\Documents\Registry\oath_records_cinderbound_vol2.zip\
  C:\Users\vmarr\Documents\Registry\oath_records_cinderbound_vol2.zip\oath_records_cinderbound_vol2\
  C:\Users\vmarr\Documents\Registry\oath_records_cinderbound_vol2.zip\oath_records_cinderbound_vol2\saltoaths_secretive\
  C:\Users\vmarr\Documents\
  C:\Users\vmarr\Documents\Personal\
  C:\Users\vmarr\
  C:\Users\vmarr\Downloads\
  C:\Users\
  C:\
  Computer\
  
  
Software\Wow6432Node\7-Zip not found.
```

Every answer but one falls straight out of this block:

- **`Extraction\PathHistory`** names
  `C:\Users\vmarr\AppData\Local\Temp\writ\KeeFarce\` — identifying
  [KeeFarce](https://github.com/denandz/KeeFarce), a tool that "extracts
  passwords from a KeePass 2.x database, directly from memory" by DLL-injecting
  into a running KeePass process. The `Extraction LastWrite` timestamp,
  `2026-06-18 13:15:15Z`, is the moment that extraction touched the system —
  distinct from the later `FM`/`Compression` LastWrite times on the same key.

  > 🧠 KeeFarce wasn't prior knowledge going in — it stood out as a unique,
  > unusual entry in the registry output (little else was there), which
  > prompted a lookup that identified it as a KeePass memory-based
  > credential-extraction tool.

- **`FM\FolderHistory`** shows the deepest folder enumerated inside an
  archive file: `oath_records_cinderbound_vol2.zip` was browsed down to
  `oath_records_cinderbound_vol2\saltoaths_secretive\` before staging began.
- **`FM\CopyHistory`** and the matching `FolderHistory` entries put the
  staging location at `c:\users\public\music\saltwork\`.
- **`Compression\ArcHistory`** shows the archive prepared for exfiltration:
  `C:\Users\Public\Pictures\shardchain.tar`.
- **`FM\PanelPath0`** — the last-recorded 7-Zip file-manager location —
  is `c:\users\vmarr\desktop\working\`, where the operation concluded.

## What didn't work

- **The sixth question.** The challenge brief asks: *"One file above all
  others — holding keys to every shard, every custodian, every oath...
  Where was it stored?"* — read as pointing at a KeePass master-database
  path. `FM\FolderHistory` (above) holds two KeePass-adjacent candidates,
  `c:\users\vmarr\appdata\Roaming\KeePass\` and
  `C:\Users\vmarr\Documents\Registry\shard_storage\ShardKeepass_FirstMark\`,
  but neither was submitted as a confirmed answer, and none is recorded in
  the notebook.

  > 🧠 This one was never resolved — either the wrong path was picked, or the
  > right path was found but submitted in a format the grader didn't accept.
  > Which of the two it was is genuinely unclear from here.

## Findings — the answer key

This is an answer-format forensics challenge: six questions, each graded
independently, matched against the `sevenzip` evidence above.

| Question | Answer | Source |
|---|---|---|
| Tool used to extract secrets from memory | `KeeFarce` | `Extraction\PathHistory` naming `...\Temp\writ\KeeFarce\` |
| When the tool was first extracted on the system | `2026-06-18 13:15:15Z` | `Extraction LastWrite` (not the `FM` LastWrite) |
| Deepest folder enumerated inside the archive file | `...oath_records_cinderbound_vol2\saltoaths_secretive\` | `FM\FolderHistory` |
| Where the stolen records were staged | `C:\Users\Public\Music\saltwork` | `FM\CopyHistory` / `FolderHistory` |
| Archive prepared for exfiltration | `C:\Users\Public\Pictures\shardchain.tar` | `Compression\ArcHistory` |
| Folder where 7-Zip activity concluded | `c:\users\vmarr\desktop\working\` | `FM\PanelPath0` |
| **Where the KeePass master database was stored** | **Unresolved** | Two `FolderHistory` candidates considered; neither confirmed |

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| RegRipper | Parsed `vmarr`'s `NTUSER.DAT` hive; the `sevenzip` plugin recovered the working evidence | [keydet89/RegRipper3.0](https://github.com/keydet89/RegRipper3.0) |

## Tactics (MITRE ATT&CK)

Only techniques whose definition matches what the registry evidence shows,
each verified against its ATT&CK page:

| Technique | ID | Where |
|---|---|---|
| Credentials from Password Stores: Password Managers | [T1555.005](https://attack.mitre.org/techniques/T1555/005/) | KeeFarce's recovered extraction path — the technique explicitly covers extracting "the master password and/or plaintext credentials from memory" of a password manager |
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | `FM\CopyHistory`/`FolderHistory` show records copied into `C:\Users\Public\Music\saltwork` ahead of compression |
| Archive Collected Data: Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | `Compression\ArcHistory` shows 7-Zip — a utility the technique names directly — used to build `shardchain.tar` |

> **Not tagged, and why:** Data from Local System
> ([T1005](https://attack.mitre.org/techniques/T1005/)) was considered for
> the browse into `oath_records_cinderbound_vol2.zip`, but the only evidence
> here is folder enumeration in a file manager — no read/copy of file
> *contents* is recorded independent of the staging and archiving already
> covered by T1074.001 and T1560.001, so it's left untagged rather than
> stretched to fit.

## Lessons

- A noisy default plugin sweep isn't necessarily missing data — the `-a` run
  here already contained the answer, just 34 KB into a 42 KB dump. The real
  gain from re-running scoped to one plugin was readability, not new data.
- A single unusual-looking registry entry (`KeeFarce`, standing alone against
  a page of ordinary Windows application noise) is worth a lookup on sight —
  it was the one line in the whole dump that didn't belong.
- Guessing a room author's exact expected answer format is a separate
  difficulty from the forensics itself. Whether the sixth question stayed
  open because of a wrong path or a wrong format is impossible to tell apart
  from the tooling alone, and that ambiguity is itself worth recording rather
  than glossing over.

## Further reading

**Used during the engagement:**
- [RegRipper](https://github.com/keydet89/RegRipper3.0) — ran against `vmarr`'s `NTUSER.DAT`, both the full `-a` sweep and the scoped `sevenzip` plugin.

**Reference material (added for study):**
- [KeeFarce](https://github.com/denandz/KeeFarce) — the identified attacker tool; its own README describes DLL-injecting into a running KeePass process to dump decrypted entries. Not run by the analyst — identified from the registry evidence only.

---

*Provenance: commands, outputs, and the notebook's own recorded answers are
transcribed from the engagement notebook. No credential material appears in
this notebook — only file paths and timestamps. External facts (KeeFarce's
mechanism, MITRE technique definitions) are linked to their source and were
fetched, not recalled.*
