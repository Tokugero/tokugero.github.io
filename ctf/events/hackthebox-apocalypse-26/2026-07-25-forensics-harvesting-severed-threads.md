---
layout: post
title: "Harvesting Severed Threads"
date: 2026-07-25 00:00:00 -0700
categories: ctfs
description: A Cyberapocalypse 2026 memory-forensics box that was never solved — recovering an ext4 volume's contents from a Linux 7.0 memory image required first patching volatility3 itself for kernel-6.16+ page-cache layout changes, which recovered a 16MB PyInstaller binary byte-complete, but the LUKS-backed source volume, a stray tmpfs file, and a captured pcap were never cracked before time ran out.
parent: HackTheBox - Apocalypse '26
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
  - "forensics"
  - "linux"
  - "memory-forensics"
  - "volatility3"
  - "luks"
  - "pyinstaller"
  - "cyberapocalypse"
---

## Engagement Notes

`harvesting-severed-threads` is a forensics challenge from Cyberapocalypse 2026
that **was not solved — no flag was recovered.** This is a post-mortem, not a
writeup of a working chain. It's included because the real work done on this
box is worth keeping a record of: fixing volatility3 itself so it could read a
Linux memory image at all.

The room's `engagement.ipynb` holds none of the actual investigation — every
cell is the unmodified room-scaffolding template (`rustscan`/`gobuster`
against a *host* named `harvesting-severed-threads`, the wrong template
entirely for a memory-image challenge), never executed. `README.md` is
likewise the generic room-skeleton doc, not a challenge briefing. Everything
below is reconstructed from the `artifacts/` directory instead — file
modification times, the contents of two hand-written volatility3 patches, a
diagnostic plugin, and the plugin output files themselves — cross-read
against each other rather than replayed from a command log. Anywhere the
ordering below rests on mtimes rather than a direct statement, that's called
out.

The target is a **3.25 GB Linux 7.0 memory image** (Ubuntu
`7.0.0-22-generic`, built 25 May 2026) — new enough that volatility3 2.28.0's
page-cache plugins simply crash on it, because the kernel's own internal
struct layout had changed out from under the framework. Diagnosing and
patching that turned into the actual engagement: a runtime monkeypatch, a
standalone diagnostic plugin, and an upstream-style patch, which together
took a recovered file from 2.6 MB of holes to a byte-complete 16 MB binary.
What that binary does, what's behind the LUKS-encrypted volume it came from,
and what's in the provided packet capture were never reached.

## Recovery chain

> Reconstructed from `artifacts/` file timestamps and content, not a replayed
> notebook session — see above.

1. **Load the memory image.** `artifacts/vol-cfg.json` records the loaded
   banner:
   ```
   Linux version 7.0.0-22-generic (buildd@lcy02-amd64-061) (x86_64-linux-gnu-gcc
   (Ubuntu 15.2.0-16ubuntu1) 15.2.0, GNU ld (GNU Binutils for Ubuntu) 2.46)
   #22-Ubuntu SMP PREEMPT_DYNAMIC Mon May 25 15:54:34 UTC 2026
   (Ubuntu 7.0.0-22.22-generic 7.0.0)
   ```
   against the matching Ubuntu ISF
   (`Ubuntu_7.0.0-22-generic_7.0.0-22.22_amd64.json.xz`).

2. **Baseline enumeration with stock volatility3** turns up a mounted,
   LUKS2-backed volume and a suspicious four-line shell history. `linux.bash`
   recovers, for PID 9030:
   ```
   PID   Process  CommandTime                   Command
   9030  bash     2026-06-27 23:19:57.000000 UTC history
   9030  bash     2026-06-27 23:19:57.000000 UTC sdmem
   9030  bash     2026-06-27 23:19:57.000000 UTC sudo su
   9030  bash     2026-06-27 23:20:13.000000 UTC sudo ./dev_mnt/pyz/exfil
   ```
   Three of the four entries share one recovered `CommandTime`; only the
   `exfil` invocation is offset, by 16 seconds. `sdmem` is the
   [`secure-delete` toolkit's RAM wiper](https://manpages.debian.org/testing/secure-delete/sdmem.1.en.html) —
   "designed to delete data which may lie still in your memory (RAM) in a
   secure manner," a multi-pass overwrite of physical memory. Read together
   with `sudo su`, its presence in the same short history reads as an
   attempt to scrub traces from RAM after escalating — but the fine-grained
   order among `history`/`sdmem`/`sudo su` isn't independently confirmed
   beyond the shared timestamp; only that all three precede the `exfil` run
   is solid.

   `linux.mountinfo.MountInfo` shows `/dev/mapper/dev_volume` (ext4) mounted
   at `/home/dev5812/dev_mnt` across many mount namespaces, and
   `linux.pagecache.luks` — a narrowly-scoped run — recovers the udev by-id
   link naming it:
   ```
   /run/udev/links/disk\x2fby-id\x2fdm-uuid-CRYPT-LUKS2-fee4d3439d49470d831500fb0e3101a0-dev_volume
   /dev/disk/by-id/dm-uuid-CRYPT-LUKS2-fee4d3439d49470d831500fb0e3101a0-dev_volume -> ../../dm-0
   ```
   `/home/dev5812/dev_mnt/pyz/exfil` — the file the recovered history shows
   being run — sits on this same LUKS-backed mount.

3. **A general page-cache dump crashes.** The unscoped `linux.pagecache` run
   fails; volatility3's own upstream tracker has the exact symptom filed as
   [issue #1943](https://github.com/volatilityfoundation/volatility3/issues/1943),
   "`page` is missing the `.index` attribute," against a Linux 6.17 image —
   the `struct page` → `struct folio` rename left `page.index` gone,
   replaced by `__folio_index`. A second, separate crash also shows up on
   the deeper page-cache walk: `Invalid cached page address at 0x0/0x10,
   aborting`, per the diagnostic plugin written to chase it (next step).

4. **Scoped queries as a stopgap.** `linux.pagecache.luks` (above) and a
   follow-up `linux.pagecache.crash_dm_crypt_keys` — targeting
   [Linux's crash-kernel dm-crypt key-persistence configfs interface](https://www.kernel.org/doc/html/latest/admin-guide/kdump/kdump.html),
   `/sys/kernel/config/crash_dm_crypt_keys` — both succeed
   where the bare, unscoped run doesn't. The `crash_dm_crypt_keys` probe was
   chased hoping it might hold the key to the LUKS volume backing
   `dev_disk.img`; it recovers only the empty directory entry, no key
   material, and the idea didn't pan out. These scoped runs started as plain
   discovery rather than a deliberate "avoid the crash" workaround — the
   recovery tooling was also fighting broken dependency versions, a
   consequence of running volatility3 from an analysis host whose own kernel
   was newer than expected relative to the target image, which was a real
   source of friction on top of the struct-layout mismatch itself.

5. **Diagnose the crash directly.** `artifacts/volplugins/xadiag.py`, a
   standalone plugin, dumps an inode's raw xarray leaf slots to find out why
   `linux.pagecache` aborts:
   ```python
   """Diagnostic: dump the raw xarray leaf slots of an inode's page cache.

   Used to confirm why linux.pagecache aborts with
   "Invalid cached page address at 0x0/0x10" on Linux >= 6.16 images.
   """
   ```
   The root cause: at the xarray leaf level, an "internal" slot (low tag bits
   `0b10`) is a sibling entry for a multi-order (large folio) slot, or an
   `XA_RETRY_ENTRY`/`XA_ZERO_ENTRY` — never a page pointer. Volatility3's
   stock `_iter_node()` strips that tag before checking, which turns a
   sibling-entry value like `0x12` into `0x10` — an address that then passes
   `is_valid_node()` and gets yielded as if it were a real page, corrupting
   the whole inode's recovery.

6. **Two fixes, assembled in stages.** `artifacts/volp` (a `vol` wrapper
   script) predates `artifacts/volplugins/xadiag.py`, which predates a first
   `linux.pagecache.RecoverFs` run — read together, this is a first fix
   attempt, a further crash that prompted the `xadiag` diagnostic, then a
   `RecoverFs` run (the
   [filesystem-recovery plugin](https://volatility3.readthedocs.io/en/latest/volatility3.plugins.linux.pagecache.html),
   which recovers cached directories/files/symlinks into a tarball) with only the
   xarray leaf-slot fix, not yet a folio-aware content read. A
   `linux.pagecache.RecoverFs.baseline` run one minute later matches
   `volp_main.py`'s own comment about a `VOLP_NO_FOLIO_FIX` environment
   variable, "for A/B comparison of the large-folio content fix" — a
   deliberate before/after check, not an accidental duplicate run.
   `artifacts/volp_main.py`, the finalized monkeypatch (postdating both runs
   above), combines everything: a `page.index` property honoring the
   `__folio_index` rename, a `page.flags` property unwrapping the
   `memdesc_flags_t` struct Linux ≥ 7.0 wraps flags in, `folio_nr_pages()`,
   a folio-aware multi-page `page.get_content()`, and the xarray leaf-slot
   fix from step 5:
   ```python
   def _xarray_iter_node(self, nodep, height):
       """XArray._iter_node that skips internal entries at the leaf level. ..."""
       ...
       if height == 1:
           if self.node_is_internal(slot):
               continue
           child = self._slot_to_nodep(slot)
           if self.is_valid_node(child):
               yield child
       ...
   ```

7. **Fully-patched recovery.** `linux.pagecache.RecoverFs.patched`, run
   after `volp_main.py` was finalized, recovers `/home/dev5812/dev_mnt/pyz/exfil`
   at its full, correct size:
   ```
   FilePath                          InodeSize  Recovered FileSize
   /home/dev5812/dev_mnt/pyz/exfil   16004280   16004280
   ```
   against the earlier, partial-fix run's same row:
   ```
   FilePath                          InodeSize  Recovered FileSize
   /home/dev5812/dev_mnt/pyz/exfil   16004280   2625536
   ```
   The recorded inode size (16,004,280 bytes) never changes between runs —
   only how much of it the plugin could actually read back from cached
   pages. The folio-aware content read alone accounts for the jump from
   2.6 MB to the full 16 MB: large folios were being read one 4 KiB page at
   a time and leaving holes in between.

8. **Formalize the fix.** `vol3-linux-6.16-pagecache.patch` — the newest
   volatility3-related artifact in the room, written after the runtime
   monkeypatch was already proven correct — turns the same fix into an
   upstream-style diff against `volatility3/framework/symbols/linux/__init__.py`
   and `.../linux/extensions/__init__.py`:
   ```diff
   +    def is_valid_leaf_slot(self, slot) -> bool:
   +        # At the leaf level an internal entry is either a sibling entry - the
   +        # continuation slots of a multi-order (large folio) entry - or one of
   +        # XA_RETRY_ENTRY / XA_ZERO_ENTRY. None of them hold a page pointer.
   +        # This has to be checked on the raw slot: _slot_to_nodep() clears the
   +        # internal tag, which turns e.g. a sibling entry 0x12 into 0x10, an
   +        # address that then wrongly passes is_valid_node().
   +        return not self.node_is_internal(slot)
   ```

9. **Identify the recovered binary.** Both copies of
   `home/dev5812/dev_mnt/pyz/exfil` are a stripped, dynamically-linked
   ELF64. Its own embedded strings identify it as a PyInstaller bundle
   linking Python's `cryptography` package:
   ```
   Could not load PyInstaller's embedded PKG archive from the executable (%s)
   cryptography.hazmat.bindings.openssl
   ```
   Recovering it byte-complete from page cache was the actual stopping point
   for this engagement — it was never unpacked or decompiled further.

10. **An unfinished side-attempt at decrypting captured WireGuard traffic.**
    `artifacts/keyfile.log` — the newest file in the whole room directory,
    written well after the volatility3 work above — was hand-assembled while
    trying to decrypt WireGuard traffic in `capture.pcapng` using key
    material recovered from the page cache. It is not something pulled from
    the target itself; it doesn't appear anywhere in either recovered
    filesystem tree or in the raw `dev_disk.img`. The attempt was never
    finished:
    ```
    New handshake session:
      LOCAL_STATIC_PRIVATE_KEY = GPXmuw+x…sUY=
      REMOTE_STATIC_PUBLIC_KEY = 34P8Lh/R…aHE=
      LOCAL_EPHEMERAL_PRIVATE_KEY = 7E0yA02H…bg0=
      PRESHARED_KEY = https://www.youtube.com/watch?v=oHafFDkFgeg
    ```
    The `PRESHARED_KEY` field is a placeholder — a joke link, not key
    material — left there because the real PSK was never recovered.
    `capture.pcapng` itself was never analyzed on its own terms; the plan
    was to read it through this decryption attempt, which didn't get far
    enough.

11. **An unexplained opaque file.** `linux.pagecache.RecoverFs.patched` also
    fully recovers a 12 KB file that only ever existed on `tmpfs`:
    ```
    FilePath          InodePages  CachedPages  InodeSize  Recovered FileSize
    /tmp/serpent.db   3           3            12288      12288
    ```
    Fully recovered, present only in memory, name unexplained — its content
    was never examined.

## What didn't work

- **The unscoped `linux.pagecache` run** — crashed outright on this kernel's
  struct layout, both on the known upstream `page.index` issue and on the
  xarray leaf-slot bug diagnosed in step 5.
- **The partial-fix `RecoverFs` run** — recovered the target directory
  structure but only 2.6 MB of the 16 MB `exfil` binary; missing the
  folio-aware content read left large chunks of every large-folio-backed
  file unread.
- **`linux.pagecache.crash_dm_crypt_keys`** — a real lead
  ([Linux's crash-kernel dm-crypt key-persistence mechanism](https://www.kernel.org/doc/html/latest/admin-guide/kdump/kdump.html))
  that turned up nothing: an empty directory entry, no key material, no path
  to decrypting `dev_disk.img`.
- **The LUKS-backed `dev_volume`** — confirmed mounted (via `MountInfo` and
  the recovered udev links) but never independently unlocked; no
  `cryptsetup luksDump` output or recovered master key exists anywhere in
  the room.
- **The WireGuard decryption attempt (`keyfile.log`)** — assembled by hand
  from pcap and page-cache material, but abandoned before the real
  preshared key was ever recovered.
- **`capture.pcapng`** — never opened on its own; the plan to read it via
  the WireGuard decryption above never completed.
- **The `exfil` binary itself** — recovered whole, but never unpacked or
  decompiled.

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| Volatility3 2.28.0 | Primary memory-forensics framework; loaded `memory.elf` and ran all `linux.*` plugins | [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) |
| Custom `xadiag.py` diagnostic plugin (self-authored) | Dumped raw xarray leaf slots to diagnose the `linux.pagecache` crash on this kernel | — |
| Custom `volp`/`volp_main.py` runtime monkeypatch (self-authored) | Fixed `page.index`/`page.flags`/folio-aware content reads and the xarray leaf-slot bug for kernel ≥ 6.16/7.0, referencing upstream issue #1943 | [volatility3#1943](https://github.com/volatilityfoundation/volatility3/issues/1943) |
| `vol3-linux-6.16-pagecache.patch` (self-authored) | Formalized the runtime monkeypatch as an upstream-style diff | — |

## Tactics (MITRE ATT&CK)

No techniques are tagged for this box. The recovered evidence is too thin, or
doesn't cleanly match an official technique definition:

- *T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching)* —
  considered for the recovered `sudo su`. The
  [technique definition](https://attack.mitre.org/techniques/T1548/003/)
  specifically covers abuse of sudo's cached-credential timestamp window or
  sudoers-file manipulation, not a bare, ordinary `sudo` invocation — nothing
  recovered here shows caching abuse or sudoers tampering.
- *T1027.002 (Obfuscated Files or Information: Software Packing)* —
  considered for the PyInstaller-bundled `exfil` binary. The
  [technique definition](https://attack.mitre.org/techniques/T1027/002/)
  targets packers like UPX that compress/encrypt an executable specifically
  to change its file signature and evade detection; a stock PyInstaller
  bundle is closer to ordinary application packaging, and there's no sign of
  an additional packing layer on top of it.
- No sub-technique under [T1070 (Indicator Removal)](https://attack.mitre.org/techniques/T1070/)
  covers RAM sanitization specifically — the recovered `sdmem` invocation
  (a physical-memory wipe tool, not a log/file/history clearing action) has
  no clean match among its eight sub-techniques.

## Lessons

- The forensic tooling can be the actual bottleneck, not the target: a
  target kernel newer than the analysis framework expects turned a
  straightforward page-cache recovery into most of the engagement.
- Running the analysis host on an older/mismatched kernel relative to the
  target compounded the tooling breakage with dependency issues, on top of
  the struct-layout mismatch itself — worth checking analysis-host/target
  kernel skew before starting, not after hitting the first crash.
- A plugin reporting "success" doesn't mean complete recovery: the recorded
  inode size and the recovered byte count are two different numbers, and the
  gap between them (2.6 MB vs. 16 MB here) was invisible without comparing
  them directly.
- Scoped, narrow queries are a reasonable way to make progress around a
  broken plugin, but it's worth tracking *why* they succeed — otherwise the
  workaround gets mistaken for the actual fix.

## Further reading

**Used during the engagement:**
- [Volatility3](https://github.com/volatilityfoundation/volatility3) — the framework itself, run throughout.
- [volatility3 issue #1943](https://github.com/volatilityfoundation/volatility3/issues/1943) — named directly in `volp_main.py`'s own comment ("upstream issue 1943") while diagnosing the `page.index` crash.

**Reference material (added for study):**
- [`volatility3.plugins.linux.pagecache` module docs](https://volatility3.readthedocs.io/en/latest/volatility3.plugins.linux.pagecache.html) — documents the `RecoverFs`/`Files` plugins used to recover cached filesystem content.
- [Linux kdump documentation — `CONFIG_CRASH_DM_CRYPT`](https://www.kernel.org/doc/html/latest/admin-guide/kdump/kdump.html) — the crash-kernel dm-crypt key-persistence mechanism behind `/sys/kernel/config/crash_dm_crypt_keys`.
- [`sdmem(1)` — secure-delete manpage](https://manpages.debian.org/testing/secure-delete/sdmem.1.en.html) — the RAM-wiping tool recovered in the bash history.

---

*Provenance: this box's `engagement.ipynb` holds no real work (unexecuted
room-scaffolding template only) — every command, output, and timestamp above
is transcribed directly from the `artifacts/` directory instead (patch files,
a diagnostic plugin, and volatility3 plugin output), with credential-shaped
material partially redacted. Where ordering is inferred from file
modification times rather than stated directly, that inference is called out
in place. External facts (the volatility3 upstream issue, MITRE technique
definitions, the kdump dm-crypt mechanism) are linked to their source and
were fetched, not recalled.*
