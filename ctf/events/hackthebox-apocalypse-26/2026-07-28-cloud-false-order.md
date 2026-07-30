---
layout: post
title: "False Order"
date: 2026-07-28 00:00:00 -0700
categories: ctfs
description: A read-only CloudTrail + S3-versioning correlation exercise, reconstructing how an external identity probed a custody bucket, failed a direct read and a first role assumption, then returned to borrow a legitimate clerk's session name to succeed into a different role and quietly swap a sealed order for a forged one.
parent: HackTheBox - Apocalypse '26
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
  - "cloud"
  - "aws"
  - "cloudtrail"
  - "forensics"
  - "iam"
  - "s3-versioning"
  - "cyberapocalypse"
  - "T1619"
  - "T1548.005"
  - "T1565.001"
---

## Engagement Notes

`false-order` is a cloud-category challenge from Cyberapocalypse 2026, and it's
not an exploit chain — no privilege was escalated by the operator, nothing was
attacked. Read-only investigator access to a CloudTrail trail
(`coalition-gate-audit-trail`) and a versioned S3 bucket
(`ashguard-order-custody`) is handed out, and the task is to reconstruct how
and by whom a specific order document was tampered with, purely by correlating
object version history against the audit trail. There's no flag; the graded
deliverable is a fixed set of questions about the intrusion, all answered here
by re-deriving them directly from the raw CloudTrail event log rather than
taking the notebook's own answers at face value.

## Attack path

1. The legitimate internal clerk (IAM user `coalition-gate-clerk`, source IP
   `10.41.53.22`) runs routine read-only S3 checks against the custody bucket
   for several days; its last logged action is at `23:21:48`.
2. One minute later, an external identity — IAM user
   `seal-copyist-contractor`, source IP `198.18.44.91` — begins a slow,
   evenly-paced recon: identity check, bucket listing, object listing on
   `ashguard-order-custody`.
3. A direct `GetObject` on `custody/east-gate-order.json` comes back
   `AccessDenied` — this identity has no direct read grant on that key.
4. A first `sts:AssumeRole` into role `ashguard-order-auditor`, with
   `roleSessionName: "seal-copyist-session"`, is also denied.
5. After a gap, a fast burst of calls repeats the denied `GetObject` and a
   second denied `AssumeRole` into `ashguard-order-auditor` — this time under
   `roleSessionName: "coalition-gate-clerk"`, matching the legitimate clerk's
   own IAM username.
6. In the same burst, `AssumeRole` into a *different* role,
   `ashguard-order-scanner`, under that same borrowed session name, succeeds.
7. As the assumed role: the target object's version history is listed, the
   current object is deleted (a soft-delete — the bucket is versioned), and a
   forged replacement is uploaded with `PutObject`.
8. Reading both object versions afterward shows the forgery: most fields were
   rewritten outright, and the `ledger_hash` differs from the original by
   exactly one hex character.

## Setup: read-only investigator access

The starting point is a handed-out access key for IAM user
`gate-investigator`, pointed at a challenge-specific endpoint:

```python
import boto3
endpoint = "http://154.57.164.72:30711"
region = "us-east-1"
access_key = "AKIAQZ9U…J93Q"
secret_key = "bkCoGNCI…2rLh"
user = "gate-investigator"

sts = boto3.client('sts', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region, endpoint_url=endpoint)
identity = sts.get_caller_identity()
print(identity)
```

```
{'UserId': 'AIDAZWM6LGZC79YMT2JA', 'Account': '638291047582', 'Arn': 'arn:aws:iam::638291047582:user/gate-investigator', ...}
```

## The tampered object

The brief points straight at one object: `custody/east-gate-order.json` in
the `ashguard-order-custody` bucket. Reading the current version:

```python
east_gate_order = s3.get_object(Bucket="ashguard-order-custody", Key="custody/east-gate-order.json")
pprint(east_gate_order["Body"].read())
```

```
{
  "settlement_id": "EAST-GATE-C4R2",
  "season": "winter",
  "gate": "coalition-gate",
  "issuer": "Coalition Gate Authority",
  "issued_date": "2026-01-09",
  "total_units": 920,
  "custody_status": "RELEASED",
  "order_status": "RELEASED",
  "witness_line": "Gate release authorized per emergency writ WR-4412; witness attestation waived.",
  "ledger_hash": "sha256:4f8c2a91e0b7d3c6a5f1e9d8c7b6a5049382716f5e4d3c2b1a0f9e8d7c6b5a5"
}
```

The bucket has versioning enabled and the object has exactly two versions —
current, and one seven seconds older:

```python
east_gate_order_versions = s3.list_object_versions(Bucket="ashguard-order-custody", Prefix="custody/")
for document in east_gate_order_versions['Versions']:
    if document["Key"] == "custody/east-gate-order.json":
        pprint(document)
```

```
{'ETag': '"1be261e8b6c7a5d1976fcbec93d62caa"', 'IsLatest': True, ... 'LastModified': datetime.datetime(2026, 7, 28, 2, 21, 52, tzinfo=tzutc()), 'VersionId': '131be313-411e-49b6-b06d-7f859e559a82'}
{'ETag': '"382c450d91c4242455cb2f84d7012300"', 'IsLatest': False, ... 'LastModified': datetime.datetime(2026, 7, 28, 2, 21, 45, tzinfo=tzutc()), 'VersionId': '30ca4a6b-6dbb-4b65-88ea-51c2d95fee91'}
```

Fetching the older version by its `VersionId`:

```python
east_gate_order_old = s3.get_object(Bucket="ashguard-order-custody", Key="custody/east-gate-order.json", VersionId="30ca4a6b-6dbb-4b65-88ea-51c2d95fee91")
pprint(east_gate_order_old["Body"].read())
```

```
{
  "settlement_id": "EAST-GATE-C4R2",
  "season": "winter",
  "gate": "coalition-gate",
  "issuer": "Coalition Gate Authority",
  "issued_date": "2026-01-09",
  "total_units": 1840,
  "custody_status": "SEALED",
  "order_status": "PENDING_APPROVAL",
  "witness_line": "The gatehouse clerk attested the sealed order before dawn watch.",
  "ledger_hash": "sha256:4f8c2a91e0b7d3c6a5f1e9d8c7b6a5049382716f5e4d3c2b1a0f9e8d7c6b5a4"
}
```

Comparing the two: `custody_status` moved SEALED → RELEASED, `order_status`
moved PENDING_APPROVAL → RELEASED, `total_units` dropped 1840 → 920, and
`witness_line` was replaced entirely — citing an "emergency writ" instead of
the original dawn-watch clerk attestation. `ledger_hash` keeps the same
`sha256:` prefix and 63 of 64 hex characters; only the final nibble changes,
`...b5a4` → `...b5a5`.

> 🧠 The wholesale field rewrites and the single-nibble hash change are both
> just flat findings from the diff, not a deliberately staged "gotcha" — this
> box was primarily an exercise in parsing a large amount of log data
> correctly, and neither one is more "the point" than the other.

## Correlating the full CloudTrail trail

`coalition-gate-audit-trail` is paged in full, unfiltered:

```python
paginator = ct.get_paginator('lookup_events')
page_iterator = paginator.paginate()
all_events = []
for page in page_iterator:
    events = page.get('Events', [])
    all_events.extend(events)
    print(f"Retrieved {len(events)} events...")
print(f"Total events retrieved: {len(all_events)}")
```

```
Retrieved 50 events...
[... 10 more pages of 50 ...]
Retrieved 47 events...
Total events retrieved: 597
```

[597-event raw dump elided — filtered and sorted by `sourceIPAddress` below
instead of reproduced]. Grouping by source IP:

| Source IP | Events | Identity | Pattern |
|---|---|---|---|
| `10.41.53.22` | 548 | IAM user `coalition-gate-clerk` | Read-only S3 calls only (`ListObjectsV2`, `HeadObject`, `GetObject`, `ListBucketVersions`, `GetBucketVersioning`, `ListBuckets`), 2026-07-23 08:36 → 2026-07-27 23:21:48 |
| `198.18.44.91` | 21 | IAM user `seal-copyist-contractor` | The intrusion — detailed below |
| `98.97.141.106` / `127.0.0.1` | 28 | `gate-investigator` / local | This investigation session |

The last action from the internal gatehouse IP before the intrusion begins is
a `ListObjectsV2` call at `23:21:48`. Sixty seconds later, `198.18.44.91`
opens with `GetCallerIdentity` as `seal-copyist-contractor` — the first
action from that IP.

### Recon, a denied read, a denied role — spaced ~12–24 minutes apart

| Time (UTC) | Event | Result |
|---|---|---|
| 23:22:48 | `GetCallerIdentity` | OK |
| 23:36:00 | `ListBuckets` | OK |
| 23:48:13 | `ListObjectsV2` (`ashguard-order-custody`) | OK |
| 00:02:50 | `GetObject` (`custody/east-gate-order.json`) | **AccessDenied** |
| 00:24:15 | `ListObjectsV2` (`custody/` prefix) | OK |
| 00:40:47 | `ListObjectsV2` (`ashguard-intake` bucket) | OK |
| 00:58:22 | `AssumeRole` → `ashguard-order-auditor`, session `seal-copyist-session` | **AccessDenied** |

> 🧠 The 00:02:50 `GetObject` denial is the "explicitly denied" S3 action the
> intrusion attempts before ever assuming a role, and the 00:58:22 attempt is
> the role name it fails to assume before its eventual success.

### A gap, then a scripted-looking burst

After the 00:58:22 denial, the same slow cadence continues for roughly
another hour and a half (`ListBuckets`, `ListObjectsV2` on `receipts/`, on
`ashguard-order-archive`, on `custody/` again) with no further privileged
attempts — until, at `02:21:51.428`, ten calls land back to back inside 850
milliseconds:

| Time (UTC) | Event | Identity | Result |
|---|---|---|---|
| 02:21:51.428 | `GetCallerIdentity` | `seal-copyist-contractor` | OK |
| 02:21:51.576 | `ListAllMyBuckets` | `seal-copyist-contractor` | OK |
| 02:21:51.654 | `ListObjectsV2` | `seal-copyist-contractor` | OK |
| 02:21:51.675 | `GetObject` | `seal-copyist-contractor` | **AccessDenied** |
| 02:21:51.721 | `AssumeRole` → `ashguard-order-auditor`, session `coalition-gate-clerk` | `seal-copyist-contractor` | **AccessDenied** |
| 02:21:51.757 | `AssumeRole` → `ashguard-order-scanner`, session `coalition-gate-clerk` | `seal-copyist-contractor` | **OK** |
| 02:21:52.059 | `GetCallerIdentity` | `assumed-role/ashguard-order-scanner/coalition-gate-clerk` | OK |
| 02:21:52.176 | `ListBucketVersions` | `assumed-role/ashguard-order-scanner/coalition-gate-clerk` | OK |
| 02:21:52.229 | `DeleteObject` | `assumed-role/ashguard-order-scanner/coalition-gate-clerk` | OK |
| 02:21:52.272 | `PutObject` | `assumed-role/ashguard-order-scanner/coalition-gate-clerk` | OK |

Two things stand out against the earlier recon phase: the ~1h23m idle gap
beforehand, and the jump from ~12–24 minutes between calls to sub-second
spacing.

> 🧠 Both the gap and the burst-timing are read as artifacts of how this
> challenge's event data was generated rather than genuine attacker
> downtime or evidence of scripted tooling — they shouldn't be
> over-interpreted as deliberate pacing or automation. That said, the split
> between a slow recon phase and a sub-second destructive burst did cause
> some initial confusion while reconstructing the timeline, since it isn't
> obvious at a glance that both phases belong to the same identity and the
> same intrusion.

The two `AssumeRole` calls in the burst both carry
`roleSessionName: "coalition-gate-clerk"` — an exact match for the
legitimate internal user's IAM username (`arn:aws:iam::638291047582:user/coalition-gate-clerk`,
548 events, exclusively from `10.41.53.22`, last seen one minute before this
intrusion began). The contractor's own, first `AssumeRole` attempt
(`00:58:22`) used a self-identifying session name instead
(`seal-copyist-session`).

> 🧠 Choosing `coalition-gate-clerk` as the session name on both the second,
> still-denied `AssumeRole` and the successful one is read as a deliberate
> attempt to blend the resulting CloudTrail entries in with the legitimate
> clerk's own activity — masking presence in the logs rather than an
> incidental pickup during recon.

No policy document is available for either role (this room ships no
infrastructure-as-code), so the difference between `ashguard-order-auditor`
denying the assumption twice and `ashguard-order-scanner` allowing it is
stated here only as the CloudTrail record shows it — a mechanical fact, not
a claim about *why* the two roles' trust or permission configuration differ.

How `seal-copyist-contractor`'s own long-lived credentials were originally
obtained is out of scope: the trail begins at that identity's first
`GetCallerIdentity` call, already authenticated, and nothing in the notebook
or brief establishes how the key was acquired.

## Findings

The graded answer set, each re-derived independently above from the raw
event log rather than taken on the notebook's word:

| Question | Answer |
|---|---|
| Last CloudTrail action from the internal gatehouse IP before the intrusion | `ListObjectsV2` at 23:21:48 |
| First CloudTrail action from the external IP | `GetCallerIdentity`, from `198.18.44.91` |
| S3 action explicitly denied before any role assumption | `GetObject` |
| Full S3 path of the tampered object | `s3://ashguard-order-custody/custody/east-gate-order.json` |
| IAM role assumed for the destructive session | `arn:aws:iam::638291047582:role/ashguard-order-scanner` |
| STS principal ARN on the `DeleteObject` call | `arn:aws:sts::638291047582:assumed-role/ashguard-order-scanner/coalition-gate-clerk` |
| Source IP for the `AssumeRole` and destructive S3 calls | `198.18.44.91` |
| IAM username owning the long-lived credentials used to call `AssumeRole` | `seal-copyist-contractor` |
| Role name the intrusion failed to assume before the successful `AssumeRole` | `ashguard-order-auditor` |
| `roleSessionName` on the successful `AssumeRole` into the scanner role | `coalition-gate-clerk` |
| `errorCode` on the denied `GetObject` probe before role assumption | `AccessDenied` |
| S3 action marking the forged upload after `DeleteObject` | `PutObject` |

## What didn't work

- **Direct `GetObject` on the target key** — denied both times it was tried
  (`00:02:50` and again at `02:21:51.675`, both `AccessDenied`). The
  contractor identity never had a direct S3 read grant on
  `custody/east-gate-order.json`.
- **`AssumeRole` into `ashguard-order-auditor`** — denied twice: once under
  the contractor's own session name (`00:58:22`), once under the borrowed
  clerk session name in the final burst (`02:21:51.721`). Whatever this
  role's trust/permission configuration is, it never let the contractor in —
  `ashguard-order-scanner` was the role that did.

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| `boto3` | AWS SDK used for every API call (`sts`, `s3`, `cloudtrail`) against the challenge endpoint | [boto3 documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) |

## Tactics (MITRE ATT&CK)

- **[T1619 — Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619/)**:
  the recon phase's `ListObjectsV2`/`ListAllMyBuckets`/`ListBucketVersions`
  calls enumerate bucket contents and object versions — MITRE's own
  description names `ListObjectsV2` as a canonical example of this technique.
- **[T1548.005 — Abuse Elevation Control Mechanism: Temporary Elevated Cloud
  Access](https://attack.mitre.org/techniques/T1548/005/)**: the successful
  `sts:AssumeRole` into `ashguard-order-scanner` grants temporary credentials
  with delete/write permissions the contractor identity didn't otherwise
  have.
- **[T1565.001 — Data Manipulation: Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/)**:
  the `DeleteObject` + `PutObject` pair replaces a sealed, pending-approval
  order with a forged "released" one — manipulating data at rest to
  misrepresent an outcome, matching the technique's definition directly.

**Not tagged, and why:**
- *T1036.010 (Masquerade Account Name) / T1036.005 (Match Legitimate Resource
  Name or Location)* — considered for the `roleSessionName: "coalition-gate-clerk"`
  reuse. Neither sub-technique's official definition cleanly covers an
  ephemeral STS session identifier matched to an *existing* user's name:
  [T1036.010](https://attack.mitre.org/techniques/T1036/010/) is specifically
  about naming *newly created* accounts to look benign, and
  [T1036.005](https://attack.mitre.org/techniques/T1036/005/) is scoped to
  files, Registry keys, and similar system resources. Left untagged; the
  blending behavior itself is described in prose above instead.
- *T1078.004 (Valid Accounts: Cloud Accounts)* — considered for
  `seal-copyist-contractor`'s long-lived credentials, but the
  [technique definition](https://attack.mitre.org/techniques/T1078/004/)
  specifically requires *compromised or stolen* cloud credentials, and how
  this identity's key was obtained is outside what the notebook or brief
  establish.

## Further reading

**Reference material (added for study):**
- [Retaining multiple versions of objects with S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html) — explains why `DeleteObject` on a versioned bucket inserts a delete marker rather than erasing the prior version, which is exactly what let the original SEALED document still be read back by `VersionId` after the forgery.
- [AWS CloudTrail LookupEvents API reference](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html) — the API this box's entire correlation is built on (`paginator.paginate()` over `lookup_events`).

---

*Provenance: commands, outputs, credentials, and flags are transcribed from the
engagement notebook (credential material partially redacted). External facts (MITRE
technique definitions, CVEs, error semantics) are linked to their source and were
fetched, not recalled.*
