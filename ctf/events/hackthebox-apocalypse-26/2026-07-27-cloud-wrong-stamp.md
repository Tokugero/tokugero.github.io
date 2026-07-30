---
layout: post
title: "Wrong Stamp"
date: 2026-07-27 00:00:00 -0700
categories: ctfs
description: A CloudTrail-only forensics reconstruction of a long-lived IAM key switching from an internal VPC address to an external one in 21 seconds, then attempting a denied DeleteTrail before falling back to StopLogging as its last recorded action — an answer-key challenge with no flag.
parent: HackTheBox - Apocalypse '26
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
  - "cloud"
  - "aws"
  - "iam"
  - "cloudtrail"
  - "cyberapocalypse"
  - "T1078.004"
  - "T1562.008"
  - "T1619"
---

## Engagement Notes

`wrong-stamp` is a cloud-category challenge from Cyberapocalypse 2026, framed as
a forensics investigation rather than an exploit chain:

> Elric Ashspar finds a seizure stamp in a dead clerk's bag near Stonepass.
> Vaultrune uses copies of that stamp to take supplies from Sythra's border
> guards, leaving a road Stormbound needs open without them. The stamp looks
> old, but Elric spots fresh tool marks on it. He must find the flaw, prove the
> stamp is fake, and give the guards a quick way to reject future copies.
>
> Stonepass's surviving CloudTrail history is the only record of activity
> surrounding the copied stamp. You hold read-only investigator access.
> Reconstruct the final recorded actions and determine which identity stopped
> the trail from logging.

Translated out of the fiction: a read-only IAM identity, one CloudTrail history
to page through, and eight embedded questions about the account's final
recorded actions. There's no `HTB{...}` flag anywhere in this challenge — the
graded deliverable is the answer to each of those eight questions, all
re-derived below directly from the raw event log.

## Attack path

1. Authenticate as the handed-out `stonepass-investigator` IAM user against a
   challenge-hosted endpoint and confirm identity with `sts.get_caller_identity()`.
2. Direct trail introspection is denied three times running: `ListTrails()`,
   then `GetTrail()` under two different name castings.
3. Pivot to `cloudtrail:LookupEvents`, which the investigator's policy does
   allow — paginating the full account history returns 271 events.
4. Filter to the one other IAM identity present in the log, `stonepass-warden`,
   isolating its events from the investigator's own denied calls and
   everything else.
5. Read the `stonepass-warden` timeline: two straight days of routine activity
   from a single internal VPC address, ending in `ListAccessKeys`.
6. 21.05 seconds later, the same access key starts making calls from a
   different, external IP with a different `userAgent` build.
7. From the external IP: a `GetTrailStatus` check, a denied `DeleteTrail`, a
   pass over the trail's own S3 log bucket, then a `StopLogging` call that
   succeeds and is the last event CloudTrail ever records for this identity.
8. Answer each of the eight embedded questions against this reconstructed
   timeline.

## Access and the pivot to LookupEvents

The starting point is a static access key for IAM user `stonepass-investigator`,
pointed at a challenge-hosted endpoint:

```python
import boto3

user = 'stonepass-investigator'
access_key = 'AKIA66DS…HZEKP'
secret_key = 'Upn/yx5u…Ji8E1'
region = 'us-east-1'
endpoint = 'http://154.57.164.81:30965/'

sts = boto3.client('sts', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region, endpoint_url=endpoint)
identity = sts.get_caller_identity()
print(identity)
```

```
{'UserId': 'AIDA61QRTXEVN7IBXYFJ', 'Account': '491827305948',
 'Arn': 'arn:aws:iam::491827305948:user/stonepass-investigator', ...}
```

A follow-up `sts.get_session_token()` call also succeeds and prints a full
temporary credential set, but the `cloudtrail` client created in the next cell
reuses the original static keys, not the session token. The temporary
credentials were pulled with an eye toward feeding them into enumeration
tooling, but that tooling didn't end up helping on this box, so the session
token itself was never chained into anything further.

Despite the read-only framing, direct trail metadata is locked down tighter
than expected — `ListTrails` and two `GetTrail` attempts (one for
`'stonepass'`, one for `'Stonepass'`) are all denied identically:

```
ListTrails()                  -> AccessDeniedException: not authorized to perform cloudtrail:ListTrails
GetTrail(name='stonepass')    -> AccessDeniedException: not authorized to perform cloudtrail:GetTrail
GetTrail(name='Stonepass')    -> AccessDeniedException: not authorized to perform cloudtrail:GetTrail
```

> 🧠 The re-cased retry (`Stonepass` after `stonepass`) was just a guess, not a
> deliberate test of case-sensitivity in the policy — both were denied for the
> same reason regardless of casing.

What the investigator's policy does allow is `cloudtrail:LookupEvents`.
Paginating it end-to-end pulls the account's entire recorded history:

```python
from pprint import pprint

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
Retrieved 50 events...
Retrieved 50 events...
Retrieved 50 events...
Retrieved 50 events...
Retrieved 21 events...
Total events retrieved: 271
```

271 events across the account's full CloudTrail history — mostly the
investigator's own denied recon calls, plus routine activity from other
identities. [271-event raw dump elided — filtered to a single identity below
instead of reproduced.]

## Isolating the compromised identity

Filtering the full event set down to the one other IAM user visible in the
log, `stonepass-warden`, isolates a single, continuous identity:

```python
warden_events = [
    event for event in all_events
    if event.get('Username') == 'stonepass-warden'
]
pprint(warden_events)
```

For two straight days (`2026-07-25T07:17:11Z` → `2026-07-27T04:25:43Z`), every
one of `stonepass-warden`'s roughly 250 logged calls — `GetTrailStatus`,
`ListObjectsV2`/`GetBucketLocation` on the trail's own log bucket,
`ListAccessKeys`, `GetUser`, `DescribeTrails` — comes from the same source IP,
`10.30.41.118`, a `10.x` address inside the account's own VPC (the
`userAgent` string on these calls also carries `exec-env/EC2`). That pattern
holds right up to the last call from that address:

```json
{"eventTime": "2026-07-27T04:25:43.738Z", "eventSource": "iam.amazonaws.com",
 "eventName": "ListAccessKeys", "sourceIPAddress": "10.30.41.118",
 "userIdentity": {"userName": "stonepass-warden", "accessKeyId": "AKIA5N7E…S84KUC"}}
```

**Last logged action from the internal IP, immediately before the takeover:
`ListAccessKeys`.**

21.05 seconds later, the same IAM identity — same `userName`, same
`accessKeyId` — starts making calls from a different address, `192.0.2.55`,
with a different (older) Boto3/Botocore/Python/kernel `userAgent` string than
the internal caller:

```json
{"eventTime": "2026-07-27T04:26:04.791Z", "eventSource": "cloudtrail.amazonaws.com",
 "eventName": "GetTrailStatus", "sourceIPAddress": "192.0.2.55",
 "userIdentity": {"userName": "stonepass-warden", "accessKeyId": "AKIA5N7E…S84KUC"}}
```

**First logged action from the new IP: `GetTrailStatus`.**

> ⚠️ UNVERIFIED: nothing in the retrieved CloudTrail data shows *how* this key
> passed from the warden's own internal use to whoever made this next call —
> there's no phishing artifact, no leaked-secret source, nothing between the
> `ListAccessKeys` call and the IP switch. The notebook's own closing note
> calls this "had their key lifted," which is this discontinuity — same
> credential, new IP, new software fingerprint, immediately followed by
> destructive actions no legitimate two-day pattern here ever attempted — read
> as inference from the log, not a theft mechanism the log itself proves.

## The final window: recon, a denied cover-up, then StopLogging

Everything from the IP switch to the last recorded event happens inside ten
seconds, all under the `stonepass-warden` identity from `192.0.2.55`:

```
GetTrailStatus  stonepass-audit-trail                                    04:26:04.791Z
DeleteTrail     stonepass-audit-trail  -> AccessDeniedException          04:26:07.159Z
ListBucket      stonepass-audit-trail-logs                               04:26:09.137Z
ListObjectsV2   stonepass-audit-trail-logs                               04:26:11.150Z
GetObject       stonepass-audit-trail-logs (AWSLogs/.../2026/06/24/...)  04:26:12.965Z  -> NoSuchKey
StopLogging     stonepass-audit-trail                                    04:26:14.602Z
```

The trail's status is checked first, then `DeleteTrail` is attempted and
denied outright:

```json
{"eventTime": "2026-07-27T04:26:07.159Z", "eventSource": "cloudtrail.amazonaws.com",
 "eventName": "DeleteTrail", "sourceIPAddress": "192.0.2.55",
 "requestParameters": {"name": "stonepass-audit-trail"},
 "errorCode": "AccessDeniedException",
 "errorMessage": "User is not authorized to perform: cloudtrail:DeleteTrail"}
```

Blocked from deleting the trail outright, the same session lists and reads
around the trail's own S3 log bucket, `stonepass-audit-trail-logs` — a
`ListBucket`, a `ListObjectsV2`, and a `GetObject` attempt on a specific log
archive key that comes back `NoSuchKey`. With deletion blocked, the session
falls back to simply switching logging off:

```json
{"eventTime": "2026-07-27T04:26:14.602Z", "eventSource": "cloudtrail.amazonaws.com",
 "eventName": "StopLogging", "sourceIPAddress": "192.0.2.55",
 "requestParameters": {"name": "stonepass-audit-trail"},
 "userIdentity": {"userName": "stonepass-warden"}}
```

`StopLogging` succeeds — no error code, unlike the `DeleteTrail` attempt — and
this is the last event CloudTrail ever records for the account. That's exactly
why the investigator's own subsequent recon (the denied `GetTrail`/`ListTrails`
calls made while starting this investigation) turns up nothing useful going
forward: after this event, there's nothing left logged to see.

## Answer key

The graded answer set, each re-derived above from the raw event log:

| Question | Answer |
|---|---|
| Last CloudTrail action from the compromised user's internal IP, immediately before the attacker session began | `ListAccessKeys` |
| First CloudTrail action from the attacker IP | `GetTrailStatus` |
| API action the attacker attempted that was explicitly denied, before stopping the trail | `DeleteTrail` |
| S3 bucket the attacker enumerated before stopping the trail | `stonepass-audit-trail-logs` |
| Name of the CloudTrail trail that was stopped | `stonepass-audit-trail` |
| IAM username whose credentials executed the trail disable | `stonepass-warden` |
| IP address the trail was disabled from | `192.0.2.55` |
| API action used to disable the audit trail | `StopLogging` |

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| `boto3` | AWS SDK used for every API call — STS, CloudTrail `lookup_events` | [boto3 documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) |

## Tactics (MITRE ATT&CK)

- **[T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)**:
  the `stonepass-warden` access key stays constant across the pivot, but its
  source IP and software fingerprint change abruptly, and the session that
  follows immediately attempts destructive, cover-up-shaped actions no
  legitimate two-day usage pattern here ever came close to — a valid cloud
  account being used by someone other than its established, internal caller.
  How the key itself was obtained isn't established by this log (see the
  ⚠️ note above); the technique tag covers the account's abuse, not the
  theft mechanism.
- **[T1562.008 — Impair Defenses: Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)**:
  the `DeleteTrail` attempt and the successful `StopLogging` call are the two
  exact AWS API calls MITRE's own detection guidance for this technique names.
- **[T1619 — Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619/)**:
  `ListBucket`/`ListObjectsV2` against `stonepass-audit-trail-logs` enumerates
  the trail's own log bucket — MITRE's own description names `ListObjectsV2`
  as a canonical example of this technique.

**Not tagged, and why:**
- *T1530 (Data from Cloud Storage)* — considered for the `GetObject` call
  against the log bucket, but the
  [technique definition](https://attack.mitre.org/techniques/T1530/) describes
  adversaries *accessing* data objects from cloud storage. This `GetObject`
  call returned `NoSuchKey` — no object was actually retrieved, only a bucket
  listing and a failed read attempt.

---

*Provenance: commands, outputs, credentials, and flags are transcribed from the
engagement notebook (credential material partially redacted). External facts (MITRE
technique definitions, CVEs, error semantics) are linked to their source and were
fetched, not recalled.*
