---
layout: post
title: "Empty Chairs"
date: 2026-07-28 00:00:00 -0700
categories: ctfs
description: A CloudTrail-only forensics reconstruction of a contractor's long-lived IAM key blindly failing AssumeRole for four days, then succeeding and forging an SQS dispatch order before purging the queue — an answer-key challenge with no flag.
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
  - "T1580"
  - "T1548.005"
  - "T1565.001"
---

## Engagement Notes

`empty-chairs` is a cloud-category challenge from Cyberapocalypse 2026, framed
as a forensics investigation rather than an exploit chain: read-only
`eastreach-investigator` credentials into a CloudTrail-logged AWS account, and
a set of sub-questions to answer by reconstructing what an external party did
with a compromised identity before a batch of dispatched "scouts" (in-fiction)
went missing. There is no `HTB{...}` flag anywhere in this challenge — the
deliverable is a table of answers, each pinned to a specific CloudTrail event,
extracted purely by filtering and sorting 3,294 logged API calls. The
investigation turns up one AWS access pattern worth remembering: a long-lived
IAM key blindly failing the same `AssumeRole` call for four days straight,
then switching to a new source IP, succeeding against a *different* secret it
had never tried before, and doing everything it was ever going to do — forge
a dispatch order, decrypt a routing envelope, write a forged ledger entry, and
purge the queue behind it — in nine seconds.

The challenge briefing also promises a second evidence source ("the manifest
bucket's S3 server access logs") that was never actually reachable with the
credentials on hand — see the note on that gap below.

## Attack path

1. Authenticate as the handed-out `eastreach-investigator` IAM user against
   the challenge endpoint and pull every CloudTrail event via
   `lookup_events` — 3,294 events total.
2. Filter every `ReceiveMessage` call by source IP to find the boundary
   between the legitimate internal dispatcher and an external reader of the
   same queue.
3. Build a "malicious IP" set by excluding internal (`10.23.x.x`),
   loopback, and S3-service traffic — surfacing one long-lived IAM user,
   `eastreach-contractor`, operating from four external IPs.
4. Sort that identity's activity by time: four days of denied `AssumeRole`
   and `GetSecretValue` attempts against the same role and the same three
   decoy secret names, from three of the four IPs.
5. On the fourth IP, the same key finally reads the one secret it had never
   tried, then successfully assumes a role it was never denied on the first
   try.
6. As the assumed role, replay the nine-second sequence that follows: read
   the target SQS queue, inject a forged order, decrypt a KMS-wrapped
   routing envelope, publish an SNS alert, write a forged DynamoDB ledger
   entry, pull a signed manifest from S3, check the CloudTrail trail's
   status, and purge the queue.
7. Answer each embedded question against this reconstructed timeline.

## Establishing the baseline: who normally reads the queue

The investigator's own access is a plain boto3 session against a
challenge-hosted endpoint:

```python
import boto3

user = 'eastreach-investigator'
access_key = 'AKIAXXVR39UKNWIN…'
secret_key = 'mTQwRyvhLu1znyZ…'
region = 'us-east-1'
endpoint = 'http://154.57.164.81:30956/'

sts = boto3.client('sts', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region, endpoint_url=endpoint)
identity = sts.get_caller_identity()
print(identity)
```

```
{'UserId': 'AIDA64S1P6IJIQ9PT54L', 'Account': '719384620571',
 'Arn': 'arn:aws:iam::719384620571:user/eastreach-investigator', ...}
```

Pulling every CloudTrail event via the paginator lands on the full haystack:

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
Retrieved 50 events...
[... 66 pages of 50 elided ...]
Total events retrieved: 3294
```

Every `ReceiveMessage` call is filtered and its source IPs deduplicated to
establish who normally talks to the dispatch queues:

```python
receive_message = [log for log in all_events if log["EventName"] == "ReceiveMessage"]
receive_message_ips = []
for log in receive_message:
    ip = json.loads(log['CloudTrailEvent'])['sourceIPAddress']
    if ip not in receive_message_ips:
        receive_message_ips.append(ip)
pprint(receive_message_ips)
```

```
['203.0.113.88',
 '10.23.87.41', '10.23.87.48', '10.23.87.43',
 '10.23.87.59', '10.23.87.52', '10.23.87.55']
```

Six `10.23.87.x` addresses are the legitimate `eastreach-dispatcher` service
polling its own queue. `203.0.113.88` is the one address that does not
belong. Sorting the `ReceiveMessage` calls on the recall queue by timestamp
pins the exact handoff between the two: the last legitimate poll comes from
`10.23.87.41`, and the very next `ReceiveMessage` on that queue comes from
`203.0.113.88` — the same IP that goes on to run the entire diversion.

## Isolating the external actor

A `malicious_ips` set is built by excluding any event whose raw JSON
mentions `10.23`, `127.0.0.1`, or `s3.amazonaws.com`:

```python
malicious_ips = set()
for log in all_events:
    if ('10.23' not in log['CloudTrailEvent'] and '127.0.0.1' not in log['CloudTrailEvent'] and 's3.amazonaws.com' not in log['CloudTrailEvent']):
        malicious_ips.add(json.loads(log['CloudTrailEvent'])['sourceIPAddress'])
print(malicious_ips)
```

```
{'203.0.113.41', '198.51.100.22', '203.0.113.17', '98.97.141.106', '203.0.113.88'}
```

`98.97.141.106` is noise — it is the investigator's own workstation,
captured only because the very first `GetCallerIdentity` call above is
itself a logged CloudTrail event. The other four IPs all trace back to one
IAM identity: `eastreach-contractor`, authenticating throughout with a
single long-lived access key (`AKIAG7OI7AQ50S68QSO1` — no session token, no
expiry).

## Four days of failed reconnaissance

Sorting every event from `eastreach-contractor` by timestamp shows the same
pattern repeating from three of the four IPs (`203.0.113.41`,
`198.51.100.22`, `203.0.113.17`) across `2026-07-24T07:09:23Z` through
`2026-07-28T03:05:37Z` — 470 events, weighted toward the final hours before
the pivot (62 / 75 / 81 / 51 events on 07-24 through 07-27, then 201 in the
last stretch of 07-28):

| What repeats | Target | Result |
|---|---|---|
| `AssumeRole`, session name `contractor-survey` | `role/eastreach-archive-reader` | `AccessDenied`, every time |
| `GetSecretValue` | `eastreach/dispatch-signing-draft` | `AccessDeniedException`, every time |
| `GetSecretValue` | `eastreach/patrol-ledger-token` | `AccessDeniedException`, every time |
| `GetSecretValue` | `eastreach/depot-routing/manifest` | `AccessDeniedException`, every time |
| `ListSecrets`, `GetCallerIdentity` | — | the only calls that ever succeed |

The secret that eventually works, `eastreach/dispatch-signing`, is never
attempted during this whole phase — the four days are spent guessing at one
role and three decoy secret names that were never going to work.

## The live diversion — 2026-07-28T03:05:41Z to 03:05:54Z

The same credentials switch to a fourth IP, `203.0.113.88`, and within three
seconds read the secret that actually works, after two more denied guesses
against the same decoy names:

```
GetSecretValue  eastreach/dispatch-signing-draft   AccessDeniedException
GetSecretValue  eastreach/patrol-ledger-token      AccessDeniedException
GetSecretValue  eastreach/depot-routing/manifest   AccessDeniedException
GetSecretValue  eastreach/dispatch-signing         OK
```

The first `AssumeRole` in this session repeats the recon phase's role one
more time under a fresh session name and is still denied. The very next
call succeeds:

```python
{'CloudTrailEvent': '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"eastreach-contractor", ...
"eventName":"AssumeRole","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.88", ...
"requestParameters":{"path":"/","roleArn":"arn:aws:iam::719384620571:role/eastreach-dispatch-role","roleSessionName":"dispatch-runner","action":"AssumeRole"},"responseElements":{"credentials":{"accessKeyId":"ASIALUEWIGDWH008LGR0","expiration":"2026-07-28T04:05:45.787635732Z"},"assumedRoleUser":{"arn":"arn:aws:sts::719384620571:assumed-role/eastreach-dispatch-role/dispatch-runner", ...}}}'}
```

> 🧠 The role that finally worked (`eastreach-dispatch-role`, session
> `dispatch-runner`) was picked over the repeatedly-denied
> `eastreach-archive-reader` because the archive-reader role "probably
> wouldn't have access to routing" anyway — a reasoned exclusion, not a
> blind retry of the same guess.

From this point on, CloudTrail records `userIdentity.type` as `AssumedRole`
rather than `IAMUser` for every subsequent call. What follows happens in
nine seconds:

| Time (UTC) | Call | Target | Result |
|---|---|---|---|
| 03:05:47 | `GetQueueAttributes` | `eastreach-recall-archive` | `AccessDeniedException` (wrong queue) |
| 03:05:48 | `ReceiveMessage` | `eastreach-scout-recall-pending` | OK |
| 03:05:48 | `SendMessage` | `eastreach-scout-recall-pending` | OK — forged order |
| 03:05:49 | `Decrypt` (KMS) | `alias/eastreach/watchpost-routing-key` | OK |
| 03:05:49 | `Publish` (SNS) | `eastreach-diversion-alerts` | OK |
| 03:05:50 | `PutItem` (DynamoDB) | `eastreach-watchpost-ledger` | OK — forged ledger row |
| 03:05:51 | `ListObjectsV2` + `GetObject` (S3) | `eastreach-watchpost-manifests/signed-routing-bundle.json` | OK |
| 03:05:53 | `GetTrailStatus` | `eastreach-watchpost-trail` | OK |
| 03:05:54 | `PurgeQueue` | `eastreach-scout-recall-pending` | OK |

The wrong-queue probe (`eastreach-recall-archive`) shows the role reaching
for a plausible-sounding queue name first; the one it can actually touch,
`eastreach-scout-recall-pending`, is the real target. The forged message
body:

```json
{
  "order_id": "ER-DIV-9941",
  "route_override": "quietmarch-depot-11/bypass-C",
  "authorized_by": "dispatch-runner",
  "priority": "URGENT"
}
```

> 🧠 The queue name was found "scrolling up through the original
> `all_events` after the event_id identified in the successful assume
> role" and validated against the malicious IP making the call — the first
> SQS call in that scroll didn't mutate the queue (the wrong-queue probe
> above), so the next one to actually modify it was the answer.

The `SendMessage` is immediately followed by a KMS `Decrypt` against the
routing key alias — consistent with decrypting the legitimate routing
envelope so the forged order blends in — then an SNS `Publish` (raising the
diversion alert) and a DynamoDB `PutItem` into the watchpost ledger, writing
the forged order in as if it were authentic. The role then pulls the
manifest bucket directly, retrieving `signed-routing-bundle.json` via
`GetObject`, captured verbatim in the notebook as a pasted CloudTrail
record:

```
{'CloudTrailEvent': '{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole", ...
"eventName":"GetObject","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.88", ...
"requestParameters":{"bucketName":"eastreach-watchpost-manifests","key":"signed-routing-bundle.json"}, ...
"resources":[{"ARN":"arn:aws:s3:::eastreach-watchpost-manifests/signed-routing-bundle.json", ...
```

## The gap in the evidence: S3 access logs

> The watch post's dispatch systems recorded activity before the scouts
> disappeared. You hold read-only investigator access to CloudTrail and the
> manifest bucket's S3 server access logs.

The briefing promises a second evidence source, but the investigator's
credentials couldn't locate or reach that logging bucket — no cell in the
notebook ever retrieves an S3 access log file, and the whole reconstruction
above comes from CloudTrail alone. One embedded question still asks for a
detail that would normally come from that log ("what is the S3 access log
operation field for the `GetObject` on `signed-routing-bundle.json`?"); it's
answered `REST.GET.OBJECT`, sourced directly from AWS's own [S3 server
access log format
reference](https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html)
rather than from a retrieved log line.

> ⚠️ That one answer is a documented fact (AWS's log format spec names
> `REST.GET.OBJECT` as the operation string for a GET request), not a
> finding pulled from this account's actual access logs.

## Erasing the evidence

The last two calls of the nine-second session are the anti-forensics tell:

```
GetTrailStatus  eastreach-watchpost-trail        OK
PurgeQueue      eastreach-scout-recall-pending    OK
```

The trail, `eastreach-watchpost-trail`, is checked but never disabled or
deleted — it keeps recording every step above. `PurgeQueue` is the actual
evidence-destruction move: it wipes the queue's contents, including the
forged order and any legitimate messages still sitting in it. CloudTrail
itself, precisely because it was never touched, is what survives to tell
the whole story.

> ⚠️ UNVERIFIED: nothing in the retrieved CloudTrail data shows how
> `eastreach-contractor`'s key was originally obtained — the only
> `CreateAccessKey` events for that user are infrastructure-seeding calls
> from `127.0.0.1`, not an attacker action. Treated as out of scope for this
> challenge; not reconstructed here.

## Answer key

| Question | Answer |
|---|---|
| Last internal source IP on `ReceiveMessage` before the external takeover | `10.23.87.41` |
| External IP running the full diversion (incl. `PurgeQueue`) | `203.0.113.88` |
| Secret returning `AccessDenied` on the first denied `GetSecretValue` call (live IP) | `eastreach/dispatch-signing-draft` |
| Secret successfully read before the role assumption | `eastreach/dispatch-signing` |
| IAM role name the attacker failed to assume before the successful pivot | `eastreach-archive-reader` |
| IAM role ARN successfully assumed | `arn:aws:iam::719384620571:role/eastreach-dispatch-role` |
| `roleSessionName` on the successful `AssumeRole` | `dispatch-runner` |
| CloudTrail identity type after the pivot | `AssumedRole` |
| SQS queue targeted for the fraudulent recall order | `eastreach-scout-recall-pending` |
| Forged `order_id` | `ER-DIV-9941` |
| Forged `route_override` | `quietmarch-depot-11/bypass-C` |
| KMS `keyId` used to decrypt the routing envelope | `arn:aws:kms:us-east-1:719384620571:alias/eastreach/watchpost-routing-key` |
| SNS topic that received the diversion alert | `eastreach-diversion-alerts` |
| DynamoDB table that received the forged ledger entry | `eastreach-watchpost-ledger` |
| S3 access-log operation field for the `GetObject` call (documented, not log-sourced) | `REST.GET.OBJECT` |
| CloudTrail trail verified before the queue was purged | `eastreach-watchpost-trail` |
| API action that destroyed the queue evidence | `PurgeQueue` |
| IAM user owning the long-lived key that started the chain | `eastreach-contractor` |

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| `boto3` | AWS SDK used for every API call — STS, CloudTrail `lookup_events`, S3, IAM | [boto3 documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) |

## Tactics (MITRE ATT&CK)

- **[T1078.004 — Valid Accounts: Cloud
  Accounts](https://attack.mitre.org/techniques/T1078/004/)**: the entire
  chain runs on one already-compromised, long-lived IAM access key
  (`eastreach-contractor`) with no session expiry — exactly the persistent
  cloud-credential misuse this technique describes.
- **[T1580 — Cloud Infrastructure
  Discovery](https://attack.mitre.org/techniques/T1580/)**: the four-day
  recon phase's `ListSecrets`, `ListRoles`, `ListBuckets`, and
  `DescribeTrails` calls enumerate what the compromised key can reach,
  matching the technique's documented `ListBuckets`-style procedure
  examples.
- **[T1548.005 — Abuse Elevation Control Mechanism: Temporary Elevated
  Cloud Access](https://attack.mitre.org/techniques/T1548/005/)**: the
  successful `sts:AssumeRole` into `eastreach-dispatch-role` is exactly the
  role-assumption abuse this technique covers.
- **[T1565.001 — Data Manipulation: Stored Data
  Manipulation](https://attack.mitre.org/techniques/T1565/001/)**: the
  forged `PutItem` into `eastreach-watchpost-ledger` inserts fabricated data
  at rest to make the fraudulent order read as authentic.

**Not tagged, and why:**
- *T1485 (Data Destruction)* and *T1070 (Indicator Removal)* — both
  considered for the final `PurgeQueue` call. T1485's definition and
  examples center on destroying files, disk structures, or storage objects
  to interrupt availability; T1070's parent definition and every documented
  sub-technique/procedure example target OS or application logs (event
  logs, command history, file metadata), not cloud message-queue contents.
  Neither official definition cleanly covers purging an SQS queue as an
  anti-forensics move.
- *T1565.002 (Transmitted Data Manipulation)* — considered for the forged
  `SendMessage` itself. The technique's definition requires intercepting
  and altering data already in transit; injecting a wholly new forged
  message into a queue isn't that.

## Lessons

> 🧠 The main personal takeaway wasn't about the AWS chain itself, but the
> tooling used to work it: more practice with Python data manipulation —
> filtering, sorting, and cross-referencing a few thousand JSON events by
> hand — would have made this investigation faster.

## Further reading

**Used during the engagement:**
- [AWS S3 server access log format
  reference](https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html)
  — the source for the one answer not derivable from the retrieved
  CloudTrail data.

---

*Provenance: commands, outputs, credentials, and flags are transcribed from the
engagement notebook (credential material partially redacted). External facts (MITRE
technique definitions, CVEs, error semantics) are linked to their source and were
fetched, not recalled.*
