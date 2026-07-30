---
layout: post
title: "Ash Record"
date: 2026-07-25 00:00:00 -0700
categories: ctfs
description: A min-gap subsequence-matching puzzle that was never actually solved with an algorithm — the accepted submission just echoes the sequence length straight back out of the input line.
parent: HackTheBox - Apocalypse '26
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
- "coding"
- "python"
- "cyberapocalypse"
---

## Engagement Notes

`ash-record` is a coding-category challenge from Cyberapocalypse 2026, framed as
a forensics puzzle: a hamlet was evacuated in an unnaturally orderly way, and the
task is to confirm how much of a suspected "extraction sequence" the recovered
evidence actually backs up. Underneath the narrative it's a constrained-subsequence
matching problem with a minimum-time-gap rule between matches.

This one is not a clean solve writeup. The subsequence-matching logic was never
implemented — the cell meant to hold it is a placeholder comment, and the local
test assertion was set up to fail regardless of any real logic, since its expected
value was hardcoded rather than computed. The submission that was actually accepted
prints a value straight out of the first input line without touching the residue
data at all. It was solved, but not the way the problem was designed to be solved.

## The problem

The first line gives three space-separated integers: `N P min_gap`. `N` is the
number of recovered residues, `P` is the length of the suspected extraction
sequence, and `min_gap` is the minimum time difference required between any two
consecutively matched residues. The second line gives `P` space-separated
material-type strings — the suspected sequence, in order. Each of the next `N`
lines gives one residue as `timestamp material_type`, not necessarily in
timestamp order.

The required output is a single integer: the longest prefix of the suspected
sequence that can be confirmed as a subsequence of the residues, subject to the
min-gap constraint between consecutive matches. Constraints: `1 ≤ N ≤ 5000`,
`1 ≤ P ≤ 12`, `1 ≤ min_gap ≤ 10`, `1 ≤ timestamp ≤ 10000`, material strings are
lowercase, length ≤ 10.

## Attack path

1. Read the problem and sketched a greedy approach: skip residues that violate
   the min-gap rule and count matched steps until the sequence runs out or the
   residues do.
2. Set up a local test case (the challenge's own sample I/O) and a placeholder
   assertion to check against — before writing the matching logic itself.
3. Never filled in the matching logic. The assertion was hardcoded to fail.
4. Re-read the prompt and noticed the second value on the first input line is
   the length of the suspected sequence, `P`. Submitted a script that just
   prints that value back out.
5. The submission was accepted.

## Reading the problem, and stalling on it

> 1 <= N <= 5000
> 1 <= P <= 12
> 1 <= min_gap <= 10
> 1 <= timestamp <= 10000
> Material type strings consist of lowercase letters, length <= 10

The first working notes on an approach:

> From this I'm left to make assumptions, I ASSUME that if I hit a line that is
> greater than the minimum gap, then I can assume its bad and pop it and try
> the next one, as they're valid I should probalby just increment a value until
> I hit the desired number of steps.
>
> I'm given n = input() and print(n) to get the response

and a short parse plan:

> Step 1) Parse the data, line 1 is instructions, line 2 is valid materials and
> their order, line 3+ instructions
> step 2) split instructions to input length, length of goal,

A local test case was set up before any of that was implemented:

```python
test_input = """
5 4 3
ash rope oil ash
1 ash
4 rope
7 oil
10 ash
11 rope
"""
test_answer = 0
test_output = 4
```

That test case is the challenge's own published sample input/output, not a
hand-built one. The cell meant to hold the actual matching logic, though, was
never filled in:

```
> logic would go here if I needed it
```

and the assertion meant to validate it was doomed from the start, since
`test_answer` was hardcoded to `0` rather than computed:

```python
assert test_answer == test_output
```

> 🧠 The gap between the sketched greedy idea and ever writing it down as code
> was never closed — that part of the reasoning is not reconstructed here, by
> the operator's own call.

## What didn't work

- **The greedy pop/skip idea sketched in the notes.** Never implemented — not a
  tried-and-failed dead end so much as an approach that was reasoned about and
  then abandoned before being coded.
- **The local test scaffold (`test_answer = 0` / `assert`).** Not a real check.
  `test_answer` was never computed from actual logic, so the assertion was
  guaranteed to fail no matter what.

> 🧠 "It's just the print statement and my frustration" — there isn't more to
> the dead-end than that: the matching logic simply never got written.

## The pivot

> I didn't even end up writing the code here, I just tried the following in
> the provided ide as a quick test
>
> After reading it 800 times I realized they just output the answer as
> part of the input, so this was my final script:
>
> take in the number
> n = input()
>
> calculate answer
> suspect = n.split('\n')[0].split()[1]
>
> print answer
> print(suspect)

In plain terms: instead of computing the confirmable prefix, the final script
reads the first input line (`N P min_gap`), splits it, and prints the second
token — `P`, the length of the suspected sequence — without ever touching the
residue data. A chat line pasted alongside it frames this as a deliberate,
slightly incredulous guess rather than a derived insight:

> [7:44 AM] Tokugero: literally "first line of input, second value, throw it
> at the wall and see if it sticks"

> 🧠 The submission was accepted. The reasoning behind *why* printing `P`
> verbatim happens to be correct on the actual test data was not worked out —
> the guess was thrown at the checker, and it stuck.

## Tactics

Not applicable. This is a single-file coding/scripting challenge with no
exploitation, enumeration, or access-control component — there is no MITRE
ATT&CK technique that fits the shape of what happened here.

## Lessons

> 🧠 "Just read slowly and carefully" — the intended algorithm (a min-gap
> constrained subsequence match) was never written, and the accepted answer
> came from noticing something about the input format on a very close re-read,
> not from solving the stated problem.

## Further reading

No external tools or references were used solving this challenge — it was
worked entirely in the platform's own IDE, in Python, from the problem prompt.

---

*Provenance: commands, outputs, credentials, and flags are transcribed from the
engagement notebook (credential material partially redacted). External facts (MITRE
technique definitions, CVEs, error semantics) are linked to their source and were
fetched, not recalled.*
