---
layout: post
title: "crypto - perfect math class"
date: 2024-07-06 00:00:00 -0700
categories: ctfs
description: "Use modulus math to solve for a common modulo, then use Hastad's Broadcast to solve for the flag"
parent: Down Under CTF 5
grand_parent: CTF Events
event: "down-under-ctf-5"
tags:
- "crypto"
- "chinese remainder theorem"
- "crt"
---
# perfectmath

## Engagement Notes

Two questions regarding modulus math. One is a common-modulo between estimated numbers, followed by a Hastad's Broadcast calculation to determine the flag bytes.


```python
# When the soldiers stand 3 in a row, there are 2 soldiers left over. When they line up 5 in a row, there are 4 soldiers left over. When they line up 7 in a row, there are 5 soldiers left over.

# Find the modulus of each equation between the suspected values
for i in range(1000, 1100):
    if (i - 2) % 3 == 0 and (i - 4) % 5 == 0 and (i - 5) % 7 == 0:
        print(i)
```

    1034


The challenge gives us more modulus math to do. Some googling tells us that small `e` can be worked with Hastad's Broadcast, for which SageMath provides some convenient modulus math to help us solve.

The more interesting takeaway was how I managed to get sage working. In this case I used the `sagemath/sagemath` docker image, and then connected my jupyter notebook via vscode/codium plugins to the local container across port 8888. The result of that was a locally running jupyter notebook that could run sage commands.


```python
e = 3

c_1 = 1050018241<snip>8024637
c_2 = 3163144283<snip>7878737
c_3 = 6486497703<snip>2258659

n_1 = 1478962700<snip>9853299
n_2 = 9597936500<snip>9815403
n_3 = 9564930831<snip>7188095

# Use sage to solve using CRT
from sage.all import *
c = [c_1, c_2, c_3]
n = [n_1, n_2, n_3]
M = crt(c, n)
m = M ** (1/3)
print(m)
# Unhex m
print(bytes.fromhex(hex(int(m))[2:]))

```

    11564025922867522<snip>6967888274582504750347133
    b'DUCTF{btw_y0u_c4n_als0_us3_CRT_f0r_p4rt14l_fr4ct10ns}'

