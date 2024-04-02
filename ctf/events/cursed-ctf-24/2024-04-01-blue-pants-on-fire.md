---
layout: post
title: "pwn blue-pants-on-fire"
date: 2024-04-01 00:00:00 -0700
categories: ctfs
description: 
parent: Cursed CTF '24
grand_parent: CTF Events
event: "cursed-ctf"
tags:
- "rust"
- "pwn"
- "reverse engineering"
- "bpf"
---

## Blue Pants On Fire (BPF) - PWN challenge
This challenge began with an anti-spam proof-of-work script that routed you into a qemu-looking boot sequence followed by 'The flag is at /flag.txt. Good Luck!'. The goal was to bypass bpf filters that would hijack the contents of the output of flag.txt before it sent the string to stdout.

### Recon
#### Tools

#### Logging in
```sh
[12:23:59] tokugero :: pangolin  ➜  ~ » nc fuzzbox.addisoncrump.info 5000
proof of work:
curl -sSfL https://pwn.red/pow | sh -s s.AAA6mA==.IYecQs5WM8psI1QUf8xxYg==
solution:
```
```sh
[12:23:40] tokugero :: pangolin  ➜  ~ » curl -sSfL https://pwn.red/pow | sh -s s.AAA6mA==.IYecQs5WM8psI1QUf8xxYg==

s.W2ACFYds5hFD0wgb6kr90ur/0b658a+OT1FoKUJNOPv5wAVuDlJhIzUNXG4M/L48Ood1xyWuFzvsLO9dhWkQw850ByS8Cp5X8D0/wblynsT8Qap4/hCu17yrtX3iHFSdoDqVj5nm6nEF2X8ADqQ/DH7b3WzEaIIx8odyO9bjvOz4fo+6I0SYqJEGyGlLZRLZDu7zqKpK1y3sGKfbbyhHYg==
```
```sh
[    2.754164] Run /init as init process


Boot took 2.77 seconds

┏┓ ╻  ╻ ╻┏━╸   ┏━┓┏━┓┏┓╻╺┳╸┏━┓   ┏━┓┏┓╻   ┏━╸╻┏━┓┏━╸
┣┻┓┃  ┃ ┃┣╸    ┣━┛┣━┫┃┗┫ ┃ ┗━┓   ┃ ┃┃┗┫   ┣╸ ┃┣┳┛┣╸
┗━┛┗━╸┗━┛┗━╸   ╹  ╹ ╹╹ ╹ ╹ ┗━┛   ┗━┛╹ ╹   ╹  ╹╹┗╸┗━╸

Good luck :) Flag is at /flag.txt

[    2.958757] input: ImExPS/2 Generic Explorer Mouse as /devices/platform/i8042/serio1/input/input3
[    3.may corrupt user memory!1] is installing a program with bpf_probe_write_user helper that 
[    3.165430] blue-pants-on-f[1] is installing a program with bpf_probe_write_user helper that may corrupt user memory!
[    3.166298] blue-pants-on-f[1] is installing a program with bpf_probe_write_user helper that may corrupt user memory!
/bin/sh: can't access tty; job control turned off
~ $ 
```

### Understanding
#### Tools

### Crafting the exploit
#### Tools

### Things that didn't work

### Conclusion