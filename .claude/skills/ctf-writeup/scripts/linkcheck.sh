#!/usr/bin/env bash
# HTTP-check every link in a markdown post. Fabricated/dead links must be caught
# before publishing. Emits a status per URL and a nonzero exit if any URL is a
# genuine break (after accounting for known false positives).
#
# Usage: linkcheck.sh <post.md>
#
# False positives (reported but NOT counted as failures):
#   000  in-command target box URLs (http://<box>.htb:PORT/...) — the target, not a citation
#   403  anti-bot / Cloudflare sites (akamai.com, medium.com, some blogs) — confirm with WebFetch
#
# Any other non-2xx/3xx (esp. 404) IS a failure — most likely a fabricated tool/repo link.
set -uo pipefail

post="${1:?usage: linkcheck.sh <post.md>}"
fail=0

# Extract URLs, strip trailing punctuation/paren.
grep -oE 'https?://[^) ]+' "$post" | sed 's/[.,]*$//' | sort -u | while read -r url; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -L --max-time 20 "$url")
  note=""
  case "$code" in
    2*|3*) ;;                                   # ok
    000)
      if [[ "$url" =~ \.htb(:[0-9]+)?/ ]]; then
        note="  (target box in a command — expected unreachable, not a citation)"
      else
        note="  <-- CHECK: no response"; fail=1
      fi
      ;;
    403)
      note="  (403 likely anti-bot — CONFIRM the page is real with WebFetch, do not delete)"
      ;;
    *)
      note="  <-- FAIL: likely fabricated or moved — find the real URL or leave unlinked"; fail=1
      ;;
  esac
  printf "%-4s %s%s\n" "$code" "$url" "$note"
done

echo
echo "Reminder: a 403 is only OK once WebFetch confirms the page exists and is on-topic."
