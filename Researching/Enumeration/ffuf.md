---
title: "ffuf"
created: 2026-03-11
type: tool
tags: [tool, enumeration, recon, fuzzing]
---

# ffuf

Fast web fuzzer written in Go. Replaces `FUZZ` in any part of a request with each line from a wordlist. Used for directory discovery, subdomain enumeration, parameter fuzzing, and login brute-forcing.

---

## Directory Discovery

```bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ
```

With extensions:

```bash
ffuf -w wordlist.txt -u http://target.com/FUZZ -e .php,.html,/ -mc 200,301,302
```

## Subdomain Discovery

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -H "Host: FUZZ.target.com" -u http://target.com -fs 0
```

`-fs 0` filters out empty responses. If subdomains return varied content, use the two-pass technique: run once without `-fs`, note the response size that most results share (the "default" page), then re-run with `-fs {size}` to filter those out and surface real subdomains.

## Parameter Fuzzing

GET parameters:

```bash
ffuf -w wordlist.txt -u http://target.com/page?FUZZ=value
```

POST parameters:

```bash
ffuf -w wordlist.txt -X POST -d "FUZZ=value" \
     -H "Content-Type: application/x-www-form-urlencoded" -u http://target.com/login
```

## Username Enumeration

```bash
ffuf -w names.txt -X POST \
     -d "username=FUZZ&email=x&password=x&cpassword=x" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -u http://target.com/signup -mr "username already exists"
```

## Multi-Wordlist (Login Brute-Force)

Use named wordlists with `W1` and `W2`:

```bash
ffuf -w users.txt:W1,passwords.txt:W2 -X POST \
     -d "username=W1&password=W2" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -u http://target.com/login -fc 200
```

---

## Flags

| Flag | Purpose |
|------|---------|
| `-w <file>` | Wordlist (use `:NAME` for multi-wordlist) |
| `-u <url>` | Target URL with `FUZZ` keyword |
| `-X <method>` | HTTP method (GET, POST, etc.) |
| `-d <data>` | POST body |
| `-H <header>` | Add/override a header |
| `-e <exts>` | Extensions to append (`.php,.html,/`) |
| `-mc <codes>` | Match HTTP status codes (default: 200,204,301,302,307,401,403,405) |
| `-fc <codes>` | Filter (exclude) status codes |
| `-fs <size>` | Filter by response size |
| `-fl <lines>` | Filter by line count |
| `-fw <words>` | Filter by word count |
| `-mr <regex>` | Match response body regex |
| `-fr <regex>` | Filter response body regex |
| `-t <threads>` | Thread count (default 40) |
| `-r` | Follow redirects |
| `-o <file>` | Output to file |
| `-of <fmt>` | Output format (json, csv, html) |

---

## Related Notes

- [[Gobuster]] — simpler directory brute-forcer
- [[dirb]] — older directory scanner
- [[Custom Wordlists]] — building targeted wordlists
- [[Nikto]] — web vulnerability scanner
