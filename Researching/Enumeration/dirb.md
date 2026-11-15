---
title: "dirb"
created: 2026-03-11
type: tool
tags: [tool, enumeration, recon]
---

# dirb

Web content scanner that finds hidden directories and files by running a dictionary attack against a web server. Simpler than [[ffuf]] or [[Gobuster]] but single-threaded and slower on large wordlists.

---

## Basic Usage

```bash
dirb http://target.com
```

Uses the default wordlist at `/usr/share/dirb/wordlists/common.txt`.

With a custom wordlist:

```bash
dirb http://target.com /usr/share/wordlists/dirb/big.txt
```

With extensions:

```bash
dirb http://target.com -X .php,.html,.txt
```

---

## Flags

| Flag | Purpose |
|------|---------|
| `-o <file>` | Save output to file |
| `-r` | Don't search recursively |
| `-X <exts>` | Append extensions (e.g., `.php,.html,.bak`) |
| `-a <agent>` | Custom User-Agent string |
| `-c <cookie>` | Send a cookie (e.g., `session=abc123`) |
| `-H <header>` | Add a custom header |
| `-p <proxy>` | Use a proxy (e.g., `http://127.0.0.1:8080`) |
| `-z <ms>` | Delay between requests (milliseconds) |
| `-N <code>` | Ignore responses with this status code |
| `-w` | Don't stop on warning messages |
| `-S` | Silent mode — don't show tested words |

---

## Default Wordlists

Located at `/usr/share/dirb/wordlists/`:

| List | Size | Use |
|------|------|-----|
| `common.txt` | ~4,600 | Quick scan, default |
| `big.txt` | ~20,400 | Thorough scan |
| `small.txt` | ~960 | Very fast, low coverage |
| `vulns/` | varies | Vulnerability-specific paths (Apache, IIS, CGI) |

---

## When to Use dirb vs ffuf/Gobuster

| | dirb | [[ffuf]] / [[Gobuster]] |
|---|------|---------|
| **Speed** | Slow (single-threaded) | Fast (multi-threaded) |
| **Features** | Basic directory scanning | Subdomain, parameter, header fuzzing |
| **Best for** | Quick checks, small lists | Large lists, complex fuzzing |

For serious enumeration, prefer ffuf or Gobuster. dirb is fine for a quick default-wordlist scan.

---

## Related Notes

- [[ffuf]] — fast multi-purpose fuzzer
- [[Gobuster]] — fast directory brute-forcer
- [[Custom Wordlists]] — building targeted wordlists
