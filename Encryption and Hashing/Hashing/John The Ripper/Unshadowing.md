---
title: "Unshadowing"
created: 2026-03-11
type: technique
tags: [technique, cracking, hashing, linux]
---

# Unshadowing

John needs both user info and hash data in one file. On Linux, these live in two separate files — `unshadow` combines them.

---

## Why It's Needed

| File | Contains |
|------|----------|
| `/etc/passwd` | Usernames, UIDs, home dirs, shells — readable by all |
| `/etc/shadow` | Password hashes, aging info — root only |

John needs fields from both to crack effectively (especially for [[Single Crack Mode]] which uses the username).

## Combine the Files

```bash
unshadow /etc/passwd /etc/shadow > unshadowed.txt
```

You can also use individual lines instead of full files:

```
# /etc/passwd line
root:x:0:0::/root:/bin/bash

# /etc/shadow line
root:$6$2nwjN454g.dv4HN/$m9Z/r2xVfweYVkrr...GA0:18576::::::
```

```bash
unshadow local_passwd local_shadow > unshadowed.txt
```

## Crack It

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

John auto-detects the hash format from the `$6$` prefix (SHA-512). You can also specify explicitly:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt
```

---

## Common Shadow Hash Prefixes

| Prefix | Algorithm | John Format |
|--------|-----------|-------------|
| `$1$` | MD5 | md5crypt |
| `$5$` | SHA-256 | sha256crypt |
| `$6$` | SHA-512 | sha512crypt |
| `$y$` | yescrypt | yescrypt |

---

## Related Notes

- [[John Basics]] — cracking commands
- [[Single Crack Mode]] — uses the username from the unshadowed file
- [[Password Hashing]] — hashing algorithms and salting
