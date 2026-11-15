---
title: "John Basics"
created: 2026-03-11
type: tool
tags: [tool, cracking, hashing]
---

# John the Ripper

Versatile CPU-based password cracker. Handles a wide range of hash formats, including many non-standard ones. Good auto-detection, excellent for Unix shadow files and quick attempts.

---

## Basic Syntax

```bash
john [options] <hash_file>
```

---

## Dictionary Attack

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

Always specify `--format=` when you know the hash type. Auto-detect can guess wrong — it once defaulted to LM for an MD5 hash and cracked nothing.

## Auto-Detect (when unsure)

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

If it picks the wrong format, re-run with explicit `--format=`.

## Rule-Based Attack

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt --rules=wordlist hashes.txt
```

| Rule Set | Description |
|----------|-------------|
| `--rules=wordlist` | Default mutations (capitalize, append numbers, etc.) |
| `--rules=single` | Name/username-based mutations |

---

## Common Formats (`--format=`)

| Algorithm | Format |
|-----------|--------|
| MD5 | `raw-md5` |
| SHA-1 | `raw-sha1` |
| SHA-256 | `raw-sha256` |
| SHA-512 | `raw-sha512` |
| NTLM | `nt` |
| bcrypt | `bcrypt` |

Standard hash types need the `raw-` prefix. Check available formats:

```bash
john --list=formats | grep -iF "md5"
```

---

## Viewing Cracked Passwords

```bash
john --show --format=raw-md5 hashes.txt
```

Always include `--format` with `--show` — otherwise John may not find the entries in the potfile.

Potfile location: `/usr/local/john/run/john.pot`

---

## Hash Identification

```bash
hashid '<hash_string>'
```

For 32-char hex hashes (MD5 vs NTLM), use context: Windows SAM/AD → NTLM, web app → likely MD5.

---

## Specialized Converters

John includes `*2john` tools that convert protected files into crackable hash format:

| Tool | Converts |
|------|----------|
| [[SSH2John]] | SSH private keys |
| [[GPG2John]] | GPG/PGP keys |
| `zip2john` | Password-protected ZIP files |
| `rar2john` | Password-protected RAR files |
| `keepass2john` | KeePass databases |

Usage pattern:

```bash
ssh2john id_rsa > ssh_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt
```

---

## Related Notes

- [[Password Hashing]] — how passwords are stored, algorithm comparison
- [[Hashcat]] — GPU-accelerated alternative
- [[Hydra]] — online brute-forcing (live services)
- [[Unshadowing]] — combining /etc/passwd and /etc/shadow
- [[Single Crack Mode]] — username-based mutations
- [[Custom Rules]] — writing custom John rules
