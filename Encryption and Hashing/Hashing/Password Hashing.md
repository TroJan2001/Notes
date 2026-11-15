---
title: "Password Hashing"
created: 2026-11-15
type: concept
tags: [concept, hashing, authentication, defense]
---

# Password Hashing

Passwords should never be stored in plain text. Instead, store a **hash** — when a user logs in, hash what they typed and compare it to the stored hash. The original password is never kept.

---

## Properties of a Good Hash Function

| Property | Meaning |
|----------|---------|
| **One-way** | Can't reverse the hash to recover the original input |
| **Deterministic** | Same input always produces the same output |
| **Fixed-length** | Output is always the same size regardless of input length |
| **Collision-resistant** | Computationally infeasible for two inputs to produce the same hash |

---

## Common Algorithms

| Algorithm | Output | Good for Passwords? | Speed |
|-----------|--------|---------------------|-------|
| **MD5** | 32 hex chars | No — fast, collision-prone | Billions/sec on GPU |
| **SHA-1** | 40 hex chars | No — deprecated | Billions/sec on GPU |
| **SHA-256** | 64 hex chars | Marginal — still fast | Billions/sec on GPU |
| **NTLM** | 32 hex chars | Legacy Windows only | Billions/sec on GPU |
| **bcrypt** | ~60 chars, `$2a$`/`$2b$`/`$2y$` prefix | Yes — deliberately slow | Cost-configurable |
| **Argon2** | Variable | Yes — modern standard | Memory-hard |

The key: MD5/SHA/NTLM were designed for **speed** (file integrity, signatures). That's terrible for passwords — attackers can test their whole wordlist in seconds. bcrypt and Argon2 are deliberately **slow**, with a tunable cost factor.

---

## Salting

Without a salt, identical passwords produce identical hashes → vulnerable to **rainbow tables** (pre-computed hash lookups).

A **salt** is a unique random string per user, combined with the password before hashing:

```
stored_value = hash(password + salt)
```

- Salt is stored alongside the hash (not secret)
- Every user gets a different salt → same password = different hash
- Rainbow tables become useless
- bcrypt and Argon2 handle salting automatically

---

## Hash Identification

### Visual — Length and Prefix

| Type | Length | Distinguishing Feature |
|------|--------|----------------------|
| MD5 | 32 hex | Ambiguous with NTLM |
| SHA-1 | 40 hex | — |
| SHA-256 | 64 hex | — |
| NTLM | 32 hex | Ambiguous with MD5 — use context |
| bcrypt | ~60 chars | `$2a$`, `$2b$`, or `$2y$` prefix |

MD5 vs NTLM: same length, context resolves it. Windows SAM/AD → NTLM. Web app database → likely MD5.

### Tools

```bash
hashid '<hash_string>'
hashcat --identify '<hash_string>'
```

### Online Lookups (CTF only — never on real engagements)

- **crackstation.net** — pre-computed lookup table
- **hashes.com** — identifies type + attempts lookup

---

## Mode/Format Reference

| Algorithm | Hashcat `-m` | John `--format=` |
|-----------|-------------|------------------|
| MD5 | 0 | raw-md5 |
| SHA-1 | 100 | raw-sha1 |
| SHA-256 | 1400 | raw-sha256 |
| SHA-512 | 1700 | raw-sha512 |
| NTLM | 1000 | nt |
| bcrypt | 3200 | bcrypt |

---

## Related Notes

- [[Hashcat]] — GPU-accelerated cracking
- [[John Basics]] — CPU-based cracking
- [[NTLM]] — Windows password hashing
- [[Authentication Bypass]]
