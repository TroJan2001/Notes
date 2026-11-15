---
title: "Hashcat"
created: 2026-11-15
type: tool
tags: [tool, cracking, hashing]
---

# Hashcat

GPU-accelerated password cracker. Significantly faster than [[John Basics|John the Ripper]] for most hash types — billions of MD5/SHA candidates per second on a modern GPU. For bcrypt, speed difference is minimal because bcrypt is deliberately slow.

---

## Basic Syntax

```bash
hashcat -m <mode> -a <attack> <hash_file> <wordlist_or_mask> [options]
```

---

## Attack Modes (`-a`)

| Mode | Name | Description |
|------|------|-------------|
| `0` | Dictionary | Test each word in a wordlist |
| `1` | Combination | Combine words from two wordlists |
| `3` | Mask/Brute-force | Generate candidates from a pattern |
| `6` | Hybrid wordlist+mask | Wordlist words + appended mask |
| `7` | Hybrid mask+wordlist | Mask prefix + wordlist words |

---

## Common Hash Modes (`-m`)

| Algorithm | Mode |
|-----------|------|
| MD5 | 0 |
| SHA-1 | 100 |
| SHA-256 | 1400 |
| SHA-512 | 1700 |
| NTLM | 1000 |
| bcrypt | 3200 |
| WPA/WPA2 | 22000 |

Full list: `hashcat --help | grep -i <algorithm>`

---

## Dictionary Attack

```bash
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

## Rule-Based Attack

```bash
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/local/hashcat/rules/best64.rule
```

| Rule File | Description |
|-----------|-------------|
| `best64.rule` | 64 high-value mutations — good first choice |
| `rockyou-30000.rule` | 30,000 rules from RockYou analysis |
| `d3ad0ne.rule` | Large community rule set |
| `dive.rule` | Extensive coverage |
| `OneRuleToRuleThemAll.rule` | Popular community compilation |

Rules apply common mutations: capitalize first letter, append numbers/symbols, leetspeak substitutions. Exploits the predictable behavior password policies create.

## Mask Attack

```bash
hashcat -m 0 -a 3 hashes.txt '?u?l?l?l?l?l?d?d?d?d?s'
```

| Placeholder | Character Set |
|-------------|---------------|
| `?l` | Lowercase (a–z) |
| `?u` | Uppercase (A–Z) |
| `?d` | Digits (0–9) |
| `?s` | Special characters |
| `?a` | All printable ASCII |

Use when you know the password pattern — far fewer candidates than full brute force.

---

## Useful Flags

| Flag | Purpose |
|------|---------|
| `-m <mode>` | Hash type |
| `-a <mode>` | Attack mode |
| `-r <file>` | Rule file |
| `-o <file>` | Save cracked results to file |
| `--show` | Display previously cracked hashes from potfile |
| `--identify` | Identify hash type (no cracking) |
| `--session=<name>` | Name a session for resuming |
| `--restore` | Resume a named session |
| `--force` | Force CPU mode (no GPU) |
| `-w <level>` | Workload profile (1=low, 3=high) |

---

## Potfile

Results stored in `/usr/local/hashcat/hashcat.potfile`. Hashcat skips already-cracked hashes automatically — no wasted time on re-runs.

View previous results:

```bash
hashcat -m 0 hashes.txt --show
```

---

## Decision Flow

1. **Dictionary** (`-a 0` + rockyou.txt) — always start here
2. **Dictionary + rules** (`-a 0 -r best64.rule`) — if dictionary fails
3. **Mask** (`-a 3`) — when you know the pattern
4. **Brute force** (`-a 3` with broad mask) — only for short passwords

---

## Related Notes

- [[Password Hashing]] — how passwords are stored, algorithm comparison
- [[John Basics]] — CPU-based alternative
- [[Hydra]] — online brute-forcing (live services, not offline hashes)
- [[Custom Wordlists]] — building targeted wordlists
