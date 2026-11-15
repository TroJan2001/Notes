---
title: "Crunch"
created: 2026-11-15
type: tool
tags: [tool, wordlists, brute-force]
---

# Crunch

Wordlist generator that creates every possible string matching a given length and character set. Use when you know the password **pattern** or **format**.

---

## Basic Syntax

```bash
crunch <min_len> <max_len> [charset] -o <output_file>
```

## Examples

Generate all 6-character hex strings:

```bash
crunch 6 6 0123456789abcdef -o hex6.txt
```

Generate passwords matching a pattern:

```bash
crunch 11 11 -t Helios20%%! -o passwords.txt
```

Generate 4–8 character passwords from lowercase + digits:

```bash
crunch 4 8 abcdefghijklmnopqrstuvwxyz0123456789 -o short.txt
```

---

## Template Characters

| Char | Meaning |
|------|---------|
| `%` | Digit (0–9) |
| `@` | Lowercase letter (a–z) |
| `,` | Uppercase letter (A–Z) |
| `^` | Symbol (!@#$...) |

## Flags

| Flag | Purpose |
|------|---------|
| `-o <file>` | Output to file |
| `-t <pattern>` | Use a pattern template |
| `-b <size>` | Split output into files of this size (e.g., `1mb`) |
| `-z <method>` | Compress output (gzip, bzip2, lzma) |

---

## Piping to Other Tools

Send generated passwords directly to Hydra without writing to disk:

```bash
crunch 8 8 -t Pass20%% | hydra -l admin -P - target ssh
```

The `-P -` tells Hydra to read passwords from stdin.

---

## Warning

Crunch generates **every** combination — output grows exponentially. A 8-character lowercase+digits list is 2.8 **trillion** entries. Use patterns (`-t`) or short charsets to keep it manageable. Targeted [[Custom Wordlists]] from OSINT are usually more efficient.

---

## Related Notes

- [[Custom Wordlists]] — when to use crunch vs OSINT-based lists
- [[CeWL]] — website-based wordlist generation
- [[Hydra]] — consumes wordlists for login brute-forcing
