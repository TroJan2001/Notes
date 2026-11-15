---
title: "Custom Rules"
created: 2026-03-11
type: technique
tags: [technique, cracking, hashing]
---

# Custom Rules

Define your own mangling patterns for John the Ripper. Useful when you know the target's password policy (e.g., "must contain a capital, a number, and a symbol") — rules generate exactly those mutations.

---

## Where to Define

Rules go in `john.conf`:
- Package install: `/etc/john/john.conf`
- Built from source: `/opt/john/john.conf`

## Rule Syntax

```ini
[List.Rules:RuleName]
cAz"[0-9][!@#$%]"
```

### Modifiers

| Modifier | Action |
|----------|--------|
| `c` | Capitalize first letter |
| `Az` | Append characters to the end |
| `A0` | Prepend characters to the start |
| `l` | Lowercase entire word |
| `u` | Uppercase entire word |
| `r` | Reverse the word |
| `d` | Duplicate the word |

### Character Sets

| Pattern | Characters |
|---------|-----------|
| `[0-9]` | Digits 0–9 |
| `[A-Z]` | Uppercase letters |
| `[a-z]` | Lowercase letters |
| `[A-z]` | All letters (upper + lower) |
| `[!@#$%]` | Specific symbols |
| `[0]` | Only the character 0 |

---

## Example

Password policy: must start with a capital, end with a number and a symbol.

Word `polopassword` → target `Polopassword1!`

```ini
[List.Rules:PoloPassword]
cAz"[0-9][!£$%@]"
```

Breakdown:
- `c` — capitalize first letter → `Polopassword`
- `Az` — append to end
- `[0-9]` — a digit → `Polopassword1`
- `[!£$%@]` — a symbol → `Polopassword1!`

## Usage

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --rule=PoloPassword hashes.txt
```

---

## Built-In Rule Sets

| Flag | Description |
|------|-------------|
| `--rules=wordlist` | Default mutations (capitalize, append numbers, etc.) |
| `--rules=single` | Username-based mutations (used with [[Single Crack Mode]]) |
| `--rules=extra` | Extended rules |
| `--rules=jumbo` | Large comprehensive set |

---

## Related Notes

- [[John Basics]] — basic cracking commands
- [[Single Crack Mode]] — username-based mangling
- [[Hashcat]] — Hashcat's rule files (`best64.rule`, `dive.rule`, etc.)
