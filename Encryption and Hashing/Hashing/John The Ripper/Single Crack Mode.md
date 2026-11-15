---
title: "Single Crack Mode"
created: 2026-03-11
type: technique
tags: [technique, cracking, hashing]
---

# Single Crack Mode

John generates password candidates from the **username** itself — applying mangling rules (capitalize, reverse, append numbers, etc.) to derive likely passwords. Useful when people base their password on their own name.

---

## Usage

```bash
john --single --format=raw-md5 hashes.txt
```

## File Format Requirement

Single crack mode needs the username prepended to each hash, separated by a colon:

```
mike:1efee03cdcb96d90ad48ccc7b8666033
admin:5f4dcc3b5aa765d61d8327deb882cf99
```

Without the username, John has nothing to mangle — it won't generate useful candidates.

---

## What It Tries

For username `mike`, John generates candidates like:
- `mike`, `Mike`, `MIKE`
- `mike1`, `mike123`, `mike!`
- `ekim` (reversed)
- `m1k3` (leetspeak)
- And many more based on its built-in mangling rules

---

## When to Use

- Usernames are known and passwords are likely derived from them
- Quick first pass before a full dictionary attack
- Combined with [[Custom Rules]] for targeted mangling

---

## Related Notes

- [[John Basics]] — dictionary and other attack modes
- [[Custom Rules]] — defining your own mangling patterns
- [[Unshadowing]] — preparing Linux shadow hashes (includes usernames)
