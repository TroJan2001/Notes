---
title: "CeWL"
created: 2026-11-15
type: tool
tags: [tool, recon, wordlists, osint]
---

# CeWL

**Custom Word List generator** — a Ruby tool that spiders a website and extracts unique words from page content. Also harvests email addresses. Useful for building company-specific wordlists from the target's own language.

---

## Basic Usage

```bash
cewl http://target.com -w output.txt
```

## Full Example

```bash
cewl -d 2 -m 3 --lowercase --with-numbers -e --email_file emails.txt -w words.txt http://target.com
```

## Flags

| Flag | Purpose |
|------|---------|
| `-w <file>` | Write words to file |
| `-d <depth>` | Spider depth (default 2) |
| `-m <min>` | Minimum word length |
| `--lowercase` | Convert all words to lowercase |
| `--with-numbers` | Include words containing digits |
| `-e` | Enable email extraction |
| `--email_file <file>` | Save emails to separate file |
| `-c` | Show word count next to each word |
| `-v` | Verbose output |
| `--offsite` | Follow links to other sites |
| `-a` | Include metadata from documents |
| `--meta_file <file>` | Save metadata words to file |

---

## Tips

- Pair with `-d 2` or `-d 3` for deeper crawls — higher depths take longer and may leave the target domain
- Extracted emails can be converted to usernames: `grep -Po '^[^@]+' emails.txt > users.txt`
- Combine CeWL output with document strings for a more complete wordlist (see [[Custom Wordlists]])

---

## Related Notes

- [[Custom Wordlists]] — full OSINT wordlist building strategy
- [[Crunch]] — pattern-based wordlist generation
- [[ffuf]] — uses wordlists for fuzzing
