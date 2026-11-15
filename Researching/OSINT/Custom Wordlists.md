---
title: "Custom Wordlists"
created: 2026-11-15
type: technique
tags: [technique, recon, wordlists, osint, brute-force]
---

# Custom Wordlists

Generic wordlists like `rockyou.txt` cast a wide net. **Custom wordlists** built from OSINT about the target are smaller, faster, and more likely to hit because they contain words the target actually uses.

---

## Three Categories of Custom Words

| Category | Examples | Source |
|----------|----------|--------|
| **Company-specific** | Product names, project codenames, employee names, slogans | Website, social media, job ads, LinkedIn |
| **Technology-specific** | Framework routes, plugin names, CMS paths | Wappalyzer, BuiltWith, HTTP headers, SecLists |
| **Generic** | `admin`, `login`, `api`, `dev`, `settings`, `backup` | SecLists, common sense |

---

## OSINT Gathering Techniques

### CeWL — Website Word Scraper

Spiders a website and extracts unique words. Also harvests emails with `-e`.

```bash
cewl -d 2 -m 3 --lowercase --with-numbers -e --email_file emails.txt -w words.txt http://target.com
```

| Flag | Purpose |
|------|---------|
| `-d 2` | Spider depth (2 levels) |
| `-m 3` | Minimum word length |
| `--lowercase` | Normalize case |
| `--with-numbers` | Include words containing digits |
| `-e` | Extract emails |
| `--email_file` | Save emails to separate file |

### Document Harvesting

Download hosted documents and extract strings:

```bash
wget -r -A pdf http://target.com/docs/
for f in $(find target.com/docs -name '*.pdf'); do strings -n 5 "$f" >> raw_words.txt; done
```

Extract emails from documents:

```bash
grep -RhiaoP '[A-Za-z0-9._%+-]+@company\.com' target.com/docs > emails_docs.txt
sort -u emails_docs.txt > emails_unique.txt
```

### Name → Username Conversion

Turn full names into common username formats with `awk`:

```bash
# "Alex Johnson" → alex.johnson
awk '{print tolower($1)"."tolower($2)}' names.txt > users_first.last.txt

# "Alex Johnson" → ajohnson
awk '{print tolower(substr($1,1,1))tolower($2)}' names.txt > users_flast.txt

# "Alex Johnson" → alexj
awk '{print tolower($1)tolower(substr($2,1,1))}' names.txt > users_firstl.txt
```

### Other OSINT Sources

- **LinkedIn / job ads** — reveal tech stack and employee names
- **WHOIS** — domain registration, admin contacts, nameservers
- **Certificate transparency (crt.sh)** — historical subdomains
- **Social media** — hashtags, acronyms, internal project names

---

## Cleaning the Wordlist

Raw lists are messy. Clean them before use:

```bash
# Merge sources, deduplicate
cat words1.txt words2.txt | sort -u > words_raw.txt

# Normalize: lowercase, strip Windows line endings, filter junk
cat words_raw.txt \
  | tr '[:upper:]' '[:lower:]' \
  | tr -d '\r' \
  | grep -P '^[a-z0-9][a-z0-9._-]{4,}$' \
  | sort -u > words_clean.txt
```

The `grep` pattern keeps strings that:
- Start with a letter or digit
- Contain only `a-z 0-9 . _ -`
- Are at least 5 characters long

This removes PDF garbage, HTML tags, and short noise.

---

## Pattern-Based Generation with Crunch

When you know the password format, crunch generates every possibility:

```bash
crunch 11 11 -t Helios20%%! -o passwords.txt
```

| Template Char | Meaning |
|---------------|---------|
| `%` | Digit (0–9) |
| `@` | Lowercase letter |
| `,` | Uppercase letter |
| `^` | Symbol |

`Helios20%%!` generates 100 passwords: `Helios2000!` through `Helios2099!`.

---

## Pre-Made Wordlist Locations

| List | Path | Use |
|------|------|-----|
| **rockyou.txt** | `/usr/share/wordlists/rockyou.txt` | General password cracking (14M entries) |
| **SecLists** | `/usr/share/seclists/` | Passwords, directories, subdomains, usernames, payloads |

---

## Related Notes

- [[ffuf]] — directory and subdomain fuzzing
- [[Gobuster]] — directory brute-forcing
- [[Hydra]] — login brute-forcing
- [[John Basics]] — offline password cracking
