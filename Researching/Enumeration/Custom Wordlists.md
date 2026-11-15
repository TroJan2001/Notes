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

### Website Crawling

Use [[CeWL]] to spider the target website and extract unique words + email addresses from page content.

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
awk '{print tolower($1)"."tolower($2)}' names.txt > users_first.last.txt
awk '{print tolower(substr($1,1,1))tolower($2)}' names.txt > users_flast.txt
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
cat words1.txt words2.txt | sort -u > words_raw.txt

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

## Pattern-Based Generation

Use [[Crunch]] when you know the password format — it generates every possible combination matching a template.

---

## Pre-Made Wordlist Locations

| List | Path | Use |
|------|------|-----|
| **rockyou.txt** | `/usr/share/wordlists/rockyou.txt` | General password cracking (14M entries) |
| **SecLists** | `/usr/share/seclists/` | Passwords, directories, subdomains, usernames, payloads |

---

## Related Notes

- [[CeWL]] — website word scraping
- [[Crunch]] — pattern-based password generation
- [[ffuf]] — directory and subdomain fuzzing
- [[Gobuster]] — directory brute-forcing
- [[Hydra]] — login brute-forcing
- [[John Basics]] — offline password cracking
