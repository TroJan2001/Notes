---
title: "Google Hacking, Dorking"
created: 2026-03-11
updated: 2026-11-09
type: technique
tags: [osint, recon, technique]
---

## What Is It

Using Google's advanced search operators to find sensitive content indexed from a target — exposed admin panels, leaked documents, login pages, and more.

## Operators

| Operator | Description | Example |
|----------|-------------|---------|
| **site:** | Results only from this domain | `site:example.com` |
| **inurl:** | Word must be in the URL | `inurl:admin` |
| **filetype:** | Specific file type | `filetype:pdf` |
| **intitle:** | Word must be in the page title | `intitle:admin` |
| **intext:** | Word must be in the page body | `intext:password` |
| **cache:** | Google's cached version of a page | `cache:example.com` |

## Practical Examples

- Find admin panels: `site:example.com inurl:admin`
- Find log files with passwords: `filetype:log "password" site:example.com`
- Find directory listings: `intitle:"index of" "backup" site:example.com`
- Find exposed config files: `site:example.com filetype:env OR filetype:cfg`
- Find login pages: `site:example.com intitle:login`
- Find PDFs from a target: `site:example.com filetype:pdf`

Combine multiple operators in one query for precise results.

## Related

- [[Wappalyzer]]
- [[Wayback Machine]]
- [[S3 Buckets]]
