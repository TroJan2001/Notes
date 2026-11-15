---
tags: [moc, recon, osint]
---

# Researching & OSINT

## Reconnaissance
- [[Google Hacking, Dorking]]
- [[S3 Buckets]]
- [[Wappalyzer]]
- [[Wayback Machine]]
- [[robots.txt]]
- [[Sitemap.xml]]
- [[curl]]

## Enumeration
- [[Custom Wordlists]] — OSINT-based wordlist building strategy
- [[CeWL]] — website word scraping
- [[Crunch]] — pattern-based password generation
- [[ffuf]] / [[Gobuster]] / [[dirb]]
- [[Nikto]]
- [[WPScan]]

## Vulnerability Research
- [[Vulnerability Searching]]
- [[Vulnerability Databases]]
- [[Vulnerability Identification]]
- [[Vulnerability Scanning]]
- [[ExpliotDB]]
- [[Auditing]]

## Forensics
- [[Foremost]]
- [[Steganography]]

---

## Auto-Index (Dataview)

> [!info] All notes in this section, auto-updated by Dataview

```dataview
LIST WITHOUT ID file.link + " — *" + type + "*"
FROM "Researching"
WHERE type != null AND !contains(file.name, "MOC")
SORT file.name ASC
```
