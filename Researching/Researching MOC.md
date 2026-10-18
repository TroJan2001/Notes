---
tags: [moc, recon, osint]
---

# Researching & OSINT

## Vulnerability Research
- [[Vulnerability Searching]]
- [[ExpliotDB]]
- [[Auditing]]

## File Discovery & Hidden Files
- [[Gobuster]] / [[dirb]] / [[ffuf]]
- [[Nikto]]
- [[Steganography]]
- [[Foremost]]
- [[WPScan]]

## OSINT
- [[Google Hacking, Dorking]]
- [[S3 Buckets]]
- [[Wappalyzer]]
- [[Wayback Machine]]

## Document Metadata
- [[ExifTool]]
- [[pdfinfo]]

## Web Basics
- [[robots.txt]]
- [[Sitemap.xml]]
- [[curl]]

---

## Auto-Index (Dataview)

> [!info] All notes in this section, auto-updated by Dataview

```dataview
LIST WITHOUT ID file.link + " — *" + type + "*"
FROM "Researching" OR "Document Metadata"
WHERE type != null AND !contains(file.name, "MOC")
SORT file.name ASC
```
