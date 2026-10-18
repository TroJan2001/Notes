---
tags: [moc, shells]
---

# Shells

## Reverse Shells
- [[Reverse shells]] — Netcat, Metasploit, one-liners
- [[Socat]] / [[Socat Encrypted Shells]]
- [[Netcat Shell Stabilisation]] — Python, rlwrap, stty

## Web Shells
- [[Web Shells]]

## Windows
- [[Windows Shells]]

## Post-Access
- [[Exploiting User Account]]

---

## Auto-Index (Dataview)

> [!info] All notes in this section, auto-updated by Dataview

```dataview
LIST WITHOUT ID file.link + " — *" + type + "*"
FROM "Shells"
WHERE type != null AND !contains(file.name, "MOC")
SORT file.name ASC
```
