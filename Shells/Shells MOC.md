---
tags: [moc, shells]
---

# Shells

## Core
- [[Shells and Listeners]] — reverse/bind shells, netcat, socat, stabilisation, encryption, one-liners

## Web Shells
- [[Web Shells]] — PHP, ASP, JSP webshells for HTTP-based access

## Post-Access
- [[Post-Shell Actions]] — credential hunting, persistent accounts after landing a shell

---

## Auto-Index (Dataview)

> [!info] All notes in this section, auto-updated by Dataview

```dataview
LIST WITHOUT ID file.link + " — *" + type + "*"
FROM "Shells"
WHERE type != null AND !contains(file.name, "MOC")
SORT file.name ASC
```
