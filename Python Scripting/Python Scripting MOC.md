---
tags: [moc, python, scripting]
---

# Python Scripting

Python patterns and libraries for penetration testing, CTFs, and security automation.

## Pentest Script Patterns
- [[Python Recon Scripts]] — subdomain/directory enumeration, web scraping, automated downloads, python-nmap
- [[Python Network Scripts]] — ARP scanning/spoofing, port scanning, DNS spoofing, packet sniffing, reverse shells
- [[Python Exploitation Scripts]] — hash cracking, SSH brute-force, Impacket (AD/Windows), pwntools (binary exploitation), pycryptodome

## Reference
- [[Python Pentest Libraries]] — full library table, common patterns, links to [custom implementations](https://github.com/TroJan2001/Security-and-Ethical-Hacking)

---

## Auto-Index (Dataview)

> [!info] All notes in this section, auto-updated by Dataview

```dataview
LIST WITHOUT ID file.link + " — *" + type + "*"
FROM "Python Scripting"
WHERE type != null AND !contains(file.name, "MOC")
SORT file.name ASC
```
