---
tags: [home, index]
---

# Cybersecurity Notes

## Maps of Content

- [[Network Exploitation MOC]] — Nmap, services, Metasploit, firewalls
- [[Web Pentesting MOC]] — XSS, SQLi, LFI, command injection, recon tools
- [[Privilege Escalation MOC]] — Linux & Windows privesc techniques
- [[Shells MOC]] — Reverse shells, web shells, stabilisation
- [[Encryption & Hashing MOC]] — Crypto, John the Ripper, hashing
- [[Windows MOC]] — Processes, AD, Kerberos, networking protocols
- [[DevSecOps MOC]] — Docker, Kubernetes, container security
- [[Researching MOC]] — OSINT, vulnerability research, file discovery

## Quick Access

### Top Tools
- [[Nmap NSE & Commands]] / [[Nmap Basic Port Scans]]
- [[Gobuster]] / [[ffuf]] / [[Nikto]]
- [[Hydra]] / [[John Basics]]
- [[Metasploit]] / [[Msfvenom]] / [[Meterpreter]]
- [[Sqlmap]] / [[WPScan]] / [[Burp Suite]]

### Common Attacks
- [[SQL Injection]] / [[Command Injection]] / [[XSS]]
- [[LFI & RFI]] / [[Log Poisoning]]
- [[Reverse shells]] / [[SSH Tunnels]]

### Privesc Cheat Sheet
- [[SUID&GUID Files]] / [[Exploiting Crontab]] / [[Exploiting PATH Variable]]
- [[LinEnum]] / [[Basic Enumeration]]

## Other Topics
- [[Wi-Fi Hacking]] — Wireless network attacks
- [[Inter-Process Communication (IPC)]] / [[Sessions and Full-Duplex Communication]] — OS fundamentals

## Resources
- [[Resources]] — External links, cheatsheets, references

---

## Vault Stats (Dataview)

> [!tip] Install the **Dataview** community plugin to see these queries live

### Recently Modified
```dataview
LIST WITHOUT ID file.link + " — *" + type + "*"
FROM ""
WHERE type != null
SORT file.mtime DESC
LIMIT 10
```

### All Tools
```dataview
LIST
FROM ""
WHERE type = "tool"
SORT file.name ASC
```

### All Techniques
```dataview
LIST
FROM ""
WHERE type = "technique"
SORT file.name ASC
```

### Orphan Notes (no backlinks)
```dataview
LIST
FROM ""
WHERE length(file.inlinks) = 0 AND !contains(file.name, "MOC") AND file.name != "Home" AND file.name != "Readme"
```
