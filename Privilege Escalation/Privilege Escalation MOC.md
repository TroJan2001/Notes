---
tags: [moc, privesc]
---

# Privilege Escalation

## Core
- [[Overview]] — horizontal vs vertical escalation concepts
- [[Methodology]] — structured enumeration framework, six misconfiguration categories, chaining findings

## Linux Privilege Escalation

### Enumeration
- [[Basic Enumeration]]
- [[Find Command]]
- [[Capabilities]]
- [[History, Config and SSH Files]]
- [[Legacy Packages]]

### Tools
- [[Automated Enumeration Tools]] — LinPEAS, LinEnum, LES, pspy
- [[Process Snooping]] — event-driven process monitoring with pspy

### SUID / SGID
- [[SUID & SGID Files]]
- [[Environment Variables Exploitation]]
- [[Known Exploits]]
- [[Shared Object Injection Exploitation]]
- [[Systemctl]]

### Sudo Abuse
- [[Sudo Exploitation]]

### Scheduled Tasks
- [[Exploiting Crontab]]

### Path & Variables
- [[Exploiting PATH Variable]]

### File Permissions
- [[Weak File Permissions]]

### Network
- [[NFS Privesc|NFS]]
- [[MySQL UDF Exploit]]

### Kernel Concepts
- [[Page Cache]]
- [[User Namespaces]]

### CVEs
- [[Dirty COW (CVE-2016-5195)]]
- [[Exim CVE-2016-1531]]
- [[Fragnesia Page Cache Corruption|Fragnesia (CVE-2026-46300)]]
- [[Polkit CVE-2021-3560]]
- [[Polkit CVE-2021-4034 (Pwnkit)]]

## Windows Privilege Escalation
- [[Windows Services]]
- [[Abusing vulnerable software]]
- [[Abusing Windows Privileges]]
- [[Passwords Usual Spots]]
- [[Other ways for Privilege Escalation]]

---

## Auto-Index (Dataview)

> [!info] All notes in this section, auto-updated by Dataview

```dataview
LIST WITHOUT ID file.link + " — *" + type + "*"
FROM "Privilege Escalation"
WHERE type != null AND !contains(file.name, "MOC")
SORT file.name ASC
```
