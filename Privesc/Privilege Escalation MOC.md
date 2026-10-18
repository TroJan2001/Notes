---
tags: [moc, privesc]
---

# Privilege Escalation

## Linux Privilege Escalation
- [[Privilege Escalation]] — Overview & Concepts

### Enumeration
- [[Basic Enumeration]]
- [[Find Command]]
- [[Capabilities]]
- [[History, Config and SSH Files]]
- [[Legacy Packages]]
- [[LinEnum]]

### SUID/SGID
- [[SUID&GUID Files]]
- [[Environment Variables Exploitation]]
- [[Known Exploits]]
- [[Shared Object Injection Exploitation]]
- [[Systemctl]]

### Sudo Abuse
- [[Escaping Vi Editor]]
- [[Exploiting Sudo Environment Variables]]

### Scheduled Tasks
- [[Exploiting Crontab]]

### Path & Variables
- [[Exploiting PATH Variable]]

### File Permissions
- [[Weak File Permissions]]

### Network
- [[NFS]]
- [[MySQL UDF Exploit]]

### CVEs
- [[Dirty COW (CVE-2016-5195)]]
- [[Exim CVE-2016-1531]]
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
TABLE type AS Type, tags AS Tags
FROM "Privesc"
WHERE type != null AND !contains(file.name, "MOC")
SORT file.name ASC
```
