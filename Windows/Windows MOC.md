---
tags: [moc, windows]
---

# Windows

## Core Concepts
- [[Windows Tokens]]
- [[TMP & Bitlocker]]
- [[WHfB]]
- [[Windows Update]]
- [[Windows Firewall]]
- [[EDR]]

## System Processes
- [[System]] → [[smss.exe]] → [[csrss.exe]] → [[wininit.exe]] → [[services.exe]] → [[svchost.exe]]
- [[winlogon.exe]] → [[explorer.exe]]
- [[lsass.exe]]

## System Configuration Tools
- [[cmd]] / [[msconfig]] / [[msinfo32]]
- [[regedit]] / [[resmon]] / [[compmgmt]]
- [[Local User and Group Management]]

## Networking Protocols
- [[NetBIOS]] / [[SMB]] / [[RPC]] / [[RDP]]
- [[NFS]] / [[Transport]]
- [[Name Resolution]]
- [[Windows Print Spooler Service]]
- [[LPC and ALPC in Windows]]
- [[From Shares to Pipes, SMB as a Transport for MSRPC]]
- [[Management & Discovery]]

## Active Directory
- [[Kerberos Authentication Flow]]
- [[Kerberos Authentication Attacks in Active Directory]]
- [[NTLM (NT LAN Manager)]]
- [[LDAP]]

## Attack Techniques
- [[Credential Extraction & Abuse]]
- [[Enumeration & Reconnaissance]]
- [[Remote Execution & Lateral Movement]]
- [[Privilege Escalation]]
- [[Summary|AD Attack Techniques Summary]]

## Foundations
- [[Foundation|Networking Foundation]]
- [[Foundation|AD Authentication Foundation]]

## Reference
- [[OSC Cheatsheet and Map]]
- [[MindMap]]

---

## Auto-Index (Dataview)

> [!info] All notes in this section, auto-updated by Dataview

```dataview
TABLE type AS Type, tags AS Tags
FROM "Windows"
WHERE type != null AND !contains(file.name, "MOC")
SORT file.name ASC
```
