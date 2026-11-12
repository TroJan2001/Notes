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
- [[NetBIOS]] / [[SMB Protocol|SMB]] / [[RPC]] / [[RDP]]
- [[NFS Protocol|NFS]] / [[Transport]]
- [[Name Resolution]]
- [[Windows Print Spooler Service]]
- [[LPC and ALPC in Windows]]
- [[From Shares to Pipes, SMB as a Transport for MSRPC]]
- [[Management & Discovery]]

### Authentication Protocols
- [[Kerberos Authentication Flow]]
- [[NTLM (NT LAN Manager)]]
- [[LDAP]]

## Active Directory

### Concepts
- [[AD Authentication Foundation]]
- [[Organizational Units and DACLs]]
- [[Managed Service Accounts]]

### Attacks & Techniques
- [[Kerberos Authentication Attacks in Active Directory]]
- [[Credential Extraction & Abuse]]
- [[Enumeration & Reconnaissance]]
- [[Remote Execution & Lateral Movement]]
- [[Windows AD Privilege Escalation|Privilege Escalation]]
- [[BadSuccessor Attack]]
- [[AD Attack Techniques Summary|Summary Table]]

## Foundations
- [[Windows Networking Foundation]]

## Reference
- [[OSC Cheatsheet and Map]]
- [[MindMap]]

---

## Auto-Index (Dataview)

> [!info] All notes in this section, auto-updated by Dataview

```dataview
LIST WITHOUT ID file.link + " — *" + type + "*"
FROM "Windows"
WHERE type != null AND !contains(file.name, "MOC")
SORT file.name ASC
```
