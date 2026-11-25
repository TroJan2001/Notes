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
- [[Binary Exploitation MOC]] — Heap overflows, memory corruption, RCE
- [[Social Engineering MOC]] — Phishing, psychology, credential harvesting
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

### Privilege Escalation Cheat Sheet
- [[SUID & SGID Files]] / [[Exploiting Crontab]] / [[Exploiting PATH Variable]]
- [[LinEnum]] / [[Basic Enumeration]]

## Other Topics
- [[Wireless Security MOC]] — Wi-Fi, Bluetooth, RFID/NFC, IoT protocols
- [[Mobile Security MOC]] — App architecture, static/dynamic analysis, OWASP Mobile Top 10
- [[Cloud Security MOC]] — Service models, IAM, storage, networking, IMDS & SSRF
- [[AI Security MOC]] — AI security umbrella: ML security (adversarial ML, poisoning, drift, CSCE 704) + LLM security (prompt injection, jailbreaking)
- [[Pentesting Methodology MOC]] — PTES, Kill Chain, threat modeling (STRIDE/DREAD/PASTA/ATT&CK), frameworks
- [[Security Fundamentals MOC]] — CIA triad, security models, risk management, auditing, IR
- [[Blue Team MOC]] — SOC operations, SIEM/Splunk, Event IDs, IR lifecycle, MITRE ATT&CK, Pyramid of Pain
- [[Python Scripting MOC]] — Pentest scripts, network tools, exploitation patterns, library reference
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
