---
title: "Cyber Kill Chain"
created: 2026-11-09
type: concept
tags: [concept, security, framework, fundamentals]
---

## What Is It

A 7-stage framework by Lockheed Martin (2011) that maps how cyber attacks unfold. Understanding each stage helps defenders detect and break the chain before the attacker reaches their goal.

## The 7 Stages

| Stage | What Happens | Example |
|-------|-------------|---------|
| **1. Reconnaissance** | Gather info about the target | Google Dorking, WHOIS, social media, port scanning |
| **2. Weaponisation** | Create/modify the payload | Compile malware, craft a malicious Office macro |
| **3. Delivery** | Transmit payload to the target | Spear phishing email, malicious USB, malvertising, smishing |
| **4. Exploitation** | Trigger a vulnerability | Default credentials, SQL injection, zero-day exploit |
| **5. Installation** | Establish persistence | Rootkit, web shell, scheduled task, cron job, LOLBins |
| **6. Command & Control (C2)** | Covert communication channel | DNS tunneling, DGA, HTTPS C2, social media C2 |
| **7. Actions on Objectives** | Execute the attacker's goal | Data exfiltration, ransomware, lateral movement, data corruption |

## Key Concepts

**DNS Tunneling** — encoding C2 data inside DNS queries to bypass firewalls. Hard to detect because DNS traffic is almost always allowed.

**DGA (Domain Generation Algorithm)** — malware generates thousands of random domain names daily, attacker registers a few. If one is blocked, malware moves to the next. Defends against domain takedowns.

**LOLBins (Living-off-the-Land Binaries)** — using legitimate system tools (PowerShell, bash, curl) for malicious purposes. Bypasses application allowlisting since the tools are already approved.

## Defenses Per Stage

| Stage | Defense |
|-------|---------|
| Reconnaissance | Minimize public info, WHOIS privacy, monitor for scanning |
| Weaponisation | Disable macros, user training, remove unnecessary software |
| Delivery | Email/web filtering, WAF, user awareness training |
| Exploitation | Patch management, MFA, IPS, WAF |
| Installation | EDR, application allowlisting, file integrity monitoring |
| C2 | DNS monitoring, network monitoring, encryption inspection, honeypots |
| Actions on Objectives | DLP, backups, network segmentation, least privilege, EDR |

## Related

- [[Penetration Testing Methodology]]
- [[Incident Response]]
- [[Security Principles]]
