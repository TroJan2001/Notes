---
title: "Incident Response"
created: 2026-11-09
type: concept
tags: [concept, security, incident-response, forensics, dfir]
---

## Overview

Incident Response (IR) is the organized approach to handling security breaches and cyberattacks. The goal: detect, contain, and recover as fast as possible while preserving evidence.

## Incident Response Phases

1. **Preparation** — build the team, write playbooks, set up tools before anything happens
2. **Detection & Analysis** — identify that an incident occurred and assess severity
3. **Containment** — stop the bleeding (isolate compromised systems, block attacker access)
4. **Eradication** — remove the threat (malware, backdoors, compromised accounts)
5. **Recovery** — restore systems to normal operation
6. **Lessons Learned** — what happened, what went wrong, how to prevent it next time

## Key Concepts

### Golden Hour

The critical first hour after an incident is detected. What happens here sets the tone:

1. **Notify** members via call tree and agree on a communication channel
2. **Brief** — responders share what they know so far
3. **Triage** — assess severity and decide on actions
4. **Communicate** — issue holding statements to internal and external parties

### Order of Volatility

When collecting evidence from a live system, capture the most fragile data first — it disappears when power is lost:

1. **CPU registers, cache** — gone instantly
2. **RAM** (memory contents, running processes, encryption keys)
3. **Network state** (ARP cache, routing table, active connections)
4. **Running processes and open files**
5. **Disk contents** — survives reboot, collect after volatile data
6. **Backups, remote logs, archives** — persistent, collect last

**Rule:** volatile first, then disk image, then everything else.

### Incident Playbooks

Predefined step-by-step procedures for specific incident types. Written **before** an incident so the team doesn't improvise under pressure.

Examples:
- Ransomware playbook
- Phishing playbook
- Data breach playbook
- DDoS playbook
- Insider threat playbook

### DRP vs BCP

| | DRP (Disaster Recovery Plan) | BCP (Business Continuity Plan) |
|---|---|---|
| **Focus** | Technical recovery | Entire business operation |
| **Scope** | Restore systems, servers, data | People, processes, communication, supply chain + DRP |
| **Question** | "How do we get systems back online?" | "How does the business keep running?" |

DRP is a chapter inside the BCP.

## Related

- [[Logs]]
- [[Auditing]]
- [[Security Models]]
