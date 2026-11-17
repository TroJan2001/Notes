---
title: "Threat Intelligence Frameworks"
created: 2026-11-17
type: concept
tags: [blueteam, mitre, attack, threat-intel, concept]
---

Common language for describing adversary behavior and prioritizing detection investments.

## MITRE ATT&CK Framework

A dictionary for adversary behavior. See [[Threat Modeling]] for the full 14-tactic Enterprise matrix, Kill Chain mapping, and CTID threat modeling workflow.

### Detection-Focused Mappings

| Attack Pattern | Technique | ID |
|---------------|-----------|-----|
| Brute-force login attempts | Brute-Force: Password Guessing | T1110.001 |
| Port/service scanning | Network Service Discovery | T1046 |
| Web directory enumeration | Active Scanning: Wordlist Scanning | T1595.003 |
| Lateral movement via SMB | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Audit log clearing | Indicator Removal: Clear Windows Event Logs | T1070.001 |
| cmd.exe/PowerShell execution | Command and Scripting Interpreter | T1059 |
| Supply chain compromise | Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 |
| DNS-based C2 | Application Layer Protocol: DNS | T1071.004 |
| Web defacement | Defacement: External Defacement | T1491.002 |

### ATT&CK Navigator
Free web tool at `mitre-attack.github.io/attack-navigator` — interactive grid to visualize detection coverage, threat group TTPs, or incident mapping.

## Pyramid of Pain

Ranks indicators by **operational difficulty** they cause the attacker when blocked (David Bianco, 2013):

| Layer | Indicator Type | Pain Level | Attacker Recovery Time |
|-------|---------------|------------|----------------------|
| 6 (top) | **TTPs** | Tough | Must redesign entire operation |
| 5 | **Tools** | Challenging | Must find/build new tooling |
| 4 | **Network/Host Artifacts** | Annoying | Must change operational patterns |
| 3 | **Domain Names** | Simple | Register a new domain |
| 2 | **IP Addresses** | Easy | Spin up new cloud server in minutes |
| 1 (bottom) | **Hash Values** | Trivial | Recompile with one-byte change |

**Key principle:** prioritize detection by adversary cost. Blocking a hash is free and nearly useless. Detecting a TTP forces the attacker to fundamentally retool.

### SolarWinds Example
- Blocking C2 domain `avsvmcloud.com` = Layer 3 (Simple) — APT29 registers a new one
- Detecting behavior of software updates making encoded DNS queries to unknown domains = Layer 6 (TTPs) — forces complete C2 redesign

## Related Notes

- [[Windows Event IDs & Attack Patterns]] — the patterns that map to ATT&CK
- [[Incident Response Lifecycle]] — the process that uses threat intel
- [[SOC Operations]] — the analysts who consume threat intelligence
