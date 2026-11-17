---
title: "Incident Response Lifecycle"
created: 2026-11-17
type: concept
tags: [blueteam, ir, nist, sans, concept]
---

Structured frameworks for managing incidents from detection through recovery.

## NIST SP 800-61 Rev 2 — Four Phases (Cyclical)

| Phase | What happens |
|-------|-------------|
| **1. Preparation** | Build capability before incidents — policies, tools, training, escalation procedures |
| **2. Detection & Analysis** | Identify incident occurred, determine scope and severity (SIEM, log analysis, triage) |
| **3. Containment, Eradication & Recovery** | Isolate systems → remove attacker's foothold → restore operations with monitoring |
| **4. Post-Incident Activity** | Lessons learned, document timeline, feed improvements back into Preparation |

The cycle loops: Post-Incident Activity → Preparation improvements → better Detection next time.

### NIST Definitions

- **Event** — any observable occurrence in a system/network
- **Adverse event** — event with a negative consequence
- **Computer security incident** — violation or imminent threat of violation of security policies

Not every event is adverse, not every adverse event is an incident.

## SANS PICERL Model

Same process, more granularity — splits NIST phase 3 into three:

| SANS Phase | Maps to NIST |
|-----------|-------------|
| **P**reparation | Preparation |
| **I**dentification | Detection & Analysis |
| **C**ontainment | Containment, Eradication & Recovery |
| **E**radication | Containment, Eradication & Recovery |
| **R**ecovery | Containment, Eradication & Recovery |
| **L**essons Learned | Post-Incident Activity |

NIST for policy documentation, SANS for operational playbooks.

## Case Studies

### Target 2013 — Analysis/Escalation Failure
- FireEye detected BlackPOS malware (Detection worked)
- Bangalore SOC didn't escalate to Minneapolis (Analysis failed)
- 18 days between alert and containment
- 40M payment cards, $162M costs, CEO/CIO resigned
- Root cause: no enforced escalation path + alert fatigue

### SolarWinds SUNBURST 2020 — Detection Failure
- APT29 backdoored Orion build pipeline → distributed to ~18,000 orgs
- **9 months** undetected (Detection & Analysis failure)
- Exposed log retention problem: 90-day retention can't reconstruct 9-month intrusion
- Post-incident drove: supply chain verification, longer retention, behavioral detection

## Pentest Relevance

Map engagement findings to IR phases:
- Did their SIEM detect your brute-force? (Detection)
- Did anyone escalate it? (Analysis)
- Did they isolate the compromised host? (Containment)
- Could they reconstruct your full kill chain from logs? (Log retention / Post-Incident)

## Related Notes

- [[SOC Operations]] — the people executing the IR lifecycle
- [[SIEM & Splunk]] — the tool used in Detection & Analysis
- [[Threat Intelligence Frameworks]] — shared language for adversary behavior
