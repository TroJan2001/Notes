---
title: "SOC Operations"
created: 2026-11-17
type: concept
tags: [blueteam, soc, concept]
---

How Security Operations Centers are structured and why alerts sometimes fall through the cracks.

## SOC Tier Structure

| Tier | Role | Responsibilities |
|------|------|-----------------|
| **L1: Triage Analyst** | First line of defense | Monitor alert queue, classify alerts, close false positives, escalate real threats |
| **L2: Incident Handler** | Deep-dive investigator | Receives L1 escalations, scopes incidents, coordinates containment, collects evidence |
| **L3: Threat Hunter** | Proactive hunter | Hypothesis-driven hunting, builds detection rules, advanced forensics, tool development |

Escalation always flows **upward**: L1 triages → L2 investigates → L3 hunts. Each tier filters workload for the tier above.

## L1 Analyst Workflow

This cycle repeats dozens/hundreds of times per shift:

1. **Monitor the queue** — review new, unassigned alerts
2. **Triage** — classify: known false positive? Does source IP/event type/target suggest real threat?
3. **Investigate** — correlate with other data sources, check related logs, gather context
4. **Decide** — close as false positive (with documentation) or escalate to L2 (with findings attached)

## SOC Performance Metrics

| Metric | Measures | Global Average |
|--------|----------|---------------|
| **MTTD** (Mean Time to Detect) | Time between initial compromise and detection | 181 days (IBM 2025) / 14 days median (Mandiant M-Trends 2026) |
| **MTTR** (Mean Time to Respond) | Time from detection to containment | 60 days (IBM 2025) |

Lower is better for both. Every extra day of dwell time = more lateral movement, privesc, exfiltration.

## Alert Fatigue

The degradation in analyst attention caused by constant low-quality alerts:

- SOC false positive rates: **50-80%**
- Only **~37%** of alerts are actually investigated
- The rest are auto-closed, deprioritized, or never opened

**Target breach (2013):** FireEye IDS flagged BlackPOS malware correctly. Technology worked. Bangalore SOC didn't escalate to Minneapolis. 18 days between alert and containment → 40M payment cards stolen, $162M+ costs.

## Pentest Relevance

Understanding SOC operations helps pentesters:
- **Stealth** — know what triggers alerts, operate below detection thresholds
- **Reporting** — map findings to detection gaps the SOC can act on
- **Realistic testing** — understand defender pressures and blind spots

## Related Notes

- [[SIEM & Splunk]] — the tool SOC analysts use to investigate
- [[Windows Event IDs & Attack Patterns]] — what to search for
- [[Incident Response Lifecycle]] — what happens after detection
