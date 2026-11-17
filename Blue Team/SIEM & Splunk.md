---
title: "SIEM & Splunk"
created: 2026-11-17
type: tool
tags: [blueteam, siem, splunk, tool]
---

A SIEM is the centralized platform where SOC analysts search, correlate, and investigate security events.

## What a SIEM Does

| Function | What it does |
|----------|-------------|
| **Aggregation** | Collects logs from endpoints, servers, firewalls, IDS, apps, cloud |
| **Normalization** | Converts diverse log formats into a common schema |
| **Indexing** | Stores events for fast search across millions/billions of records |
| **Correlation** | Rules that detect patterns across multiple sources and time windows |
| **Alerting** | Notifies analysts when a correlation rule fires |

A SIEM without tuned rules, trained analysts, and response procedures is just an expensive log archive.

## Splunk Data Model

| Field | What it is | Example |
|-------|-----------|---------|
| **index** | Logical container for data (like a database) | `index=botsv1` |
| **source** | File path or input that generated the event | `WinEventLog://Security` |
| **sourcetype** | Classification of data format — controls parsing | `WinEventLog:Security`, `suricata` |
| **host** | Hostname/IP of the generating device | `web-server-01` |
| **_time** | Timestamp | — |
| **_raw** | Original event text before parsing | — |

## The Time Picker Trap

Default time range = **Last 24 hours**. If the data is from a different period, you get zero results. Always set the correct time window first.

## Core SPL (Search Processing Language)

SPL works as a **pipeline** — start with a search, pipe (`|`) results through commands:

```spl
# What data types exist?
index=botsv1 | stats count by sourcetype

# View raw events (first 10)
index=botsv1 sourcetype=WinEventLog:Security | head 10

# Event volume over time (hourly)
index=botsv1 sourcetype=WinEventLog:Security | timechart span=1h count

# Top attacker by IPS alerts (excluding internal)
index=botsv1 sourcetype=suricata NOT src_ip=192.168.* NOT src_ip=10.*
| stats count by src_ip | sort -count | head 1

# Web directory brute-force detection
index=botsv1 sourcetype=iis sc_status=404
| stats count by c_ip | where count > 100 | sort -count

# Top POST target from specific IP
index=botsv1 sourcetype=iis c_ip=<IP> cs_method=POST
| stats count by cs_uri_stem | sort -count | head 1
```

## Detection Pattern

All detection queries follow the same logic: **aggregate by source → count → look for outliers**. This is threshold-based detection. The Event ID and sourcetype change, but the analytical approach transfers everywhere.

## Normal vs Suspicious

| Pattern | Normal | Suspicious |
|---------|--------|-----------|
| Security event volume | Steady baseline, slight increase during business hours | Sharp spikes in narrow window, especially off-hours |
| Failed logons | Scattered, single-digit/hour | Hundreds from one IP targeting one account in minutes |
| HTTP 404s | Occasional, spread over hours | Thousands from one IP with sequential URI patterns |
| New service installs | Rare, during maintenance windows | Multiple outside change windows, randomized names |

## Related Notes

- [[SOC Operations]] — the people who use the SIEM
- [[Windows Event IDs & Attack Patterns]] — what to search for
- [[Threat Intelligence Frameworks]] — mapping findings to ATT&CK
