---
title: "Windows Event IDs & Attack Patterns"
created: 2026-11-17
type: reference
tags: [blueteam, windows, detection, reference]
---

The specific Event IDs and log patterns that separate normal operations from active compromise.

## Authentication Events (WinEventLog:Security)

| Event ID | What it logs | Why it matters |
|----------|-------------|---------------|
| **4624** | Successful logon | Confirms access. Logon Type: 2=interactive, 3=network/SMB, 10=RDP |
| **4625** | Failed logon | Volume + clustering = brute-force. Hundreds from one IP is not normal |
| **4672** | Special privileges assigned | Fires on admin logon. Suspicious for service accounts at odd hours |

## Account Management (WinEventLog:Security)

| Event ID | What it logs | Why it matters |
|----------|-------------|---------------|
| **4720** | Account created | Persistence via new accounts outside provisioning workflows |
| **4732** | Member added to local security group | Adding to Administrators = classic privesc |

## Process & Service Events

| Event ID | Sourcetype | What it logs | Why it matters |
|----------|-----------|-------------|---------------|
| **4688** | WinEventLog:Security | New process created | Tracks execution. Most useful with command-line auditing enabled |
| **7045** | WinEventLog:System | New service installed | PsExec, malware droppers, ransomware install services |

## Defense Evasion

| Event ID | What it logs | Why it matters |
|----------|-------------|---------------|
| **1102** | Security audit log cleared | High-confidence post-compromise indicator. Near-zero in healthy environments. The event itself survives the clearing |

## Baseline vs Suspicious

| Event ID | Normal | Suspicious |
|----------|--------|-----------|
| **4625** | Single-digit/day, scattered users/IPs, mistyped passwords | Hundreds from one IP in minutes, targeting one account, followed by 4624 |
| **4672** | Known admin accounts, expected machines, business hours | Non-admin accounts, unusual hours, unexpected machines |
| **7045** | Sporadic, correlates with maintenance windows | Outside maintenance, randomized names, executables in temp dirs |
| **1102** | Extremely rare, OS reinstalls or documented maintenance only | Any occurrence during investigation or outside maintenance |
| **HTTP 404** | Occasional, scattered URIs and IPs | Thousands from one IP, sequential URI patterns, scanner User-Agents |

## Attack Detection SPL Queries

```spl
# Brute-force via IPS
index=botsv1 sourcetype=fgt_utm subtype=ips
| stats count by srcip | sort -count | head 1

# Web directory enumeration (404 flood)
index=botsv1 sourcetype=iis sc_status=404
| stats count by c_ip | where count > 100 | sort -count

# Service installations
index=botsv1 sourcetype=WinEventLog:System EventCode=7045
| table _time, Service_Name, Service_File_Name

# Log clearing
index=botsv1 sourcetype=WinEventLog:Security EventCode=1102

# Unusual process creation (parent-child analysis)
index=botsv1 sourcetype=WinEventLog:Security EventCode=4688
| table _time, New_Process_Name, Creator_Process_Name | head 20
```

## Related Notes

- [[SIEM & Splunk]] — the platform where these queries run
- [[SOC Operations]] — the analysts interpreting these patterns
- [[Threat Intelligence Frameworks]] — mapping patterns to ATT&CK techniques
