---
title: "Risk Management"
created: 2026-11-09
type: concept
tags: [concept, security, risk, fundamentals]
---

## Core Definitions

- **Vulnerability** — a weakness in a system (doesn't cause harm alone)
- **Threat** — anything that can exploit a vulnerability (attackers, malware, human error)
- **Risk** — the potential damage if a threat exploits a vulnerability

**Formula:** `Vulnerability × Threat = Risk`

A vulnerability with no threat = no risk. A threat with no vulnerability = no impact.

## Context Changes Risk

Same vulnerability, different risk depending on context:

| Scenario | Vulnerability | Risk Level |
|----------|--------------|------------|
| Internal app, no sensitive data | Verbose error messages | Low |
| Public app with customer PII | Broken access control (IDOR) | Critical |
| Isolated test server | Outdated software | Low |
| Internet-facing payment system | SQL injection | Critical |

## Risk Management Cycle

1. **Identification** — find assets, vulnerabilities, and potential threats
2. **Analysis** — evaluate impact and likelihood → determines severity and remediation priority
3. **Mitigation** — apply patches, strengthen access controls, fix configs, add monitoring
4. **Monitoring** — continuously check that controls remain effective and detect new threats

This cycle repeats — it's never "done."

## Risk Responses

| Response | When | Example |
|----------|------|---------|
| **Mitigate** | Fix is practical and cost-effective | Patch a critical vulnerability |
| **Accept** | Impact is minimal, fix cost outweighs benefit | Internal app leaks server version in headers |
| **Transfer** | Risk can't be fully removed | Purchase cyber insurance for a data breach |

## Related

- [[Security Principles]]
- [[Security Models]]
- [[Incident Response]]
