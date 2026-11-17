---
title: "DevSecOps Fundamentals"
created: 2026-11-17
type: concept
tags: [devsecops, security, concept]
---

DevSecOps = integrating security as a shared responsibility throughout the entire DevOps lifecycle.

## Shifting Left

**Old way:** Security testing at the end of development. Find flaws → reject → delays, rollbacks, economic losses.

**Shift Left:** Introduce security from the **earliest stages**. Code analysis tools and automated tests run during development. Flaws caught early = cheaper to fix, no bottlenecks.

### Why Shift Left?

- Cloud automation sped up provisioning (weeks → minutes) but increased velocity = more security flaws
- Post-development security reviews become bottlenecks in fast-paced environments
- Next version ships before current flaws are remediated
- Security risks being left behind if not built in from the start

## DevSecOps Value

- Reduces vulnerabilities and risk
- Maximizes test coverage
- Automates security frameworks
- Prevents brand reputation damage and economic losses
- Easier auditing and monitoring

## Three Challenges

| Challenge | Problem | Solution |
|-----------|---------|----------|
| **Security Silos** | Security as a separate entity, only specialists handle it | Share responsibilities across all teams, security as supportive function |
| **Lack of Visibility & Prioritisation** | Security playing police, blame games, devs lack confidence | Dashboards, shared tools, trust-building, processes that instill security |
| **Stringent Processes** | Overcomplicated verification for everything, even low-risk tasks | Flexible processes, Sandbox environments for safe experimentation |

## DevSecOps Culture — Three Pillars

### 1. Promote Autonomy of Teams
- Automate security into the pipeline until it's just another test type
- Create playbooks/runbooks for spotting and fixing flaws
- Security as a **supporting function** — build trust, create knowledge overlap
- Engineers make secure decisions independently

### 2. Visibility and Transparency
- **Visibility:** Dashboards showing security state by service criticality — helps teams prioritize
- **Transparency:** Give devs access to security tools (flagged code lines, definitions, remediation steps)
- Extend traditionally security-only information to all teams

### 3. Understanding and Empathy
- Risk means different things to different teams
- Understand how devs work, what they prioritize, what they consider risk
- Build processes that find **common ground** instead of adding noise
- Tune scanners to the team's context — builds trust vs crying wolf

## Related Notes

- [[Software Development Models]] — Waterfall → Agile → DevOps evolution
