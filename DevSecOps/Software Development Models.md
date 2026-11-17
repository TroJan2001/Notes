---
title: "Software Development Models"
created: 2026-11-17
type: concept
tags: [devsecops, sdlc, concept]
---

The evolution from rigid hierarchies to collaborative, automated development.

## Waterfall (1970s)

- Linear, hierarchical project management
- Rigid roles: sysadmins, devs, QA — each isolated
- Problems: blame games, backlogged bugs, communication gaps, friction
- Not scalable when release frequency and customer expectations grew

## Agile (early 2000s)

- Agile Manifesto — four values:
  - Individuals and interactions over processes and tools
  - Working software over comprehensive documentation
  - Customer collaboration over contract negotiation
  - Responding to change over following a plan
- Self-organizing teams, client focus, flexibility
- Still missing: teams remained **siloed** (dev, ops, QA working in isolation)

## DevOps (2008)

Born from a conversation between Andrew Clay and Patrick Debois about Agile's drawbacks. Popularized at "DevOpsDays" (Belgium, 2009).

- Drives **cultural change** through integration and automation
- Cross-integration: dev + ops + QA all share visibility and tools
- Changes are small, reversible, visible to all teams
- Philosophy: **building trust** between developers and other teams

### Key DevOps Tools & Processes

| Concept | What it does |
|---------|-------------|
| **CI/CD** | Frequent code merging + automated testing on every push. Detects bugs early, reliable rollbacks |
| **Infrastructure as Code (IaC)** | Provision infrastructure through code (Terraform, Vagrant). Reusable, consistent |
| **Configuration Management** | Manage infrastructure state, apply changes efficiently |
| **Orchestration** | Automate workflows — resource planning, health checks, fast responses |
| **Monitoring** | Collect performance/stability data. Faster recovery, root-cause analysis |
| **Microservices** | Break app into small independent services. Flexible scaling, reduced complexity |

### Two Deployment Approaches

- **Declarative** — specify end state, software builds it automatically (no human interaction)
- **Imperative/procedural** — automate steps, apply changes through a manual "gate" (e.g., deploy button)

## Related Notes

- [[DevSecOps Fundamentals]] — adding security to DevOps
