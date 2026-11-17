---
title: "Cloud Networking"
created: 2026-11-17
type: concept
tags: [cloud, networking, concept]
---

Two pentest questions: **what's exposed to the internet?** and **what can we reach once inside?**

## Building Blocks

**Virtual Network (VPC)** — customer's private network inside the provider. Own IP range, isolated from other customers.

**Subnets:**
- **Public** — has a route to the internet via an Internet Gateway (IGW). Resources can be reached from outside.
- **Private** — no internet route. Internal communication only.

## Two Firewall Layers

| | Security Groups | Network ACLs (NACLs) |
|---|----------------|---------------------|
| Level | Per-instance | Per-subnet |
| Stateful? | Yes (response auto-allowed) | No (both directions explicit) |
| Rules | Allow only (implicit deny) | Allow AND deny |
| In practice | Main control | Coarser safety net, often default |

## Exposed Ports — Most Common Misconfiguration

Security group rule allowing `0.0.0.0/0` (entire internet) on a port that should be restricted:

| Service | Port | Risk |
|---------|------|------|
| SSH | 22 | Should only accept specific IPs |
| MySQL | 3306 | Database internet-facing |
| PostgreSQL | 5432 | Database internet-facing |
| MongoDB | 27017 | Historically no-auth defaults + public = mass breaches |
| RDP | 3389 | Added during migration, never removed |
| Admin panels | 8080/9000 | Internal tools reachable without VPN |

Found with ordinary `nmap` scans. The cloud doesn't change the tooling — it changes how easy it is to introduce the mistake.

## Lateral Movement

Once inside a VPC, the internal network is usually **flat** — every instance can reach every other instance on most ports by default. Very different from segmented on-prem networks.

A compromised front-end web server typically reaches:
- Internal databases and caches
- Other application servers
- Internal admin panels
- Instance Metadata Service

Post-foothold: **"what else in this VPC can I reach?"** — answer is almost always "more than expected."

## Provider Mapping

| Concept | AWS | Azure | Google Cloud |
|---------|-----|-------|-------------|
| Virtual network | VPC | VNet | VPC |
| Internet access | Internet Gateway | Public IP / NAT Gateway | External IP / Cloud NAT |
| Instance firewall | Security Group | NSG | Firewall Rule |
| Subnet firewall | NACL | NSG (subnet scope) | Firewall Rule (network tag) |

## Related Notes

- [[Cloud Compute & Metadata]] — what you find after lateral movement
- [[Cloud IAM]] — permissions after pivoting
- [[Cloud Service Models]] — shared responsibility for network config
