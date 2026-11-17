---
title: "Cloud Service Models"
created: 2026-11-17
type: concept
tags: [cloud, models, concept]
---

Cloud = rented infrastructure. A company pays a provider (AWS, Azure, GCP) for compute, storage, and networking delivered through an API instead of buying and racking their own servers.

## Service Models

How much you rent vs. manage yourself — from most responsibility to least:

### IaaS (Infrastructure as a Service)

Rent raw compute: VM, virtual disk, virtual network. You install and run everything on top. Like renting an **empty apartment** — walls and plumbing exist, you furnish it.

- Examples: AWS EC2, Azure VMs, Google Compute Engine
- You manage: OS, patches, firewall rules, runtime, app code, data, access

### PaaS (Platform as a Service)

Rent a managed runtime. Provider handles OS, patching, scaling. You upload code/data. Like a **semi-furnished apartment**.

- Examples: AWS RDS / Elastic Beanstalk, Azure SQL / App Service, Google Cloud SQL / App Engine
- You manage: App code, data, access policies

### SaaS (Software as a Service)

Rent a finished application. Provider runs everything. You log in and use it. Like a **hotel room**.

- Examples: AWS WorkMail, Microsoft 365, Google Workspace
- You manage: Data, identities, access policies (who sees what)

## Deployment Models

| Model | Description |
|-------|-------------|
| **Public cloud** | Shared infra, workloads run alongside other customers (separated by hypervisor/network) |
| **Private cloud** | Dedicated to one org — on-prem or hosted privately |
| **Hybrid cloud** | Mix of public + on-prem, connected by VPN or private link |
| **Community cloud** | Shared between orgs with common requirements (government, healthcare) |

## The Shared Responsibility Model

Who's responsible for what — this is where misconfigurations cluster:

| Layer | IaaS | PaaS | SaaS |
|-------|------|------|------|
| Physical datacenter | Provider | Provider | Provider |
| Hardware & hypervisor | Provider | Provider | Provider |
| Network config | **Customer** | Shared | Provider |
| Operating system | **Customer** | Provider | Provider |
| Runtime & middleware | **Customer** | Provider | Provider |
| Application code | **Customer** | **Customer** | Provider |
| Data | **Customer** | **Customer** | **Customer** |
| Identities & access | **Customer** | **Customer** | **Customer** |

**Key insight:** Data and identity are ALWAYS the customer's responsibility. Physical infra is always the provider's. As pentesters, we find mistakes in the customer's responsibilities — a VM with default creds, a public bucket, a wildcard IAM policy.

## Related Notes

- [[Cloud IAM]] — policies, roles, the over-permissive wildcard pattern
- [[Cloud Storage Security]] — public buckets, enumeration
- [[Cloud Networking]] — VPCs, security groups, lateral movement
- [[Cloud Compute & Metadata]] — IMDS, SSRF-to-credentials chain
