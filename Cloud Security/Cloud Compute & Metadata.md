---
title: "Cloud Compute & Metadata"
created: 2026-11-17
type: technique
tags: [cloud, ssrf, imds, technique]
---

The Instance Metadata Service (IMDS) turns a common web vulnerability (SSRF) into a full cloud compromise. This is the most important cloud-specific attack pattern.

## Instance Metadata Service (IMDS)

Every cloud VM has a small internal HTTP endpoint for self-discovery — reachable only from inside the instance at a link-local address:

| Provider | Endpoint | Protection |
|----------|----------|-----------|
| AWS | `http://169.254.169.254/latest/meta-data/` | IMDSv1: none. IMDSv2: session token via PUT |
| Azure | `http://169.254.169.254/metadata/instance?api-version=...` | `Metadata: true` header required |
| GCP | `http://metadata.google.internal/` | `Metadata-Flavor: Google` header required |

**What it serves:** Instance ID, region, startup scripts, and **temporary credentials for the VM's attached role**.

## IMDSv1 vs IMDSv2

| | IMDSv1 | IMDSv2 |
|---|--------|--------|
| Auth | None — plain GET | PUT first to get session token |
| SSRF vulnerable? | Yes | Blocked (can't do PUT + token flow via SSRF) |
| Status | Legacy, still on older images | AWS default for new instances |

IMDSv1 is the one that matters — no auth, no headers, GET returns credentials.

## The SSRF-to-Credentials Attack Chain

1. **Find an SSRF** — image importer, webhook tester, "preview link" feature, PDF generator — anything that fetches a URL server-side
2. **Discover the role name:**
   ```
   http://169.254.169.254/latest/meta-data/iam/security-credentials/
   ```
3. **Steal credentials:**
   ```
   http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
   ```
   Returns JSON: `AccessKeyId`, `SecretAccessKey`, `Token`, expiration
4. **You are now that role** — with every permission its policy grants, from outside

The **Capital One breach (2019)** was exactly this: misconfigured WAF → SSRF to IMDS → role creds → 100M+ customer records from S3.

SSRF on cloud is far more dangerous than on-prem. On-prem SSRF scans internal networks. On cloud, SSRF gives you **identity** — and identity is access to everything.

## Other Compute Forms

| Form | Identity story |
|------|---------------|
| **Disk snapshots** | Point-in-time disk copies. Sometimes shared publicly — an open hard drive |
| **Serverless** (Lambda, Azure Functions, Cloud Functions) | Each function has its own identity + env vars. SSRF targets function's metadata endpoint |
| **Containers** (ECS/EKS, ACI/AKS, Cloud Run/GKE) | Each container has own identity + metadata endpoint. Same SSRF pattern, different URLs |

## Provider Mapping

| Concept | AWS | Azure | Google Cloud |
|---------|-----|-------|-------------|
| Instance | EC2 | Virtual Machine | Compute Engine VM |
| Serverless | Lambda | Azure Functions | Cloud Functions / Cloud Run |
| Containers | ECS, EKS, Fargate | ACI, AKS | Cloud Run, GKE |

## Related Notes

- [[Cloud IAM]] — what the stolen credentials can do
- [[Cloud Storage Security]] — what you exfiltrate with them
- [[Cloud Networking]] — how you reach the SSRF target
