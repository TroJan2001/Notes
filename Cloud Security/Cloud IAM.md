---
title: "Cloud IAM"
created: 2026-11-17
type: concept
tags: [cloud, iam, concept]
---

Identity is where most cloud compromises start. A leaked access key with over-permissive policies beats a memory-corruption exploit nine times out of ten.

## IAM Policies

JSON documents that specify who can do what to which resources. Three fields carry the meaning:

| Field | Purpose | Example |
|-------|---------|---------|
| **Effect** | Allow or Deny | `"Allow"` |
| **Action** | Operations permitted | `"storage:GetObject"` |
| **Resource** | Which specific resources | `"bucket/reports/*"` |

**Well-scoped:**
```json
{ "Effect": "Allow", "Action": "storage:GetObject", "Resource": "bucket/reports/*" }
```

**Over-permissive (wildcard):**
```json
{ "Effect": "Allow", "Action": "*", "Resource": "*" }
```

First thing to check in any policy: **wildcards in Action and Resource**. `*` on both = do anything to anything.

## Roles

A **role** is a named bundle of permissions that an identity can temporarily assume. When assumed, the provider hands back **temporary credentials** scoped to that role's policies.

Why attackers care:
1. **Privilege escalation** — compromised user may be able to assume a more powerful role
2. **IMDS credentials** — VMs are assigned roles, and the metadata service hands out temporary creds for them

## The IAM Enumeration Checklist

When you land cloud credentials (leaked config, SSRF, compromised service):

1. Which identity do these credentials belong to?
2. What policies are attached (directly or through groups)?
3. Which roles can this identity assume?
4. Are any policies over-permissive (wildcards)?
5. What's the scope — single resource or whole account?

Cloud equivalent of `whoami` → `sudo -l` → `id` on Linux.

## The Pattern Behind Most Cloud Breaches

**Over-permissive policies + exposed keys.** Keys leak constantly:
- Committed to public Git repos
- Embedded in container images on public registries
- Left in config files backed up to public buckets
- Visible in screenshots posted to tickets

The keys are just strings. They become a breach when the identity behind them has wildcard permissions.

## Provider Mapping

| Concept | AWS | Azure | Google Cloud |
|---------|-----|-------|-------------|
| Identity service | IAM | Microsoft Entra ID | Cloud IAM |
| Long-lived credential | Access Key ID + Secret | Client ID + Secret | Service account key |
| Role equivalent | IAM Role | Managed Identity | Service Account |

## Related Notes

- [[Cloud Service Models]] — shared responsibility model
- [[Cloud Compute & Metadata]] — SSRF to steal role credentials
- [[Cloud Storage Security]] — what leaked creds give access to
