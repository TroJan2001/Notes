---
title: "Cloud Storage Security"
created: 2026-11-17
type: technique
tags: [cloud, storage, technique]
---

Public storage buckets are the #1 source of cloud breach headlines. Someone creates a bucket, uploads sensitive data, leaves access controls wrong.

## Object Storage Basics

Flat namespace: **buckets** (top-level containers) hold **objects** (files + metadata). Every object accessible by URL:

| Provider | URL Pattern |
|----------|-------------|
| AWS S3 | `https://<bucket>.s3.amazonaws.com/<key>` |
| Azure Blob | `https://<account>.blob.core.windows.net/<container>/<blob>` |
| GCP | `https://storage.googleapis.com/<bucket>/<object>` |

## Three Access Control Mechanisms

| Mechanism | How it fails |
|-----------|-------------|
| **Bucket policies** (IAM JSON) | `"Principal": "*"` grants access to anyone on the internet |
| **ACLs** (per-object) | "Public read" set without understanding implications |
| **Signed URLs** (time-limited) | Key leaks, or expiry set to years from now |

## How Buckets End Up Public

1. **Dev defaults in prod** — public during testing, forgotten when real data goes in
2. **Block-public-access disabled** — master switch turned off "to make something work"
3. **Wildcard principals** — `"Principal": "*"` in bucket policy
4. **Leaked signed URLs** — long-lived URL posted in a ticket, indexed by search engines

## Attacker Enumeration Workflow

1. **Guess bucket names** — `<company>-backups`, `<company>-dev`, `<company>-prod`, `<company>-assets`
2. **Probe endpoints** — HTTP request to provider URL pattern for each candidate
3. **List contents** — plain GET to a public bucket returns object index
4. **Download** — anything that lists is readable without credentials

Tools: `s3scanner`, `cloud_enum`, or simple `curl`.

## What You Find in Open Buckets

In rough order of impact:

| Artifact | Why |
|----------|-----|
| **Backups** | Database dumps, full-disk snapshots — everything in one file |
| **Source code / build artifacts** | Hardcoded secrets, internal API docs |
| **Config files** | `.env`, `credentials.json`, K8s configs, CI/CD secrets |
| **Logs** | Session tokens, internal IPs, passwords in error messages |
| **Customer data** | PII — emails, addresses, payment info |

## Related Notes

- [[Cloud IAM]] — policies controlling bucket access
- [[Cloud Compute & Metadata]] — SSRF to get creds that unlock private buckets
- [[Cloud Service Models]] — shared responsibility
