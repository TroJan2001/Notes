---
title: "S3 Buckets"
created: 2026-03-11
type: technique
tags: [technique, osint, recon, cloud]
---

# S3 Buckets

Amazon S3 (Simple Storage Service) stores files in "buckets" accessible over HTTP/HTTPS. When access permissions are misconfigured, sensitive files become publicly readable — or even writable.

---

## URL Format

```
https://{name}.s3.amazonaws.com
https://s3.amazonaws.com/{name}
```

The bucket name is chosen by the owner (e.g., `tryhackme-assets.s3.amazonaws.com`).

---

## Discovery Methods

| Method | How |
|--------|-----|
| **Page source** | `grep -r "s3.amazonaws.com" page.html` |
| **GitHub repos** | Search target's repos for S3 URLs or AWS config files |
| **DNS CNAME** | `dig target.com` — may show S3 CNAME records |
| **Certificate transparency** | Check crt.sh for S3-related subdomains |
| **Brute-force naming** | Try `{company}-assets`, `{company}-backup`, `{company}-www`, `{company}-private`, `{company}-public`, `{company}-dev` |

### Automated Tools

```bash
# S3Scanner — find and test S3 buckets
s3scanner scan --bucket target-company

# cloud_enum — multi-cloud enumeration (AWS, Azure, GCP)
cloud_enum -k target-company
```

---

## Permissions to Check

| Permission | What It Means | Risk |
|------------|---------------|------|
| **ListBucket** | Can list all files in the bucket | Exposes file names, structure, sensitive paths |
| **GetObject** | Can download files | Data exfiltration — credentials, backups, PII |
| **PutObject** | Can upload files | Plant malware, deface content, overwrite configs |

### Test Without Credentials

```bash
# List bucket contents (no AWS creds needed if public)
aws s3 ls s3://bucket-name --no-sign-request

# Download a file
aws s3 cp s3://bucket-name/file.txt . --no-sign-request
```

---

## Equivalent Services

| Provider | Service | URL Pattern |
|----------|---------|-------------|
| **AWS** | S3 | `{name}.s3.amazonaws.com` |
| **Azure** | Blob Storage | `{name}.blob.core.windows.net` |
| **GCP** | Cloud Storage | `storage.googleapis.com/{name}` |

Same misconfiguration risks apply to all three.

---

## Related Notes

- [[Google Hacking, Dorking]] — dork for exposed buckets
- [[Vulnerability Searching]] — check for known S3 misconfig patterns
