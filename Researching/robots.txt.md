---
title: "robots.txt"
created: 2026-03-11
updated: 2026-11-09
type: concept
tags: [concept, recon, web]
---

## What Is It

A file at the root of a website (`/robots.txt`) that tells search engine crawlers which pages they should or shouldn't index.

**Important:** This is a suggestion to bots, NOT a security control. You can still visit any path listed as Disallow directly in your browser.

## Format

```
User-agent: *
Allow: /
Disallow: /staff-portal
Disallow: /admin
Disallow: /backup

Sitemap: http://example.com/sitemap.xml
```

- **User-agent** — which bot the rules apply to (`*` = all bots)
- **Allow** — paths bots CAN index
- **Disallow** — paths bots should NOT index
- **Sitemap** — link to the sitemap file

## Pentest Use

By listing what they want to hide from search engines, site owners give you a **map of interesting directories**:
- Admin panels (`/admin`, `/staff-portal`)
- Backup directories (`/backup`, `/old`)
- Internal tools (`/internal`, `/api`)
- Staging environments (`/staging`, `/dev`)

Always check `/robots.txt` first — it's free recon.

## Related

- [[Sitemap.xml]]
- [[Gobuster]]
