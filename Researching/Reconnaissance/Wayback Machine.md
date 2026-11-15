---
title: "Wayback Machine"
created: 2026-03-11
type: tool
tags: [tool, osint, recon]
---

# Wayback Machine

Web archive at `archive.org/web/` that stores historical snapshots of websites. Useful in recon to find pages, endpoints, or files that have been removed from the live site.

---

## What to Look For

- **Removed pages** — old admin panels, staging URLs, test endpoints
- **Old JavaScript files** — may contain hardcoded API keys, internal endpoints, debug flags
- **robots.txt history** — previously disallowed paths that reveal hidden directories
- **Old sitemaps** — sitemap.xml snapshots listing pages no longer linked
- **Login pages** — old auth flows that may still be active at different paths
- **Source code comments** — developers sometimes remove comments in later versions

---

## Web UI

1. Go to `web.archive.org`
2. Enter the target domain
3. Browse the calendar timeline — blue dots are snapshots
4. Compare old and new snapshots to spot removed content

---

## CLI Tools

### waybackurls

Fetches all URLs the Wayback Machine has archived for a domain:

```bash
waybackurls target.com > urls.txt
```

Filter for interesting files:

```bash
waybackurls target.com | grep -E "\.(js|json|xml|config|env|bak|sql)$"
```

### gau (Get All URLs)

Similar to waybackurls but pulls from multiple sources (Wayback, Common Crawl, URLScan, AlienVault):

```bash
gau target.com > all_urls.txt
```

---

## Related Notes

- [[robots.txt]] — check historical versions for hidden paths
- [[Sitemap.xml]] — old sitemaps may list removed pages
- [[Google Hacking, Dorking]] — another way to find cached/removed content
