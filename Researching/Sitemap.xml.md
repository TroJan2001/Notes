---
title: "Sitemap.xml"
created: 2026-03-11
updated: 2026-11-09
type: concept
tags: [concept, recon, web]
---

## What Is It

A file at `/sitemap.xml` that tells search engines which pages the site owner **wants** indexed. The opposite of robots.txt — instead of hiding pages, it advertises them.

## Format

```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://example.com/</loc></url>
  <url><loc>http://example.com/news</loc></url>
  <url><loc>http://example.com/news/article?id=1</loc></url>
  <url><loc>http://example.com/s3cr3t-area</loc></url>
  <url><loc>http://example.com/customers/login</loc></url>
</urlset>
```

## Pentest Use

Sitemaps can reveal:
- **Hidden or forgotten pages** — staging areas, old content, secret paths
- **URL parameters** — `?id=1` hints at potential IDOR or SQL injection points
- **Full site structure** — maps the application without needing to crawl
- **Pages not linked from the UI** — endpoints only accessible if you know the URL

Combined with robots.txt, you get a quick picture of the site's structure before running any tools.

## Related

- [[robots.txt]]
- [[Gobuster]]
