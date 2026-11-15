---
title: "Wappalyzer"
created: 2026-03-11
type: tool
tags: [tool, osint, recon]
---

# Wappalyzer

Identifies what technologies a website uses — frameworks, CMS, server software, JS libraries, analytics, CDNs, and version numbers.

---

## How to Use

| Method | Details |
|--------|---------|
| **Browser extension** | Install for Chrome/Firefox → click icon on any page → see tech stack |
| **Online lookup** | `wappalyzer.com/lookup/` → enter any URL |
| **CLI** | `wappalyzer <url>` (Node.js package) |

---

## What It Reveals

| Category | Examples |
|----------|----------|
| **CMS** | WordPress, Joomla, Drupal, Magento |
| **Frameworks** | React, Angular, Laravel, Django, Express |
| **Server** | Apache, Nginx, IIS + version numbers |
| **JS Libraries** | jQuery, Bootstrap, Vue.js |
| **Programming Language** | PHP, Python, Ruby, Node.js |
| **Analytics** | Google Analytics, Hotjar |
| **CDN / Hosting** | Cloudflare, AWS, Akamai |

---

## Pentest Relevance

1. **Version numbers → exploit search** — if it shows `Apache 2.4.49`, search [[ExpliotDB]] for known CVEs
2. **CMS identification → pick the right scanner** — WordPress → [[WPScan]], Joomla → `joomscan`
3. **Framework identification → pick the right wordlist** — Laravel app → use SecLists Laravel routes in [[ffuf]]
4. **Tech stack → narrow attack surface** — PHP + MySQL → test for [[SQL Injection]], Node.js + MongoDB → test for NoSQL injection

---

## Alternatives

- **BuiltWith** — similar online service, more detailed for analytics/advertising tech
- **WhatWeb** — CLI tool on Kali: `whatweb <url>` — more aggressive, can fingerprint deeper

---

## Related Notes

- [[WPScan]] — WordPress-specific scanning
- [[Custom Wordlists]] — tech stack informs wordlist choice
- [[Vulnerability Searching]] — version numbers feed exploit research
