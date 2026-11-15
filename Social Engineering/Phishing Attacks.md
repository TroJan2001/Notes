---
title: "Phishing Attacks"
created: 2026-11-15
type: technique
tags: [social-engineering, phishing, technique]
---

# Phishing Attacks

Phishing uses social engineering to trick people into revealing sensitive information or running malware. Attackers impersonate legitimate sources via email, SMS, phone, or fake websites. It exploits [[Social Engineering Principles|human psychology]], not technical vulnerabilities.

---

## Types of Phishing

| Type | Target | Scale | Goal |
|------|--------|-------|------|
| **Phishing** | Anyone | Mass — same message to thousands | Quick wins: stolen passwords, card details |
| **Spear Phishing** | Specific person | Targeted — researched and customized | Foothold into the organization |
| **Whaling** | C-level executives (CEO, CFO) | Targeted | Money transfers, regulated data, override controls |
| **Smishing** | Anyone | Mass or targeted via **SMS** | Credential theft, malware install |
| **Vishing** | Anyone | Targeted via **voice calls** | Credential theft, social engineering |

---

## URL and Domain Manipulation

| Technique | How It Works | Example |
|-----------|-------------|---------|
| **URL Masking** | Display a legitimate URL as hyperlink text, actual link goes elsewhere | Shows `https://tryhackme.com`, links to `http://phisher.thm` |
| **Homograph Attacks** | Use visually similar characters (Cyrillic, zero vs O) | `go0gle.com` looks like `google.com` |
| **Typosquatting** | Register domains with common typos | `tryhacme.com` instead of `tryhackme.com` |
| **URL Shorteners** | Hide the real destination behind a short link | `bit.ly/x3kf9` → malicious site |

---

## Email Spoofing

SMTP has no built-in sender authentication. Attackers exploit this to forge the "From" field.

### Techniques

- **Header spoofing:** Modify email headers so the From field shows a trusted address. The real sender is visible in Reply-To, Return-Path, and Received headers
- **Display name spoofing:** Set the sender name to "IT Support" while using a random email address. Mobile clients often only show the display name
- **Lookalike domains:** `support@tryhackme-secure.com` instead of `support@tryhackme.com`

### Email Security Defenses

| Protocol | What It Does |
|----------|-------------|
| **SPF** (Sender Policy Framework) | DNS record listing which mail servers can send for a domain. Receiving server checks if the sending IP is authorized |
| **DKIM** (DomainKeys Identified Mail) | Cryptographic signature on the email. Receiving server verifies the signature against a public key in DNS |
| **DMARC** (Domain-based Message Authentication, Reporting & Conformance) | Policy that tells receiving servers what to do when SPF/DKIM fail (reject, quarantine, or allow). Also enables reporting |

All three work together. SPF checks the server, DKIM checks the message integrity, DMARC sets the policy.

---

## Credential Harvesting

Clone a legitimate login page, host it on a deceptive domain. Victim enters credentials → sent to attacker's server → victim redirected to real site. Victim thinks they had a failed login. Attacker has the password.

See [[Credential Harvesting with SET]] for a practical walkthrough.

---

## Payload Delivery

### Macro Documents

1. Attacker sends a `.docm` file (Word with macros)
2. Victim opens it, sees "Enable Content" prompt
3. Victim enables macros
4. VBA macro runs silently — downloads malware or beacons back to attacker
5. In pentests, replaced with a benign beacon that just confirms execution

---

## Phishing Campaign Lifecycle

For penetration testing engagements:

### 1. Planning & Scoping
- Define goals, target groups, techniques in scope
- Separate metrics: "clicked link" vs "submitted credentials"
- Get legal sign-off, set kill switch and emergency contacts

### 2. Reconnaissance
- OSINT only: company website, press releases, LinkedIn, public social media
- Find pretexts: recent announcements, policy changes, org structure
- Stay within scope, document all sources

### 3. Scenario & Payload Development
- Craft realistic but harmless messages (invoice reminder, IT notification, HR update)
- Tracking links, branded landing pages, benign attachments
- No real malware — simulated login pages and fake accounts only

### 4. Exploitation
- Send in waves or single batch per the plan
- Monitor opens, clicks, submissions, and reports in real time
- Keep kill switch ready, pause if anything leaks outside scope

### 5. Reporting & Debriefing
- Analyze results without naming individuals
- Present metrics with recommendations
- Agree on follow-up actions and re-testing cadence

---

## Campaign Metrics & Benchmarks

| Metric | What It Measures | Benchmark | Recommendation |
|--------|-----------------|-----------|----------------|
| **Open Rate** | % who opened the email | 50–65% typical | Targeted refresher training |
| **Click Rate** | % who clicked a link | 8–14% acceptable; >14% high risk | Focused security awareness training |
| **Credential Entry Rate** | % who entered credentials | <2% low; 2–5% moderate; >5% high risk | Phishing site ID training, MFA |
| **Attachment Detonation Rate** | % who opened/executed attachment | >5–7% suggests risk | Safe attachment handling training, sandboxing |
| **Reporting Rate (24h)** | % who reported within 24h | >40% strong; 30–40% average; <30% low | Reporting awareness campaign |

---

## Tools

| Tool | Purpose |
|------|---------|
| **GoPhish** | Web-based phishing campaign framework — templates, scheduling, analytics dashboard |
| **EvilNginx** | Reverse proxy that bypasses MFA — captures credentials AND session tokens in real time |
| **SET** (Social Engineering Toolkit) | Spear phishing, credential harvesting, fake websites. See [[Credential Harvesting with SET]] |

---

## Related Notes

- [[Social Engineering Principles]]
- [[Credential Harvesting with SET]]
- [[Authentication Bypass]]
- [[Session Management]]
