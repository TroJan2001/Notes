---
title: "Penetration Testing Frameworks"
created: 2026-11-09
type: concept
tags: [concept, pentesting, frameworks, fundamentals]
---

## Master Comparison Table

| Framework | Scope | Best For | Key Feature |
|-----------|-------|----------|-------------|
| **OSSTMM** | Any security channel | Repeatable audits with measurable results | RAV (Risk Assessment Values) — quantifiable security metrics |
| **OWASP WSTG** | Web applications | Detailed web app testing | 12 categories, 90+ test cases |
| **OWASP MASTG** | Mobile applications | iOS/Android security testing | Mobile-specific test methodology |
| **NIST SP 800-115** | General technical | US government / compliance-driven orgs | Federal standard, policy-aligned |
| **PTES** | End-to-end pentest | Engagements needing structured reporting | 7 phases with executive + technical reports |
| **ISSAF** | End-to-end pentest | Learning attacker progression | 9-step model (outdated, no longer maintained) |
| **MITRE ATT&CK** | Adversary behavior | Mapping findings to real-world TTPs | Tactics (why) × Techniques (how) knowledge base |
| **CBEST** | UK financial sector | UK banks under Bank of England oversight | Mandated intelligence-led testing |
| **PCI DSS** | Payment card data | Any system handling cardholder data | Regulatory compliance for card transactions |
| **CSA CCM** | Cloud environments | Cloud security assessments | Cloud-specific control matrix |
| **WASC** | Web applications | Legacy web threat classification | Predecessor to modern OWASP work |

## Framework Details

### OSSTMM (Open Source Security Testing Methodology Manual)

Tests across **5 security channels**:

| Channel | Code | What It Covers |
|---------|------|---------------|
| Human Security | HUMSEC | Social engineering, physical human interaction |
| Physical Security | PHYSSEC | Physical access to buildings, hardware, assets |
| Wireless Communications | SPECSEC | WiFi, Bluetooth, RF, spectrum-based signals |
| Telecommunications | COMSEC | Phone lines, fax, video conferencing |
| Data Networks | DATASEC | LAN, servers, endpoints, network infrastructure |

Produces **RAV (Risk Assessment Values)** — numerical scores that make security measurable and comparable across audits over time.

### OWASP WSTG (Web Security Testing Guide)

12 testing categories with 90+ individual test cases covering:
- Information gathering, configuration management, identity management
- Authentication, authorization, session management
- Input validation, error handling, cryptography
- Business logic, client-side testing, API testing

Used as a **supplementary framework** alongside a primary methodology whenever web components are in scope.

### OWASP MASTG (Mobile Application Security Testing Guide)

The mobile equivalent of WSTG — structured test cases for iOS and Android apps covering:
- Data storage, cryptography, authentication
- Network communication, platform interaction
- Code quality, resilience against reverse engineering

### NIST SP 800-115 (Technical Guide to Information Security Testing)

US government standard. Covers planning, execution, and post-testing phases. Best suited for organizations that need to align with federal compliance requirements.

### PTES (Penetration Testing Execution Standard)

7 practical phases:
1. Pre-engagement interactions
2. Intelligence gathering
3. Threat modeling
4. Vulnerability analysis
5. Exploitation
6. Post-exploitation
7. **Reporting** — explicitly split into **executive summary** (for the board) and **technical report** (for the security team)

Best choice when the engagement requires structured deliverables for both technical and non-technical stakeholders.

### ISSAF (Information Systems Security Assessment Framework)

9-step attacker progression:
1. Information gathering
2. Network mapping
3. Vulnerability identification
4. Penetration
5. Gaining access & privilege escalation
6. Enumerating further
7. Lateral movement (compromise remote users/sites)
8. Maintaining access
9. Covering tracks

No longer maintained — useful for learning the attacker's logical progression but not recommended as a primary engagement framework.

### MITRE ATT&CK

A knowledge base mapping real-world adversary behavior:
- **Tactics** (columns) = the WHY — the attacker's goal (e.g., Initial Access, Lateral Movement)
- **Techniques** (rows) = the HOW — specific methods to achieve that goal (e.g., T1566 Phishing, T1003 Credential Dumping)

Not a testing methodology — used to **map findings to adversary behavior** in reports, making them meaningful to both red and blue teams.

## Framework Selection Method

### Step 1: Identify Primary Filter

| Filter | When It Applies |
|--------|----------------|
| **Regulatory mandate** | Client is in a regulated industry (banking, healthcare, payments) |
| **Target type + engagement shape** | Combination of what's being tested and what deliverables are needed |
| **Target type only** | Simple scope with no regulatory requirement |

### Step 2: Pick Primary Framework

| Situation | Primary Framework |
|-----------|------------------|
| UK bank under Bank of England | **CBEST** (mandatory) |
| End-to-end pentest with executive reporting | **PTES** |
| Repeatable audit with metrics | **OSSTMM** |
| Web application only | **OWASP WSTG** |
| Mobile application only | **OWASP MASTG** |
| US government alignment | **NIST SP 800-115** |

### Step 3: Add Supplementary Frameworks

| Component | Add |
|-----------|-----|
| Web portal/app in scope | **OWASP WSTG** |
| Mobile app in scope | **OWASP MASTG** |
| Handles payment card data | **PCI DSS** |
| Want adversary mapping in reports | **MITRE ATT&CK** |

## Real-World Stacking Examples

| Client | Primary | Supplementary | Why |
|--------|---------|---------------|-----|
| **UK Retail Bank** (Bank of England) | CBEST | WSTG + ATT&CK | Regulatory mandate drives primary; WSTG for web components; ATT&CK strengthens reporting |
| **Regional Hospital** (HIPAA, board reporting) | PTES | WSTG + ATT&CK | Needs structured executive deliverables; WSTG for patient portal; ATT&CK for adversary mapping |
| **Fintech Mobile** (iOS/Android, card data) | MASTG | PCI DSS | Mobile apps are the target; PCI DSS required because apps handle cardholder data |

## Related

- [[Penetration Testing Methodology]]
- [[Cyber Kill Chain]]
- [[Risk Management]]
