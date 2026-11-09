---
title: "Penetration Testing Methodology"
created: 2026-11-09
type: concept
tags: [concept, pentesting, methodology, fundamentals]
---

## Pentest Phases

1. **Enumeration** — discover services, versions, directories, endpoints
2. **Vulnerability Analysis** — connect findings to known weaknesses
3. **Initial Access** — exploit a vulnerability to get a foothold
4. **Privilege Escalation** — enumerate from inside, find a way up
5. **Reporting** — document everything with evidence and remediation advice

## Types of Pentests

| Type | Perspective | Focus |
|------|------------|-------|
| **Web Application** | User interacting with the app | Auth, authz, sessions, input validation, config |
| **External Network** | Outsider with no access | Internet-facing servers, firewalls, VPNs, remote access |
| **Internal Network** | Assumed breach, already inside | Lateral movement, privilege escalation, segmentation |

## Web App Testing Areas

- **Authentication** — credential handling, brute-force protection, MFA, password reset logic
- **Authorization** — access control, vertical/horizontal privilege escalation
- **Session Management** — session fixation, invalidation after logout, cookie security, CSRF
- **Input/Output Validation** — injection attacks, data type checks, output encoding
- **Security Configuration** — headers, error handling, rate limiting, crypto, exposed services

## Effective Mindset

- **Understand the system first** — learn how it works before attacking
- **Attention to detail** — small behavior differences lead to big findings
- **"What if?" curiosity** — what if I change this parameter? What if I upload a different extension?
- **Prioritize critical areas** — test auth and access control before "About Us"
- **Think in context** — same bug = different risk depending on what data it touches
- **Chain vulnerabilities** — IDOR alone is medium, but IDOR → account takeover → RCE is critical

## Common Traps to Avoid

- **Rushing to exploit** without understanding the system
- **Over-reliance on tools** — scanners miss logic bugs
- **Tunnel vision** — fixating on one feature, ignoring everything else
- **Making assumptions** — verify how things work, don't guess
- **Blindly following checklists** — real bugs live outside the checklist

## Best Practices

- **Take notes as you go** — track every test, finding, and observation
- **Collect evidence** — screenshots, curl commands, tool output
- **Manage time** — prioritize high-impact areas, write the report as you go
- **Communicate proactively** — report blockers immediately, give regular updates
- **Stay professional** — respect scope, handle sensitive data responsibly, redact PII in reports

## Ethics and Permission

- Always have **written authorization** before testing
- Stay within the **defined scope** — if unsure, stop and ask
- **Redact sensitive data** in reports (passwords, PII, payment info)
- **Stop and report** if you find unexpected access to out-of-scope systems
- Build **trust** through transparency, honest reporting, and actionable recommendations

## Related

- [[Risk Management]]
- [[Incident Response]]
- [[Security Principles]]
