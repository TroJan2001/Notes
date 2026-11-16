---
title: "Privilege Escalation Overview"
created: 2026-03-11
updated: 2026-11-16
type: concept
tags: [privesc, concept]
---

Privilege escalation is the exploitation of a vulnerability, design flaw, or configuration oversight in an operating system or application to gain unauthorized access to resources normally restricted from the user.

## Two Variants

**Horizontal privilege escalation:** Taking over a different user at the same privilege level. For example, a normal user hijacking another normal user's account to inherit their files and access — which may include an SUID binary in their home directory that leads to root.

**Vertical privilege escalation (privilege elevation):** Moving from a lower privilege level to a higher one — typically from a standard user to administrator or root.

![](../Attachments/Pasted%20image%2020231105005554.png)

---

## Related Notes

- [[Methodology]] — structured approach to finding and exploiting privesc vectors
- [[Privilege Escalation MOC]] — full index of techniques
