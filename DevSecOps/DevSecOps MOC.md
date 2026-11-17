---
tags: [moc, devsecops, containers]
---

# DevSecOps

## Virtualization Basics
- [[Hypervisors]]
- [[Containers]]
- [[Docker]]
- [[Kubernetes]]

## Container Hardening
- [[Control Groups (cgroups)]]
- [[Docker Daemon]]
- [[Linux Sandboxing & Access Control]]
- [[Over-Privileged Containers]]

## Container Vulnerabilities
- [[Abusing Namespaces]]
- [[Container Capabilities|Capabilities]]
- [[Exposed Docker Daemon]]

## Software Development & DevSecOps
- [[Software Development Models]] — Waterfall → Agile → DevOps, CI/CD, IaC, monitoring, microservices
- [[DevSecOps Fundamentals]] — Shifting Left, challenges (silos, visibility, stringent processes), culture (autonomy, transparency, empathy)

---

## Auto-Index (Dataview)

> [!info] All notes in this section, auto-updated by Dataview

```dataview
LIST WITHOUT ID file.link + " — *" + type + "*"
FROM "DevSecOps"
WHERE type != null AND !contains(file.name, "MOC")
SORT file.name ASC
```
