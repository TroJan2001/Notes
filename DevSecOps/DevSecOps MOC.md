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

---

## Auto-Index (Dataview)

> [!info] All notes in this section, auto-updated by Dataview

```dataview
LIST WITHOUT ID file.link + " — *" + type + "*"
FROM "DevSecOps"
WHERE type != null AND !contains(file.name, "MOC")
SORT file.name ASC
```
