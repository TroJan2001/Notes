---
tags: [moc, social-engineering]
---

# Social Engineering

## Concepts
- [[Social Engineering Principles]] — Psychology, six principles, cognitive biases

## Attacks
- [[Phishing Attacks]] — Types, techniques, email spoofing, SPF/DKIM/DMARC, campaign lifecycle

## Practical
- [[Credential Harvesting with SET]] — SET credential harvester setup and usage

---

## Auto-Index (Dataview)

> [!info] All notes in this section, auto-updated by Dataview

```dataview
LIST WITHOUT ID file.link + " — *" + type + "*"
FROM "Social Engineering"
WHERE type != null AND !contains(file.name, "MOC")
SORT file.name ASC
```
