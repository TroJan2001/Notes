---
title: "AI Security MOC"
created: 2026-11-25
type: moc
tags: [ai-security, moc]
---

# AI Security

The umbrella for security + AI. The field nests: **AI ⊃ ML ⊃ deep learning ⊃ LLMs** (and there is AI that
isn't ML, and deep learning that isn't LLMs). In practice the security community keeps two parallel areas —
OWASP maintains a separate **ML Security Top 10** and **LLM Top 10** — so this vault mirrors that split.

## Areas
- [[ML Security MOC]] — securing ML systems (adversarial ML, poisoning, drift, unlearning) **and** ML used for security (malware detection, behavioural authentication). From CSCE 704.
- [[LLM Security MOC]] — attacking and defending LLM applications (prompt injection, jailbreaking, recon, scanning).

## Reference frameworks
- **OWASP Machine Learning Security Top 10** — threats to ML systems.
- **OWASP Top 10 for LLM Applications** — threats to LLM apps.
- **NIST AI 100-2** — Adversarial ML taxonomy (evasion, poisoning, privacy, abuse).
- **MITRE ATLAS** — adversarial threat landscape for AI systems.
