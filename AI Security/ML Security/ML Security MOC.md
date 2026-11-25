---
title: "ML Security MOC"
created: 2026-11-25
type: moc
tags: [ml-security, adversarial-ml, moc]
---

# ML Security

Security *of* machine-learning systems, and ML *used as* a security tool. Part of [[AI Security MOC]];
companion to [[LLM Security MOC]]. Distilled from my own notes for **CSCE 704 — Data Analytics for
Cybersecurity** (Dr. Marcus Botacin, Texas A&M University).

## Securing ML systems
Threats to the model itself, and how to measure and defend it.
- [[Security ML Evaluation Pitfalls]] — why accuracy lies under imbalance; FPR/precision/recall; time-aware evaluation; threat models
- [[Concept Drift and Evolution]] — why a model decays over time, and how to decide when *not* to decide
- [[Adversarial ML Evasion]] — functionality-preserving edits that flip a malware detector without changing behaviour
- [[Defending ML Models]] — adversarial training and Moving Target Defense
- [[ML Data Poisoning and Backdoors]] — triggers planted at training time; problem / feature / latent space; dirty vs clean label
- [[Machine Unlearning]] — removing a datapoint's influence (SISA) without full retraining

## ML for security applications
ML used *as a defensive tool* — not "securing AI", but ML applied to a security problem.
- [[Malware Detection Approaches]] — human vs machine; static vs dynamic; signatures vs ML (YARA); sequence models; early vs late
- [[Continuous Authentication and Keystroke Dynamics]] — authenticating *people* by typing rhythm, as a drift-aware stream

## LLMs as a security factor
- [[LLMs in Security]] — insecure code generation, malware building-blocks, LLM-driven attack agents
- For attacking LLM *applications*, see [[LLM Security MOC]]
