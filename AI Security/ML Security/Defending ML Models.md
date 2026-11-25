---
title: "Defending ML Models"
created: 2026-11-25
type: concept
tags: [ml-security, adversarial-ml, defense, concept]
credit: "CSCE 704 (Dr. Marcus Botacin, Texas A&M) — my synthesis"
---

## Overview

Two complementary answers to [[Adversarial ML Evasion]]: harden the model **before** deployment, and make
the detection surface **unpredictable during** deployment. Best used together — robustness at the model
level, unpredictability at the system level.

## Adversarial training

Retrain on inputs that have been deliberately modified to evade — in-place instruction replacement,
displacement with control-flow changes, byte injection into non-executed regions. The objective mixes
clean and adversarial examples with a weighting parameter, teaching the model to classify the manipulated
versions correctly.

- More consistent than prediction-time fixes (e.g. byte masking), which are costly, hurt accuracy on clean files, or get bypassed by adaptive attackers.
- **Limits:** generating strong samples is expensive; gains taper after early rounds; it ages under [[Concept Drift and Evolution]] (train on old attacks, fail on new); and it can overfit to specific adversarial patterns. Practical only if refreshed periodically.

## Moving Target Defense (MTD)

Deploy several detectors and **switch between them** at runtime. Since adversarial samples tend to overfit
one model's behaviour, rotation breaks them — and specifically defeats **transferability**, the core of
black-box attacks. Often framed as a decision problem (pick the model by past performance/resistance),
sometimes with reinforcement learning. Rotation also disrupts both soft-label and hard-label probing.

- **Cost:** training and maintaining multiple models plus a switching policy.

## Choosing

- **One static model that must stay robust over time** → adversarial training (lower complexity).
- **Can run and rotate several strong models** → MTD (more complex, stronger against transfer attacks).

A lightweight extra: zeroing non-executable bytes before classification blunts byte-injection with little
accuracy cost — but monitor the trade-off.

## How It Relates

- [[Adversarial ML Evasion]] — the attacks these answer
- [[ML Data Poisoning and Backdoors]] — a different threat (training-time, not inference-time)

## References
- CSCE 704 — Adversarial Training for Raw-Binary Malware Classifiers; Moving Target Defense against Adversarial ML

---
*Based on my own notes from **CSCE 704 — Data Analytics for Cybersecurity** (Dr. Marcus Botacin, Texas A&M University). The synthesis and wording are mine; the paper selection and course framing are his.*
