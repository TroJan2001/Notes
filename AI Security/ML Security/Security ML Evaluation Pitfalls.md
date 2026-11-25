---
title: "Security ML Evaluation Pitfalls"
created: 2026-11-25
type: concept
tags: [ml-security, evaluation, methodology, concept]
credit: "CSCE 704 (Dr. Marcus Botacin, Texas A&M) — my synthesis"
---

## Overview

Most security-ML results that look great in a paper fail on deployment. The cause is usually
not the model but the **evaluation**: wrong metric, wrong data split, or an unstated threat model.

## Why accuracy lies

In the wild, malware is often **under 2%** of files (sometimes 0.01%). A classifier that labels
everything benign scores ~99% accuracy and catches nothing. Under imbalance, accuracy and AUC hide
operational failure. Use metrics that separate error types:

- **False Positive Rate (FPR)** — benign flagged as malicious. The one that kills trust; even 1% FPR is unusable at millions of events/day.
- **Precision** — of what you flagged, how much was real. Rises as FPR falls.
- **Recall** — of real threats, how many you caught.

For a defender (and for a bug-bounty hunter triaging leads) **false positives are the expensive error**.

## Evaluation gaps that inflate results

- **Random splits / k-fold cross-validation** leak "future" information into training. Use **time-aware splits**: train on earlier data, test on later, and watch for natural decay. See [[Concept Drift and Evolution]].
- **Data snooping** — letting test/future data touch training, e.g. computing TF-IDF over the whole dataset.
- **Biased parameter selection** — tuning thresholds on the test set.
- **No baseline** — always include a simple baseline (logistic regression) to show the complex model earns its keep.
- **Label noise** — AV labels disagree across vendors and change over time; the benign/malicious boundary is itself fuzzy.

## Threat model must be explicit

Security is adversarial: attackers adapt once a defense ships. State what the attacker knows, what
they can change, and what they cannot — then test under those conditions. Attackers are economically
rational and take the cheapest path, so a defense "works" when evasion becomes uneconomical, not impossible.

## How It Relates

- [[Concept Drift and Evolution]] — why time-aware evaluation is non-negotiable
- [[Adversarial ML Evasion]] — the adaptation a threat model must anticipate

## References
- CSCE 704 — "Machine Learning (In) Security: A Stream of Problems"; "Dos and Don'ts of ML in Computer Security"

---
*Based on my own notes from **CSCE 704 — Data Analytics for Cybersecurity** (Dr. Marcus Botacin, Texas A&M University). The synthesis and wording are mine; the paper selection and course framing are his.*
