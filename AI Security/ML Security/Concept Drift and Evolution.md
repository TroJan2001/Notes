---
title: "Concept Drift and Evolution"
created: 2026-11-25
type: concept
tags: [ml-security, concept-drift, malware-detection, concept]
credit: "CSCE 704 (Dr. Marcus Botacin, Texas A&M) — my synthesis"
---

## Overview

A classifier learns a **decision boundary** from yesterday's data but must judge today's stream.
As software, APIs and malware families change, that boundary stops matching reality and errors climb.

## Drift vs evolution

- **Concept drift** — the feature→label relationship shifts. A permission or API once tied to malware becomes common in benign apps, so the boundary is now in the wrong place.
- **Concept evolution** — genuinely new patterns the model never saw (new SDKs, packers, techniques). A **true zero-day** is evolution inside the malicious domain. By definition the model cannot catch these reliably; the data to learn them does not exist yet.
- Both sides move: benign software evolves with platforms; malware evolves faster under adversarial pressure.

Retraining the classifier alone is not enough — the **feature vocabulary** (the attributes/APIs/strings
exposed to the model) also ages. Refresh **vocabulary and model together**, or the model keeps speaking
yesterday's language.

## The attacker opportunity window

The gap between *knowing* the model is stale and *finishing* its update. Two unavoidable delays:
**detection delay** (confirming drift is real) and **retraining delay** (retrain + redeploy). Attackers
slip samples through the stale boundary during this window.

**Mitigation — a pool of models:** keep several online learners; swap out an ageing one while it retrains
so detection never stops. While true labels are delayed, use **pseudo-labels** from a weighted majority
vote of the rest. This *shrinks* but never closes the window, and it has risks: models can **self-poison**
by confirming each other's mistakes, or be pushed by **model poisoning**. Guard with diversity, a
confidence-agreement threshold before accepting a pseudo-label, a sanitisation step that drops samples the
pool can't agree on, and a full refresh if several models drift together.

## Rejecting with evidence (the missing-label problem)

True labels arrive weeks later (sandboxing, human review). Meanwhile a softmax **always looks confident**
(probabilities sum to 1) even on out-of-distribution input. Invert the logic:

- **Old:** input → classifier → probability → wait for the true label.
- **New:** input → classifier → **p-value** (conformal evaluation) → accept or reject now.

The p-value comes from a **nonconformity ("weirdness") score**: how far the input sits from the training
distribution. High weirdness → low p-value → **reject / abstain** instead of guessing. A rising reject rate
is itself an **early drift signal**. The course's reading reported p-value thresholds as markedly more
reliable than raw-probability thresholds (roughly 90% vs 66%).

> Probability = how sure the model *feels*. Statistics = how sure we can *be* about that feeling.

## How It Relates

- [[Security ML Evaluation Pitfalls]] — time-aware evaluation exists because of drift
- [[ML Data Poisoning and Backdoors]] — self-updating pools widen the poisoning surface

## References
- CSCE 704 — Fast & Furious; DroidEvolver; Transcend; Transcending TRANSCEND

---
*Based on my own notes from **CSCE 704 — Data Analytics for Cybersecurity** (Dr. Marcus Botacin, Texas A&M University). The synthesis and wording are mine; the paper selection and course framing are his.*
