---
title: "Machine Unlearning"
created: 2026-11-25
type: concept
tags: [ml-security, unlearning, privacy, concept]
credit: "CSCE 704 (Dr. Marcus Botacin, Texas A&M) — my synthesis"
---

## Overview

Once you discover poisoned or backdoored data in a model's training history (see
[[ML Data Poisoning and Backdoors]]), or a user invokes GDPR's "right to be forgotten", you need to
**remove a datapoint's influence** from the model. On paper, just delete the bad data — in practice, hard.

## Why it's hard

Training is a **lossy compression**: many datapoints shape the same weights, and each datapoint touches
many parts of the model. Removing one can unintentionally unlearn others. The only *perfect* fix is to
retrain from scratch, which is too slow for real systems.

## SISA (Sharding, Isolation, Slicing, Aggregation)

Change *how* you train so unlearning becomes surgical:

- **Shard** the data into disjoint parts; train a separate model per shard.
- **Slice** each shard's training into steps, saving **checkpoints** along the way.
- To forget a datapoint: jump to the checkpoint just before its slice, retrain **only** that slice of
  **that** shard, leave everything else untouched. **Aggregate** the shard models at inference.

Big speedups on simpler tasks with small accuracy loss. On complex tasks (ImageNet) splitting too far
causes underfitting, so accuracy can drop. Still, it's a realistic path to targeted removal without a full
restart — useful to "purify" a model after a poisoned update, once the suspect samples are identified
(via drift detectors, anomaly scores, or latent-space triggers).

## Takeaway

Unlearning is a **second line of defense**, not a replacement for tight control of training data, labels,
provenance and update pipelines. Preventing a backdoor is far easier than removing one.

## How It Relates

- [[ML Data Poisoning and Backdoors]] — the problem unlearning cleans up
- [[Concept Drift and Evolution]] — both involve deciding which training data no longer belongs

## References
- CSCE 704 — Machine Unlearning (SISA)

---
*Based on my own notes from **CSCE 704 — Data Analytics for Cybersecurity** (Dr. Marcus Botacin, Texas A&M University). The synthesis and wording are mine; the paper selection and course framing are his.*
