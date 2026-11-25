---
title: "ML Data Poisoning and Backdoors"
created: 2026-11-25
type: concept
tags: [ml-security, poisoning, backdoor, concept]
credit: "CSCE 704 (Dr. Marcus Botacin, Texas A&M) — my synthesis"
---

## Overview

A classic backdoor is a hidden `if` a developer plants. In a neural network nobody writes the code — the
model learns from data. So an attacker feeds **crafted training samples** until the model teaches *itself*
to misbehave whenever a **trigger** appears, while staying accurate on everything else (so nobody notices).
One paper implanted a reliable backdoor with only **~0.1% poisoned samples**.

## Where the trigger lives

- **Problem space** — the actual bytes (e.g. a byte pattern in a PE file). Easy to implant, easier to detect.
- **Feature space** — hand-crafted features (n-grams, entropy, imports). More subtle; not tied to fixed bytes.
- **Latent space** — the network's internal representation. **Hardest to detect**: many different inputs map to the same internal pattern, so there is no byte signature to search for. Convolution/pooling often wipe out naive triggers, which is why strong attacks target the latent representation directly.

## Dirty vs clean label

- **Dirty-label** — flip labels at training time (malware-with-trigger labelled "benign"). Effective but the dataset looks wrong on inspection.
- **Clean-label** — samples keep their true label but carry a hidden pattern that pushes the model's internal representation into the backdoor zone. Harder to detect (dataset looks valid) and harder to build.

## Poisoning the supply of data

Models train on massive public data, so attackers slip samples in:

- **Naive** — swap safe code for unsafe. Fast, high success, easy to spot.
- **Covert** — hide payloads in comments/docstrings.
- **TrojanPuzzle-style** — only fragments appear in the data; the model completes the hidden payload itself during generation. See [[LLMs in Security]].
- **Sybil amplification** — create many starred fake repos so poisoned data looks popular and gets scraped.

Defenses (static analysis, dataset cleaning, fine-pruning, data provenance, drift/anomaly detection) help
but none is complete; small hidden triggers persist. **Prevention beats removal** — once a shortcut is
learned deep in the representation, see [[Machine Unlearning]] for how hard it is to take back.

## How It Relates

- [[Machine Unlearning]] — removing a poisoned datapoint's influence after the fact
- [[Concept Drift and Evolution]] — self-updating model pools can be poisoned through pseudo-labels
- [[LLMs in Security]] — code-suggestion models are a prime poisoning target

## References
- CSCE 704 — Lookin' Out My Backdoor!; TrojanPuzzle; Machine Unlearning

---
*Based on my own notes from **CSCE 704 — Data Analytics for Cybersecurity** (Dr. Marcus Botacin, Texas A&M University). The synthesis and wording are mine; the paper selection and course framing are his.*
