---
title: "Adversarial ML Evasion"
created: 2026-11-25
type: concept
tags: [ml-security, adversarial-ml, malware-detection, evasion, concept]
credit: "CSCE 704 (Dr. Marcus Botacin, Texas A&M) — my synthesis"
---

## Overview

Treat malware detection as adversarial: change the **input** just enough to cross the decision boundary
while the program still runs. Two constraints define the whole field — the edit must be
**functionality-preserving**, and the detector only sees what its **representation** exposes.

## Representation decides the attack surface

- **Raw-byte models** (MalConv, AvastNet) learn from the file's bytes. Powerful, but sensitive to layout: padding or new sections can shift the prediction without touching execution. They can also learn meaningless correlations (e.g. "UPX-packed ⇒ malware").
- **Feature-based models** read PE headers, imports, strings, section sizes. More stable to byte noise, but easy to mimic and **blind to embedded payloads** (so droppers walk through).

The Windows PE loader ignores unused sections and many header fields — exactly the gap evasion lives in.

One proposed hardening forces **non-negative network weights** so benign-looking bytes can't cancel
malicious signal — but it doesn't fix biased training data (the model can still learn "packer ⇒ malware").

## Functionality-preserving edits

- **Byte-distribution shaping** — inject benign bytes/sections to shift the file's statistical profile toward goodware.
- **Layout manipulation** — move real code into less-inspected areas (resources), or change header fields the OS ignores.
- **Packing** — compress/encrypt the executable; it looks different statically but runs the same. Over-training on a few packers teaches the model to flag the *packer*, not the malware.
- **Encoding** — XOR or Base64 the payload to hide `MZ`/`PE` headers, API names and strings.
- **Mimicry + dead imports / dead code** — add declared-but-unused libraries or never-executed code so import-frequency / TF-IDF features are drowned in benign signal.
- **Droppers** — benign-looking carrier delivers the real payload; feature extractors don't see the embedded content.

## Black-box, query-efficient evasion

Without model internals, framing is an **optimization under a query budget** (real detectors log/limit attempts):

- **Hard labels** (just "malicious"/"benign") make it harder — no gradient of closeness. **Soft labels** (confidence scores) make it much easier.
- **Learned generators (GANs):** a generator proposes variants, a discriminator judges them, trained in a loop against a **surrogate** model that imitates the target.
- **Transferability:** samples that fool the surrogate often fool the real detector, especially when detectors share architecture or training data. This is what makes black-box attacks scale.

## Takeaway

Evasion succeeds when **appearance changes without behaviour changing**. Defenses in [[Defending ML Models]]
raise the *cost* of that, they don't eliminate it.

## How It Relates

- [[Defending ML Models]] — adversarial training and Moving Target Defense answer these attacks
- [[Security ML Evaluation Pitfalls]] — a threat model must anticipate these edits
- [[Concept Drift and Evolution]] — evasion tactics themselves drift over time

## References
- CSCE 704 — Shallow Security; No Need to Teach New Tricks (XOR); Functionality-Preserving Black-Box Optimization; Mal-LSGAN

---
*Based on my own notes from **CSCE 704 — Data Analytics for Cybersecurity** (Dr. Marcus Botacin, Texas A&M University). The synthesis and wording are mine; the paper selection and course framing are his.*
