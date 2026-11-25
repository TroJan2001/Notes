---
title: "Continuous Authentication and Keystroke Dynamics"
created: 2026-11-25
type: concept
tags: [ml-security, authentication, behavioral-biometrics, concept]
credit: "CSCE 704 (Dr. Marcus Botacin, Texas A&M) — my synthesis"
---

## Overview

Authentication answers **"who are you?"**; authorization answers **"what may you do?"**. Traditional
systems authenticate **once** and then trust the session — but users walk away, sessions get stolen, and
that long trust window is the problem. Continuous authentication re-verifies the user quietly in the
background instead.

## Why password-only fails, and the usable-security tension

Re-prompting for passwords is theoretically secure but practically bad: people get annoyed, pick weak
passwords, reuse them, or bypass the policy. Every extra rule can push users toward *less* safe behaviour —
the core **usable-security** trade-off. (Password strength, hashing, salting and rainbow tables are covered
in [[Password Hashing]]; this note is about the *behavioural* layer on top.)

## Continuous authentication via behaviour

Quietly re-verify from ongoing signals — mouse use, touch pressure, and especially **typing rhythm**:

- **Keystroke dynamics** — each person types with a characteristic timing between key presses. Hard to steal or mimic, unlike a password.
- **Same mechanism, opposite intent:** a keylogger captures the *characters* (malicious); an authenticator needs only the *timing* (benign). Monitoring the keyboard is identical; the stored signal, purpose and threat model are opposite.

## Offline vs online studies

- **Offline** — analyse stored keystroke samples after the fact.
- **Online** — measure the model *during live interaction*, which captures drift, mood and fatigue. Typing patterns shift through the day, so continuous authentication is fundamentally a **streaming, drift-aware** task — the same shape as [[Concept Drift and Evolution]] in malware detection.

## The offensive flip

The same timing signals that authenticate can also **deanonymise** people or link separate accounts.
And **typosquatting** — registering domains based on common typing mistakes — is attackers exploiting human
typing behaviour, the mirror image of defenders measuring it.

## How It Relates

- [[Concept Drift and Evolution]] — behaviour drifts, so the model must adapt
- [[Password Hashing]] — the secret-based layer this complements
- [[Malware Detection Approaches]] — same underlying task: pattern recognition under drift

## References
- CSCE 704 — Online Binary Models (Keylogging vs Keystroke Authentication); Passphrase and Keystroke Dynamics Authentication (Usable Security)

---
*Based on my own notes from **CSCE 704 — Data Analytics for Cybersecurity** (Dr. Marcus Botacin, Texas A&M University). The synthesis and wording are mine; the paper selection and course framing are his.*
