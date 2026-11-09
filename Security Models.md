---
title: "Security Models"
created: 2026-11-09
type: concept
tags: [concept, security, models, cia, access-control]
---

## Overview

Security models are rule systems that define how data is accessed and protected in an organization. They answer two questions: who can **read** what, and who can **change** what.

## Bell-LaPadula (Confidentiality)

**Goal:** Keep secrets secret — prevent unauthorized reading and data leaking downward.

| Rule | Meaning | Why |
|------|---------|-----|
| No read up | Can't read above your clearance | You shouldn't see Top Secret if you're only Secret |
| No write down | Can't write to a lower level | Prevents copying secrets to an unclassified folder |

Created in 1973 for the US military during the Cold War. Confidentiality was the #1 concern — stop spies and leaks.

## Biba (Integrity)

**Goal:** Keep clean data clean — prevent untrusted data from corrupting trusted data.

| Rule | Meaning | Why |
|------|---------|-----|
| No read down | Can't read less trustworthy data | Trusted systems shouldn't pull in garbage |
| No write up | Can't write to a more trustworthy level | Untrusted processes can't modify trusted records |

Created in 1977. The opposite of Bell-LaPadula — instead of protecting secrecy, it protects accuracy.

### Bell-LaPadula vs Biba

| | Can't read... | Can't write... | Protects |
|---|---|---|---|
| **Bell-LaPadula** | UP | DOWN | Confidentiality |
| **Biba** | DOWN | UP | Integrity |

Bell-LaPadula: "don't let secrets leak down."
Biba: "don't let garbage flow up."

## Clark-Wilson (Integrity via Processes)

**Goal:** Integrity through controlled access — only approved processes can modify data.

Three components:
- **CDI** (Constrained Data Items) — the protected data (e.g., financial records)
- **TP** (Transformation Procedures) — the only approved operations on that data (e.g., accounting software)
- **IVP** (Integrity Verification Procedures) — checks that data stays valid (e.g., audit logs)

Created in 1987 for business use. The idea: users never touch data directly — they go through approved software that enforces the rules.

## Microsegmentation

**Goal:** Limit lateral movement on a network by dividing it into tiny zones, down to a single host.

- Traditional networks: one big flat zone — if an attacker gets in, they can reach everything
- Microsegmentation: each machine or group is isolated — compromising one doesn't give access to others

Used in modern cloud and corporate networks (zero trust architecture).

## Where These Are Used

These aren't code libraries. They're **frameworks** used when designing security architecture:

- **Government/military** → Bell-LaPadula for classified data
- **Banks/hospitals** → Biba and Clark-Wilson for data integrity
- **Cloud/enterprise** → Microsegmentation for network security
- **Certifications** → CompTIA Security+, CISSP, CEH all test these

## How It Relates

- [[Security Principles]] — CIA triad is the foundation these models build on
- [[Cryptographic Failures]] — crypto enforces confidentiality and integrity at the data level
