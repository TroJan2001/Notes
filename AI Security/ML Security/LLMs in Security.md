---
title: "LLMs in Security"
created: 2026-11-25
type: concept
tags: [ml-security, llm, code-security, offensive-ai, concept]
credit: "CSCE 704 (Dr. Marcus Botacin, Texas A&M) — my synthesis"
---

## Overview

LLMs as a **factor** in security — writing code, repairing bugs, explaining malware, generating it, and
driving attacks. The through-line: **LLMs don't understand, they predict.** They reproduce statistical
patterns, so they fail on multi-step reasoning and happily emit insecure code. For attacking LLM
*applications* instead, see [[LLM Security MOC]].

## Insecure code generation

- Human-in-the-loop AI code was **not** measurably less secure in a user study — because humans still
  authored most bugs and filtered many unsafe suggestions. On **autopilot** (no human edits), ~**40%** of
  raw security-relevant suggestions contained CWEs.
- **CWEs per LoC** (with a non-inferiority margin) is the right normalised metric — more code shouldn't
  mean "more bugs" by construction. It measures *potential* vulnerabilities, not confirmed exploitability.
- **Trusted Computing Base (TCB):** placement matters. AI code in a kernel or crypto module can undermine
  the whole system; fine for peripheral tasks, dangerous in the TCB.

## Bug repair, reverse engineering

- LLMs fix **localised, well-known bugs** but fail on logic / multi-file errors (races, synchronisation),
  and sometimes introduce new ones. They fill a gap fuzzers (show a bug exists, not where) and static
  analysers (point at bugs, not repairs) leave open.
- For reverse engineering they summarise disassembly, map APIs and describe behaviour — a usability win —
  but stay surface-level: they don't rebuild control flow or infer timing. They generalise *linguistically*, not logically.

## Malware generation and jailbreaks

- **Divide-and-conquer / "malware building-blocks":** ask for small, individually-harmless pieces
  (persistence, exfiltration) and assemble them — the model never "breaks policy" on any single request.
  This mirrors **prompt engineering** around guardrails; **jailbreaking** tries to break them outright. See [[LLM Jailbreaking]].
- **Attack-as-a-Service (AaaS):** classic exploit kits ship the same payload; LLM-backed services generate
  **fresh unique variants** per request. With server-side polymorphism, signature detection collapses — a
  kind of reverse concept drift where attackers evolve faster than defenders retrain. See [[Concept Drift and Evolution]].

## LLM-driven attack agents

An LLM becomes an **orchestrator**, not just an exploit writer. A representative agent (AutoAttacker) has
four modules: **Summarizer** (track state), **Planner** (choose next step), **Navigator** (run/select
commands), **Experience Manager** (store & reuse past successes = **RAG** long-term memory). This turns a
chatbot into an operator that plans, executes and learns across a full post-breach workflow — a force
multiplier for small red teams, and a risk if the agent itself is compromised.

## How It Relates

- [[ML Data Poisoning and Backdoors]] — TrojanPuzzle poisons code-suggestion models
- [[LLM Security MOC]] — attacking LLM applications (prompt injection, jailbreaking, recon)

## References
- CSCE 704 — Asleep at the Keyboard; Lost at C; Examining Zero-Shot Vulnerability Repair; Pop Quiz!; TrojanPuzzle; GPThreats-3; AutoAttacker

---
*Based on my own notes from **CSCE 704 — Data Analytics for Cybersecurity** (Dr. Marcus Botacin, Texas A&M University). The synthesis and wording are mine; the paper selection and course framing are his.*
