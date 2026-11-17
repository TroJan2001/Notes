---
title: "LLM Security MOC"
created: 2026-11-17
type: moc
tags: [llm, moc]
---

# AI & LLM Security

## Reconnaissance
- [[LLM Reconnaissance]] — default ports, fingerprinting, Ollama/MLflow APIs, Shodan dorks, CVEs

## Attack Techniques
- [[System Prompt Extraction]] — direct request, roleplay framing, error induction, creative formats
- [[LLM Prompt Injection]] — direct vs indirect injection, why it works, CVE-2023-29374 (injection → RCE)
- [[LLM Jailbreaking]] — RLHF bypass, DAN/persona, encoding/obfuscation, Crescendo multi-turn

## Tools
- [[LLM Scanning Tools]] — garak, PyRIT, promptfoo, Burp Suite for LLM endpoints

## Classification
- [[OWASP LLM Top 10]] — 2025 framework for reporting LLM findings
