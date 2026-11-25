---
title: "OWASP LLM Top 10"
created: 2026-11-17
type: concept
tags: [llm, owasp, concept]
---

The OWASP LLM Top 10 (2025) is the standard framework for classifying LLM vulnerabilities in pentest reports.

## Categories

| ID | Name | What it covers | MITRE ATLAS |
|----|------|---------------|-------------|
| **LLM01** | Prompt Injection | Direct and indirect injection — overriding model instructions via user input or pre-positioned data | AML.T0051 |
| **LLM02** | Sensitive Information Disclosure | Model leaking PII, credentials, or internal data in responses | — |
| **LLM03** | Supply Chain Vulnerabilities | Compromised models, poisoned training data, malicious plugins | AML.T0010 |
| **LLM04** | Data and Model Poisoning | Manipulating training or fine-tuning data to alter model behavior | — |
| **LLM05** | Improper Output Handling | Downstream systems trusting LLM output without sanitization (XSS, injection via LLM) | — |
| **LLM06** | Excessive Agency | LLM agents with too many permissions or tools, performing unintended actions | AML.T0053 |
| **LLM07** | System Prompt Leakage | Extracting hidden system instructions containing internal details | AML.T0056 |
| **LLM08** | Vector and Embedding Weaknesses | Attacks on RAG pipelines and embedding stores | — |
| **LLM09** | Misinformation | Model generating false but convincing information (hallucination) | — |
| **LLM10** | Unbounded Consumption | Resource exhaustion via crafted prompts (DoS) | — |

## Reporting Template

For each LLM finding, document:
- **OWASP category** (e.g., LLM01, LLM07)
- **Technique used** (e.g., roleplay-framed system prompt extraction)
- **What was extracted or redirected** (e.g., internal server name, API key)
- **Business impact** if exploited in production
- **Remediation** guidance (link to OWASP website for category-specific fixes)

## Key Relationships

- System prompt extraction (LLM07) → maps the target → enables prompt injection (LLM01)
- Prompt injection (LLM01) + excessive agency (LLM06) → unintended real-world actions
- Improper output handling (LLM05) → LLM output used unsanitized → XSS, SQLi via LLM

## Related Notes

- [[LLM Prompt Injection]] — LLM01 techniques
- [[System Prompt Extraction]] — LLM07 techniques
- [[LLM Jailbreaking]] — bypassing safety training
- [[LLM Scanning Tools]] — automated testing against these categories
