---
title: "LLM Scanning Tools"
created: 2026-11-17
type: tool
tags: [llm, tools, tool]
---

Automated tools for comprehensive LLM vulnerability coverage — systematically probing hundreds of attack vectors.

## Garak

Open-source LLM vulnerability scanner (NVIDIA). Runs modular **probes** paired with **detectors** that evaluate responses.

**Tests:** Prompt injection, jailbreaks, hallucination, data leakage, toxicity, system prompt extraction.

```bash
pip install garak

# Run specific probe
python3 -m garak --model_type ollama \
  --model_name llama3:8b \
  --probes dan.DAN_Jailbreak

# Run all DAN variants
python3 -m garak --model_type ollama \
  --model_name llama3:8b \
  --probes dan

# System prompt extraction
python3 -m garak --model_type ollama \
  --model_name llama3:8b \
  --probes sysprompt_extraction
```

Multiple detectors evaluate each probe in parallel. A single response can PASS one detector and FAIL another. Use FAIL categories to prioritize manual follow-up.

## PyRIT (Microsoft)

Programmatic red-teaming framework. Define a **target** and an **orchestrator**, then run attack campaigns.

```bash
pip install pyrit
```

- Multi-turn attack orchestration (includes `CrescendoOrchestrator`)
- Automated adversarial prompt generation
- Supports Azure OpenAI, OpenAI, Ollama, custom HTTP endpoints

## promptfoo

CLI tool designed for **CI/CD pipeline integration**:

```bash
npm install -g promptfoo
promptfoo redteam run
```

Generates `redteam.yaml` config, runs jailbreak, injection, PII leakage, toxicity tests. Outputs structured reports for ongoing automated testing.

## Tool Comparison

| Tool | Architecture | Best for |
|------|-------------|----------|
| **Garak** | Probe + detector modules | Quick vulnerability scanning |
| **PyRIT** | Target + orchestrator | Complex multi-turn campaigns |
| **promptfoo** | CLI + YAML config | CI/CD pipeline integration |

## Burp Suite for LLM Endpoints

LLM API endpoints are HTTP POST with JSON — standard Burp workflow:

- Intercept request to `/v1/chat/completions`
- Repeater: modify the `messages` array with injection payloads
- Intruder: fuzz the `content` field systematically
- **AI Prompt Fuzzer** BApp extension automates prompt injection fuzzing

## Related Notes

- [[LLM Prompt Injection]] — what these tools test for
- [[LLM Jailbreaking]] — jailbreak techniques automated by garak/PyRIT
- [[LLM Reconnaissance]] — finding the target first
