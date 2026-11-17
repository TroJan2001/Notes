---
title: "LLM Reconnaissance"
created: 2026-11-17
type: concept
tags: [llm, reconnaissance, concept]
---

AI serving frameworks run on well-known default ports and are rarely moved. A targeted scan reveals services that standard web scans miss entirely.

## Default Ports

| Service | Port(s) | Notes |
|---------|---------|-------|
| **Ollama** | 11434 | Local LLM runner, OpenAI-compatible API, **no auth by default** |
| **TorchServe** | 8080, 8081, 8082 | Inference, management, metrics |
| **Triton** (NVIDIA) | 8000, 8001, 8002 | HTTP, gRPC, metrics |
| **TF Serving** | 8500, 8501 | TensorFlow gRPC + REST |
| **MLflow** | 5000 | Model registry & experiment tracker |
| **vLLM** | 8000 | High-throughput LLM serving |
| **Jupyter** | 8888 | Often deployed unauthenticated alongside AI infra |

Targeted scan:
```bash
nmap -sV -p 5000,8000,8001,8002,8080,8081,8082,8888,11434 <TARGET>
```

Nmap's signature database doesn't cover most AI frameworks — services show as `unknown`. Confirm with direct queries:
```bash
curl -s http://<TARGET>:11434/        # "Ollama is running"
curl -si http://<TARGET>:5000/ | grep -i server  # "Server: uvicorn" (MLflow)
```

## Fingerprinting via HTTP Headers

| Header | Identifies |
|--------|-----------|
| `Server: torchserve` | TorchServe |
| `Server: uvicorn` | vLLM, MLflow, or custom-wrapped models |
| `x-litellm-version` | LiteLLM proxy |
| `x-request-id` (UUID format) | OpenAI-compatible endpoint |

## Model Listing Endpoints

Most frameworks expose these **unauthenticated**:
```bash
curl -s http://<TARGET>:11434/api/tags      # Ollama native
curl -s http://<TARGET>:11434/v1/models     # OpenAI-compatible
```

Standard chat endpoint (OpenAI-compatible):
```
POST /v1/chat/completions
```

## Ollama Unauthenticated API

Full API exposed with no auth by default:

| Endpoint | Method | Reveals |
|----------|--------|---------|
| `/api/tags` | GET | All models on the server |
| `/api/ps` | GET | Running models + memory usage |
| `/api/show` | POST | Full model config **including system prompt** |

```bash
curl -s -X POST http://<TARGET>:11434/api/show \
  -H "Content-Type: application/json" \
  -d '{"name": "llama3:8b"}'
```

The `system` field contains the infrastructure-level system prompt — hidden instructions without sending a single message.

## MLflow Unauthenticated API

No auth by default. Exposes the entire model development history:

```bash
# List experiments
curl -s http://<TARGET>:5000/api/2.0/mlflow/experiments/list

# List registered models
curl -s http://<TARGET>:5000/api/2.0/mlflow/registered-models/list

# Get model versions with filesystem paths
curl -s http://<TARGET>:5000/api/2.0/mlflow/model-versions/search
```

The `source` field reveals server filesystem paths — combined with path traversal CVEs:
- **CVE-2023-6909** — path traversal in artifact retrieval → arbitrary file read
- **CVE-2023-1177** — path traversal in tracking server → unauthenticated arbitrary file read

## Shodan Dorks

```
"ollama" port:11434
http.title:"MLflow" port:5000
"uvicorn" "/predict"
"x-request-id" "/v1/chat/completions"
```

## Related Notes

- [[System Prompt Extraction]] — extracting hidden instructions
- [[LLM Prompt Injection]] — exploiting the model
- [[LLM Scanning Tools]] — automated vulnerability scanning
