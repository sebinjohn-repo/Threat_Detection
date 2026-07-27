# 🔬 CyberGuard AI: Model Pipeline & AI Architecture

This document details the AI model selection, prompt engineering strategies, local PII privacy guardrails, and RAG vector pipeline for **CyberGuard AI**.

---

## 🌐 TCS GenAI Lab Gateway Model Assignment

We map model selection directly to the official TCS Gateway APIs available at `https://genailab.tcs.in/`:

| Component | Swagger Endpoint | TCS Model Selected | Rationale |
| :--- | :--- | :--- | :--- |
| **Master Orchestrator** | `/v1/chat/completions` | `azure_ai/genailab-maas-Phi-4-reasoning` | High-level logical planning, multi-agent decomposition, threat score synthesis |
| **Anomaly & Zero-Day Agent** | `/v1/chat/completions` | `azure/genailab-maas-gpt-4o` | Multimodal vision OCR for log screenshots, structured code vulnerability auditing |
| **Threat Intel & RAG Agent** | `/v1/chat/completions` | `azure_ai/genailab-maas-DeepSeek-V3-0324` | Ultra-fast context synthesis over retrieved RAG documents & SQLite MCP tables |
| **Response Playbook Agent** | `/v1/chat/completions` | `azure_ai/genailab-maas-Phi-4-reasoning` | Decision-tree evaluation of containment steps and human oversight triggers |
| **Forensics Documentation Agent**| `/v1/chat/completions` | `azure_ai/genailab-maas-DeepSeek-V3-0324` | Fast generation of formal markdown reports and evidence timelines |
| **RAG Vector Embeddings** | `/v1/embeddings` | `azure/genailab-maas-text-embedding-3-large` | Standard 1536-dimensional float vector embeddings for semantic search |
| **Speech-to-Text (STT)** | `/v1/audio/transcriptions` | `whisper-1` | Transcribing analyst voice queries |
| **Text-to-Speech (TTS)** | `/v1/audio/speech` | `tts-1` | Synthesizing alert voice readbacks |

---

## 🛡️ Zero-Trust Data Privacy Guardrail Pipeline

```
[ Raw Security Log / Prompt ] 
            │
            ▼
┌───────────────────────────────────────────┐
│     LOCAL PRIVACY GUARDRAIL (Python)      │
│  • IPv4 / IPv6 Regex -> [ANON_IP_N]       │
│  • User Emails Regex -> [ANON_EMAIL_N]    │
│  • Credentials Regex -> [REDACTED_SECRET] │
│  • Prompt Injection Keyword Filtering    │
└─────────────────────┬─────────────────────┘
                      │
                      ▼
         [ Sanitized Safe Prompt ] 
                      │
                      ▼ (Passed to TCS LLM APIs)
       ┌──────────────────────────────┐
       │   TCS GENAI GATEWAY LLMs     │
       └──────────────┬───────────────┘
                      │
                      ▼ (Raw Response)
┌───────────────────────────────────────────┐
│        LOCAL RE-HYDRATION ENGINE          │
│ Replaces [ANON_IP_N] back to original IP  │
│ for local SOC Analyst display             │
└─────────────────────┬─────────────────────┘
                      │
                      ▼
        [ Full UI Dashboard Render ]
```

---

## 🗄️ Local MCP SQLite & Vector RAG Pipeline

1. **Local MCP SQLite Server (`mcp_sqlite_server.py`)**:
   - Stores local threat signatures (`CVE-2024-3094`, `CVE-2023-34362`), MITRE ATT&CK techniques, user behavioral baselines, and incident response playbooks locally.
   - MCP tools expose functions (`query_sqlite_logs`, `search_threat_intel`, `fetch_playbook`) to LLM subagents without exposing raw database handles.

2. **FAISS Vector RAG Engine (`rag_service.py`)**:
   - Generates float vector embeddings using TCS `azure/genailab-maas-text-embedding-3-large`.
   - Computes cosine similarity scores to retrieve relevant MITRE ATT&CK mitigation context and attach citations to copilot Q&A answers.
