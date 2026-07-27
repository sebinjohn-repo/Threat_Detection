# 🛡️ CyberGuard AI: AI-Powered Threat Detection and Response System

**CyberGuard AI** is an enterprise-grade cybersecurity platform built for the TCS GenAI Lab Hackathon. It leverages parallel multi-agent LLM orchestration, local data privacy guardrails, local Model Context Protocol (MCP) SQLite database tools, vector RAG threat intelligence, and multimodal voice/OCR capabilities.

---

## 🌟 Key Features & Innovations

1. **Strict Data Privacy Guardrail Layer (`0% PII Leakage`)**:
   - Local regex & NER pre-processor that scrubs IP addresses, email accounts, passwords, API tokens, and financial PII before sending prompts to external LLMs.
   - Includes local re-hydration so SOC analysts see real IP/User context locally on the dashboard while LLMs receive strictly sanitized data.

2. **Local Model Context Protocol (MCP) SQLite DB Server**:
   - Exposes local SQLite database (`cyber_threats.db`) tools (`query_sqlite_logs`, `search_threat_intel`, `get_user_baseline`, `fetch_playbook`, `record_forensic_entry`).

3. **Parallel Multi-Agent Orchestration**:
   - Uses Python `ThreadPoolExecutor` to run 4 specialized subagents concurrently:
     - **Orchestrator Agent**: `azure_ai/genailab-maas-Phi-4-reasoning`
     - **1. Anomaly & Zero-Day Detection Agent**: `azure/genailab-maas-gpt-4o`
     - **2. Threat Intel & RAG Agent**: `azure_ai/genailab-maas-DeepSeek-V3-0324` + `azure/genailab-maas-text-embedding-3-large`
     - **3. Automated Response Playbook Agent**: `azure_ai/genailab-maas-Phi-4-reasoning`
     - **4. Forensics & Documentation Agent**: `azure_ai/genailab-maas-DeepSeek-V3-0324`

4. **Multimodal Glassmorphic UI with Voice & OCR**:
   - **GPT-4o Vision OCR**: Drag and drop Wireshark / terminal log screenshots for automatic text extraction.
   - **Speech-to-Text (STT)**: Hands-free voice commands using Web Speech API / TCS Whisper endpoint.
   - **Text-to-Speech (TTS)**: Voice speaker readback of generated alert summaries.

---

## 📂 Project Architecture

```
Threat_Detection/
├── MASTER_PROMPT.md                   # Master system prompt
├── README.md                          # Source code setup & run instructions
├── MODEL_PIPELINE.md                  # Model pipeline & RAG documentation
├── PRESENTATION_SLIDES.md             # Pitch presentation slide deck
├── DEMO_SCRIPT.md                     # Timed 5-minute hackathon pitch script
├── backend/
│   ├── config.py                      # TCS GenAI Lab Gateway configuration & models
│   ├── app/
│   │   ├── main.py                    # Flask API routes
│   │   ├── guardrails.py              # Local PII privacy & prompt injection layer
│   │   ├── mcp_sqlite_server.py       # Local MCP SQLite server & tool wrappers
│   │   ├── genai_client.py            # TCS Gateway client (Chat, Embeddings, STT, TTS)
│   │   └── services/
│   │       ├── rag_service.py         # FAISS RAG vector search engine
│   │       └── multi_agent_service.py # Parallel ThreadPoolExecutor multi-agent orchestrator
│   └── data/
│       └── cyber_threats.db           # Local SQLite database
└── frontend/
    ├── index.html                     # Slate-dark Glassmorphic UI layout
    ├── styles.css                     # SCSS-inspired neon dark-slate tokens
    └── app.js                         # Frontend client engine (Voice STT/TTS, OCR, Chat)
```

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.9+
- Recommended packages: `flask`, `flask-cors`, `httpx`

### 1. Install Dependencies
```bash
pip install flask flask-cors httpx
```

### 2. Set TCS GenAI API Key (Optional / Offline Fallbacks Included)
Set your TCS GenAI Gateway API key in environment or `backend/config.py`:
```bash
export GENAI_API_KEY="your_tcs_genai_api_key"
```

### 3. Run Application
```bash
python backend/app/main.py
```
Open your browser and navigate to: **`http://localhost:5000`**

---

## 🧪 Verification & Crash-Proof Design
If no API key is provided, CyberGuard AI automatically activates **Offline Crash-Proof Fallbacks** using realistic mock data so the app remains fully functional for live hackathon demonstrations.
