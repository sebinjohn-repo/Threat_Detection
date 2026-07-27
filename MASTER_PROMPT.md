# 🛡️ MASTER PROMPT: AI-Powered Threat Detection & Response System (CyberGuard AI)

You are tasked with building a full-stack, crash-proof, AI-Powered Cybersecurity Threat Detection and Response Platform named "CyberGuard AI" for a hackathon.

Follow the instructions below to create the entire application structure inside the current project directory, using the template structure in `./hackathon-templates/`.

---

## 🌐 TCS GenAI Gateway Integration Specs (https://genailab.tcs.in/)

Implement `GenAIGatewayClient` in `backend/app/genai_client.py` targeting the exact TCS Gateway endpoints:

1. **Chat API (`/v1/chat/completions`)**:
   - `azure_ai/genailab-maas-Phi-4-reasoning`: For Orchestrator & Response Playbook Agent logic.
   - `azure/genailab-maas-gpt-4o`: For Anomaly & Zero-Day Detection Agent (including base64 Vision OCR log images).
   - `azure_ai/genailab-maas-DeepSeek-V3-0324`: For Threat Intel synthesis & Forensic Documentation generation.
2. **Embeddings API (`/v1/embeddings`)**:
   - `azure/genailab-maas-text-embedding-3-large`: Generates float vector embeddings for RAG vector search.
3. **Speech-to-Text API (`/v1/audio/transcriptions`)**:
   - `whisper-1`: For audio file transcription.
4. **Text-to-Speech API (`/v1/audio/speech`)**:
   - `tts-1`: For generating synthetic voice audio alert readbacks.

---

## 🛠️ Key Architectural Components

### 1. Data Privacy & Guardrail Layer (`backend/app/guardrails.py`)
- Implement a pre-processor module that scrubs all Personal Identifiable Information (PII), confidential user metadata, and credentials BEFORE passing text/logs to TCS GenAI LLM APIs.
- Regex + Rule Scrubbing:
  - Email addresses -> `[ANON_EMAIL_N]`
  - IPv4/IPv6 addresses -> `[ANON_IP_N]`
  - Passwords/Tokens/JWTs -> `[REDACTED_SECRET]`
  - Credit Cards / SSNs -> `[REDACTED_PII]`
- Include prompt injection sanitization for ingested security logs.
- Provide a local re-hydration mechanism so SOC analysts see real IP/User context locally on the dashboard while LLMs receive strictly sanitized data.

### 2. Local MCP SQLite Database Server (`backend/app/mcp_sqlite_server.py`)
- Create a local SQLite database (`backend/data/cyber_threats.db`) with tables:
  - `security_events` (timestamp, source_ip, dest_ip, event_type, payload, anomaly_score)
  - `threat_intel` (threat_id, cve_id, mitre_technique, description, severity, indicator_pattern)
  - `user_baselines` (user_id, avg_daily_logins, typical_location, rare_process_count)
  - `incident_playbooks` (threat_category, response_steps, approval_required, risk_level)
  - `forensic_logs` (incident_id, timestamp, agent_findings, status, action_taken)
- Implement an MCP server wrapper exposing tools:
  - `query_sqlite_logs(query_str, limit)`
  - `search_threat_intel(pattern)`
  - `get_user_baseline(user_id)`
  - `fetch_playbook(threat_category)`
  - `record_forensic_entry(data)`

### 3. RAG Service (`backend/app/services/rag_service.py`)
- Integrate FAISS CPU vector database using `tcs_embeddings.py` (`verify=False` for SSL bypass).
- Index MITRE ATT&CK patterns, threat intelligence feeds, and incident response playbooks using `azure/genailab-maas-text-embedding-3-large`.
- Expose `query_threat_knowledge(query)` with citation outputs.

### 4. Parallel Multi-Agent Orchestrator (`backend/app/services/multi_agent_service.py`)
- Build an orchestrator managing 4 parallel workers using Python `concurrent.futures.ThreadPoolExecutor`:
  1. **Orchestrator Agent** (`azure_ai/genailab-maas-Phi-4-reasoning`): Coordinates parallel execution and synthesizes overall Threat Score (0-100) and Risk Level (Low/Med/High/Critical).
  2. **AnomalyDetectorAgent** (`azure/genailab-maas-gpt-4o`): Evaluates log anomaly scores, behavioral baseline deviations, and parses uploaded log screenshots via GPT-4o Vision OCR.
  3. **ThreatIntelRAGAgent** (`azure_ai/genailab-maas-DeepSeek-V3-0324` + SQLite MCP): Performs RAG vector search over MITRE ATT&CK patterns and queries local SQLite MCP database.
  4. **ResponsePlaybookAgent** (`azure_ai/genailab-maas-Phi-4-reasoning`): Recommends automated incident containment playbooks with human oversight approval prompts.
  5. **ForensicsReporterAgent** (`azure_ai/genailab-maas-DeepSeek-V3-0324`): Generates structured markdown incident documentation and timeline reports.

### 5. Flask API Routes (`backend/app/main.py`)
- Implement endpoints:
  - `POST /api/health` -> Service check
  - `POST /api/privacy/sanitize` -> Tests PII anonymization
  - `POST /api/analyze/logs` -> Ingests text/JSON logs, anonymizes, triggers multi-agent pipeline
  - `POST /api/analyze/image` -> Takes base64 image (log screenshot / Wireshark capture), calls `azure/genailab-maas-gpt-4o` for OCR log extraction, and passes to analysis pipeline
  - `GET /api/dashboard/stats` -> Returns real-time metrics (Total threats analyzed, PII scrubbed count, Avg triage time, Zero-day detections)
  - `POST /api/chat` -> Interactive security analyst copilot with RAG grounding
  - `POST /api/audio/transcribe` -> Handles voice STT transcription
  - `POST /api/audio/speak` -> Generates TTS audio output

### 6. Frontend UI (Glassmorphic Slate-Dark Dashboard + Voice/OCR Chat)
- Build an Angular or HTML5/CSS3 Single Page Web App using `hackathon-templates/frontend/glassmorphism_styles.scss`.
- Features:
  - **Live Threat Metrics HUD**: Visual cards for Active Alerts, PII Scrubbed Count, Zero-Day Threat Gauges.
  - **Log Ingestion & Multimodal Upload**:
    - File/Image dropzone for uploading Wireshark/Terminal screenshots (triggers OCR via `/api/analyze/image`).
    - Raw text log paste box with instant "Privacy Sanitization Preview" (showing anonymized vs original logs).
  - **Voice Interactive Security Copilot**:
    - HTML5 Speech-to-Text (STT) mic button for hands-free queries.
    - Text-to-Speech (TTS) speaker playback toggle to hear generated alert summaries.
  - **Multi-Agent Breakdown Panel**: Visual cards showing parallel execution outputs from Anomaly Detector, Threat Intel RAG, Response Playbook, and Forensics Report.

---

## ⚡ Offline Demo Fallbacks (Crash-Proof Requirement)
- Ensure all LLM API calls, embedding queries, and SQLite tools have try/catch blocks that gracefully return realistic mock threat intelligence data from `sample_mock_data.json` if API keys fail or network connectivity drops.

---

## 📂 Output Deliverables
Upon completing the code implementation, generate the following markdown documents:
1. `README.md` (Setup instructions & architecture overview)
2. `MODEL_PIPELINE.md` (Detailed breakdown of GPT-4o OCR, DeepSeek-V3 fast chat, Phi-4 reasoning, Embedding-3-large, and local PII guardrails)
3. `PRESENTATION_SLIDES.md` (Complete slide deck for 5-minute presentation)
4. `DEMO_SCRIPT.md` (Strict 5-minute timed demo script following official TCS guidelines)
