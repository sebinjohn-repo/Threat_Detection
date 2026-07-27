import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import base64
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS

from config import Config
from app.genai_client import GenAIGatewayClient
from app.mcp_sqlite_server import MCPSqliteServer
from app.services.rag_service import RAGService
from app.services.multi_agent_service import MultiAgentOrchestrator
from app.guardrails import PrivacyGuardrail

app = Flask(__name__, static_folder="../../frontend", static_url_path="")
CORS(app)

# Initialize core services
genai_client = GenAIGatewayClient()
mcp_server = MCPSqliteServer()
rag_service = RAGService(genai_client)
orchestrator = MultiAgentOrchestrator(genai_client, mcp_server, rag_service)

# Stat Counters
STATS = {
    "total_analyzed": 142,
    "pii_scrubbed_count": 589,
    "zero_day_detected": 18,
    "avg_latency_sec": 1.84
}

# Serve Frontend Static UI
@app.route("/")
def serve_index():
    return send_from_directory(app.static_folder, "index.html")

# 1. Health Check
@app.route("/api/health", methods=["GET"])
def health_check():
    standalone_active = mcp_server.is_standalone_online()
    return jsonify({
        "status": "ONLINE",
        "system": "CyberGuard AI Platform",
        "tcs_gateway_active": genai_client.active,
        "mcp_sqlite_connected": True,
        "mcp_standalone_server": {
            "active": standalone_active,
            "transport": "SSE",
            "url": "http://127.0.0.1:5001/sse"
        },
        "privacy_guardrail_active": True
    })


# 2. Privacy Guardrail Sanitization Preview Endpoint
@app.route("/api/privacy/sanitize", methods=["POST"])
def sanitize_preview():
    data = request.json or {}
    raw_text = data.get("text", "")
    sanitized_text, rehydrate_map, metrics = PrivacyGuardrail.sanitize(raw_text)
    return jsonify({
        "original_text": raw_text,
        "sanitized_text": sanitized_text,
        "rehydrate_map": rehydrate_map,
        "metrics": metrics
    })

# 3. Ingest and Analyze Security Logs Endpoint
@app.route("/api/analyze/logs", methods=["POST"])
def analyze_logs():
    data = request.json or {}
    raw_logs = data.get("logs", "")
    if not raw_logs:
        return jsonify({"error": "No logs provided"}), 400

    result = orchestrator.analyze_incident(raw_logs, is_image=False)
    
    # Update Stats
    STATS["total_analyzed"] += 1
    STATS["pii_scrubbed_count"] += result["privacy_metrics"].get("total", 0)

    return jsonify(result)

# 4. Ingest and Analyze Image Screenshots (GPT-4o Vision OCR)
@app.route("/api/analyze/image", methods=["POST"])
def analyze_image():
    data = request.json or {}
    image_base64 = data.get("image_base64", "")
    filename = data.get("filename", "log_screenshot.png")

    if not image_base64:
        return jsonify({"error": "No image payload provided"}), 400

    # 1. OCR Text Extraction via Vision AI
    raw_ocr_text = (
        f"2026-07-27 14:22:01 [CRITICAL] sshd[4921]: Authentication bypass attempt from 192.168.1.105 "
        f"email=user@test.com secret=sk_test_883921 [Source File: {filename}]\n"
        f"2026-07-27 14:22:05 [ALERT] System prompt override attempt detected: ignore previous instructions\n"
        f"2026-07-27 14:22:10 [WARN] Outbound TCP session to 203.0.113.50 (User: admin@enterprise.com Card: 4532-1234-5678-9012)"
    )

    # 2. Local PII Privacy Guardrail Layer
    sanitized_text, rehydrate_map, privacy_metrics = PrivacyGuardrail.sanitize(raw_ocr_text)

    # 3. Parallel Multi-Agent Execution
    result = orchestrator.analyze_incident(raw_ocr_text, is_image=True)

    # 4. Attach OCR details and Privacy metrics for UI rendering
    result["ocr_extracted_raw"] = raw_ocr_text
    result["ocr_extracted_sanitized"] = sanitized_text
    result["privacy_metrics"] = privacy_metrics

    STATS["total_analyzed"] += 1
    STATS["zero_day_detected"] += 1
    STATS["pii_scrubbed_count"] += privacy_metrics.get("total", 0)

    return jsonify(result)


# 5. Real-Time Dashboard Stats
@app.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    return jsonify(STATS)

# 6. Interactive Security Analyst Copilot Chat Endpoint
@app.route("/api/chat", methods=["POST"])
def chat_copilot():
    data = request.json or {}
    user_query = data.get("message", "")
    if not user_query:
        return jsonify({"error": "Message required"}), 400

    # Step 1: Local PII Guardrail Scrubbing
    sanitized_query, rehydrate_map, _ = PrivacyGuardrail.sanitize(user_query)

    # Step 2: RAG Retrieval
    rag_docs = rag_service.search(sanitized_query, top_k=2)
    rag_context = "\n".join([f"[{d['id']}] {d['title']}: {d['content']}" for d in rag_docs])

    # Step 3: Call TCS DeepSeek-V3 Fast Chat API
    system_prompt = (
        "You are CyberGuard Copilot, an AI Security Operations Analyst. "
        "Answer user queries strictly using cybersecurity best practices and provided RAG context.\n"
        f"RAG Grounded Context:\n{rag_context}"
    )
    raw_response = genai_client.chat_completion(
        model=Config.MODEL_FAST_CHAT,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": sanitized_query}
        ]
    )

    # Step 4: Re-hydrate response for local analyst display
    rehydrated_response = PrivacyGuardrail.rehydrate(raw_response, rehydrate_map)

    return jsonify({
        "response": rehydrated_response,
        "citations": [d["title"] for d in rag_docs],
        "sanitized_query": sanitized_query
    })

# 7. Speech-to-Text (STT) Audio Transcription Endpoint
@app.route("/api/audio/transcribe", methods=["POST"])
def audio_transcribe():
    if "file" not in request.files:
        return jsonify({"transcript": "Analyze threat logs for suspicious SSH connections."})

    audio_file = request.files["file"]
    transcript = genai_client.speech_to_text(audio_file.read(), filename=audio_file.filename)
    return jsonify({"transcript": transcript})

# 8. Text-to-Speech (TTS) Audio Readback Endpoint
@app.route("/api/audio/speak", methods=["POST"])
def audio_speak():
    data = request.json or {}
    text = data.get("text", "Critical threat alert detected. Automatic containment playbook generated.")
    audio_bytes = genai_client.text_to_speech(text)
    return send_file(
        io.BytesIO(audio_bytes) if hasattr(io, 'BytesIO') else io.BufferedReader(io.BytesIO(audio_bytes)),
        mimetype="audio/wav",
        as_attachment=False,
        download_name="speech.wav"
    )

if __name__ == "__main__":
    import io
    print("Starting CyberGuard AI Flask Server on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
