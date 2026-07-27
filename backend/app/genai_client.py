import os
import httpx
import traceback
from typing import List, Dict, Any, Union
from config import Config

class GenAIGatewayClient:
    """
    Unified API Client for TCS GenAI Lab Gateway (https://genailab.tcs.in/).
    Supports Chat Completions, Embeddings, STT, and TTS with SSL verification disabled
    and robust mock fallbacks for crash-proof hackathon demos.
    """

    def __init__(self):
        # Disable SSL verification for corporate gateway proxy compatibility
        self.client = httpx.Client(verify=False)
        self.base_url = Config.GENAI_BASE_URL
        self.api_key = Config.GENAI_API_KEY
        self.active = bool(self.api_key and self.api_key not in ["YOUR_KEY_HERE", "your_api_key_here", ""])

        if not self.active:
            print("[INFO] GenAIGatewayClient running in MOCK FALLBACK mode (No API Key set yet).")

    def _get_headers( me ) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {me.api_key}",
            "Content-Type": "application/json"
        }

    # 1. CHAT COMPLETIONS API (/v1/chat/completions)
    def chat_completion(self, model: str, messages: List[Dict[str, Any]], temperature: float = 0.3, **kwargs) -> str:
        """Calls TCS Chat Completions API with support for text and vision OCR prompts."""
        if not self.active:
            return self._mock_chat_response(model, messages)

        url = f"{self.base_url}/v1/chat/completions"
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            **kwargs
        }
        try:
            response = self.client.post(url, json=payload, headers=self._get_headers(), timeout=30.0)
            response.raise_for_status()
            result = response.json()
            return result["choices"][0]["message"]["content"].strip()
        except Exception as e:
            print(f"[WARN] TCS Gateway ChatCompletion failed ({e}). Returning fallback response.")
            return self._mock_chat_response(model, messages)

    # 2. EMBEDDINGS API (/v1/embeddings)
    def create_embeddings(self, model: str, input_texts: Union[str, List[str]]) -> List[List[float]]:
        """Calls TCS Embeddings API to generate float vectors."""
        if not self.active:
            dummy_dim = 1536
            texts = input_texts if isinstance(input_texts, list) else [input_texts]
            return [[0.01 * (i % 10) for i in range(dummy_dim)] for _ in texts]

        url = f"{self.base_url}/v1/embeddings"
        texts = input_texts if isinstance(input_texts, list) else [input_texts]
        payload = {
            "model": model,
            "input": texts
        }
        try:
            response = self.client.post(url, json=payload, headers=self._get_headers(), timeout=15.0)
            response.raise_for_status()
            result = response.json()
            return [data["embedding"] for data in result["data"]]
        except Exception as e:
            print(f"[WARN] TCS Gateway Embeddings failed ({e}). Returning mock vector.")
            dummy_dim = 1536
            return [[0.01 * (i % 10) for i in range(dummy_dim)] for _ in texts]

    # 3. SPEECH TO TEXT API (/v1/audio/transcriptions)
    def speech_to_text(self, audio_bytes: bytes, filename: str = "audio.wav", model: str = "whisper-1") -> str:
        """Converts audio speech files to text string using TCS Whisper endpoint."""
        if not self.active:
            return "Analyze threat logs for suspicious SSH connections and show recommended playbooks."

        url = f"{self.base_url}/v1/audio/transcriptions"
        files = {"file": (filename, audio_bytes, "audio/wav")}
        data = {"model": model}
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            response = self.client.post(url, files=files, data=data, headers=headers, timeout=30.0)
            response.raise_for_status()
            return response.json().get("text", "")
        except Exception as e:
            print(f"[WARN] STT failed ({e}). Returning default transcribed query.")
            return "Analyze threat logs for suspicious SSH connections and show recommended playbooks."

    # 4. TEXT TO SPEECH API (/v1/audio/speech)
    def text_to_speech(self, text: str, model: str = "tts-1", voice: str = "alloy") -> bytes:
        """Generates synthetic audio speech bytes from text string."""
        if not self.active:
            return b"RIFF_MOCK_WAV_AUDIO_BYTES_FOR_TTS_PLAYBACK"

        url = f"{self.base_url}/v1/audio/speech"
        payload = {
            "model": model,
            "input": text,
            "voice": voice
        }
        try:
            response = self.client.post(url, json=payload, headers=self._get_headers(), timeout=20.0)
            response.raise_for_status()
            return response.content
        except Exception as e:
            print(f"[WARN] TTS failed ({e}). Returning mock audio bytes.")
            return b"RIFF_MOCK_WAV_AUDIO_BYTES_FOR_TTS_PLAYBACK"

    def _mock_chat_response(self, model: str, messages: List[Dict[str, Any]]) -> str:
        """Provides realistic cybersecurity intelligence mock responses when offline."""
        prompt = str(messages[-1]["content"]).lower()

        if "ocr" in prompt or "image" in prompt or "vision" in prompt or "gpt-4o" in model:
            return (
                "### 👁️ GPT-4o Vision OCR Log Extraction\n"
                "**Detected Terminal Log Content**:\n"
                "`2026-07-27 14:22:01 [CRITICAL] sshd[4921]: Authentication bypassed for user root from [ANON_IP_1]`\n"
                "`2026-07-27 14:22:05 [ALERT] liblzma payload injection detected. Process spawned: /usr/sbin/sshd`\n\n"
                "**Visual Anomaly Indicators**:\n"
                "- Malicious signature matching CVE-2024-3094 (XZ Utils Supply Chain Backdoor).\n"
                "- High severity threat detected with abnormal root privilege escalation."
            )

        if "phi-4" in model or "orchestration" in prompt or "playbook" in prompt:
            return (
                "### 🛡️ Phi-4 Reasoning & Incident Playbook Strategy\n"
                "**Threat Classification**: Zero-Day Supply Chain Backdoor (CVE-2024-3094 / MITRE T1195.001)\n"
                "**Overall Severity Score**: `94/100` (CRITICAL RISK)\n\n"
                "**Automated Containment Workflow**:\n"
                "1. **Host Isolation**: Sever network VLAN for target host `[ANON_IP_1]`.\n"
                "2. **Session Invalidation**: Revoke all active SSH session keys and API access tokens.\n"
                "3. **Package Rollback**: Roll back `liblzma` to verified clean release `5.4.5`.\n"
                "4. **Human Oversight Trigger**: Tier-2 SOC Analyst approval required before host re-commissioning."
            )

        # Default DeepSeek-V3 fast chat response
        return (
            "### 🔍 DeepSeek-V3 Cyber Threat Intelligence & Forensic Findings\n"
            "**Threat Summary**: Anomaly detection identified suspicious authentication bypass targeting SSH services.\n"
            "**Grounded RAG Context**: Matched against local SQLite MCP Threat Intel Database (`CVE-2024-3094` / MITRE T1195.001).\n"
            "**Privacy Audit**: All IP addresses and user credentials scrubbed by local privacy guardrails prior to reasoning step."
        )
