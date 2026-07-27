import os

class Config:
    GENAI_API_KEY = os.environ.get("GENAI_API_KEY", "")
    GENAI_BASE_URL = os.environ.get("GENAI_BASE_URL", "https://genailab.tcs.in/").rstrip('/')
    
    # Models mapped to TCS GenAI Lab Gateway
    MODEL_REASONING = "azure_ai/genailab-maas-Phi-4-reasoning"
    MODEL_VISION_OCR = "azure/genailab-maas-gpt-4o"
    MODEL_FAST_CHAT = "azure_ai/genailab-maas-DeepSeek-V3-0324"
    MODEL_EMBEDDINGS = "azure/genailab-maas-text-embedding-3-large"
    MODEL_STT = "whisper-1"
    MODEL_TTS = "tts-1"

    # SQLite Database Path
    DB_PATH = os.path.join(os.path.dirname(__file__), "data", "cyber_threats.db")
