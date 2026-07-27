import math
from typing import List, Dict, Any
from config import Config
from app.genai_client import GenAIGatewayClient

class RAGService:
    """
    Retrieval-Augmented Generation (RAG) Service for Cyber Threat Intelligence.
    Uses TCS Embeddings API (azure/genailab-maas-text-embedding-3-large)
    to index MITRE ATT&CK techniques, CVE threat feeds, and security playbooks.
    """

    def __init__(self, client: GenAIGatewayClient):
        self.client = client
        self.vector_store: List[Dict[str, Any]] = []
        self._init_knowledge_base()

    def _init_knowledge_base(self):
        """Initializes knowledge documents and generates baseline embeddings."""
        documents = [
            {
                "id": "DOC-001",
                "title": "MITRE ATT&CK T1195.001 - Supply Chain Compromise",
                "content": "Adversaries may manipulate software updates or build pipelines to inject malicious code into trusted packages (e.g. CVE-2024-3094 XZ Utils liblzma injection in sshd). Mitigation requires package signature verification and memory isolation.",
                "category": "MITRE_ATTACK"
            },
            {
                "id": "DOC-002",
                "title": "MITRE ATT&CK T1190 - Exploit Public-Facing Application",
                "content": "Adversaries exploit vulnerabilities in internet-facing web servers or APIs (e.g. MOVEit Transfer SQL Injection CVE-2023-34362). Mitigation involves WAF rate limiting and input parameter sanitization.",
                "category": "MITRE_ATTACK"
            },
            {
                "id": "DOC-003",
                "title": "Incident Response Playbook: Zero-Day Backdoor Containment",
                "content": "Upon detecting zero-day backdoor activity: 1. Immediately sever network access for affected hosts. 2. Revoke active JWT and SSH tokens. 3. Perform memory dump forensics. 4. Deploy patched package.",
                "category": "PLAYBOOK"
            },
            {
                "id": "DOC-004",
                "title": "Threat Intelligence Feed: Citrix Bleed CVE-2023-4966",
                "content": "Buffer overflow vulnerability in NetScaler ADC allows unauthenticated session token leakage. Indicators: Requests to /oauth/idp/.well-known/openid-configuration returning unexpected memory buffers.",
                "category": "THREAT_INTEL"
            }
        ]

        # Generate vectors for documents
        for doc in documents:
            embeddings = self.client.create_embeddings(Config.MODEL_EMBEDDINGS, doc["content"])
            vec = embeddings[0] if embeddings else [0.0] * 1536
            self.vector_store.append({
                "doc": doc,
                "vector": vec
            })

    def search(self, query: str, top_k: int = 2) -> List[Dict[str, Any]]:
        """Performs vector similarity search against indexed threat intelligence."""
        query_embeddings = self.client.create_embeddings(Config.MODEL_EMBEDDINGS, query)
        if not query_embeddings:
            return [item["doc"] for item in self.vector_store[:top_k]]

        q_vec = query_embeddings[0]

        # Compute cosine similarities
        scores = []
        for item in self.vector_store:
            doc_vec = item["vector"]
            similarity = self._cosine_similarity(q_vec, doc_vec)
            scores.append((similarity, item["doc"]))

        # Sort descending by similarity
        scores.sort(key=lambda x: x[0], reverse=True)
        return [doc for score, doc in scores[:top_k]]

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Computes cosine similarity between two float vectors."""
        if len(vec1) != len(vec2) or not vec1:
            return 0.0
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm_a = math.sqrt(sum(a * a for a in vec1))
        norm_b = math.sqrt(sum(b * b for b in vec2))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot_product / (norm_a * norm_b)
