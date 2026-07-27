import re
from typing import Dict, Tuple, List

class PrivacyGuardrail:
    """
    Local Data Privacy Guardrail Layer.
    Ensures zero PII, internal IP addresses, user credentials, or financial data
    are sent to external or cloud LLM APIs.
    """

    # Regex patterns for sensitive entity scrubbing
    IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    IPV6_PATTERN = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    CREDENTIAL_PATTERN = r'(?i)\b(?:password|passwd|secret|api[_-]?key|bearer|token)\s*[:=]\s*["\']?([^\s"\'};]+)'
    SSN_FINANCIAL_PATTERN = r'\b(?:\d[ -]*?){13,16}\b'  # Credit cards / SSNs

    @classmethod
    def sanitize(cls, raw_text: str) -> Tuple[str, Dict[str, str], Dict[str, int]]:
        """
        Scrubs sensitive PII from raw_text.
        Returns:
            - sanitized_text (str): Safe text ready to be passed to LLM
            - rehydrate_map (dict): Mapping from anonymized placeholders back to original values
            - metrics (dict): Scrubbing statistics for dashboard HUD
        """
        if not raw_text:
            return "", {}, {"emails": 0, "ips": 0, "secrets": 0, "financial": 0, "total": 0}

        rehydrate_map = {}
        metrics = {"emails": 0, "ips": 0, "secrets": 0, "financial": 0, "total": 0}
        sanitized_text = raw_text

        # 1. Scrub Emails
        emails = list(set(re.findall(cls.EMAIL_PATTERN, sanitized_text)))
        for idx, email in enumerate(emails, 1):
            placeholder = f"[ANON_EMAIL_{idx}]"
            rehydrate_map[placeholder] = email
            sanitized_text = sanitized_text.replace(email, placeholder)
            metrics["emails"] += 1

        # 2. Scrub IP Addresses (IPv4 and IPv6)
        ips = list(set(re.findall(cls.IPV4_PATTERN, sanitized_text) + re.findall(cls.IPV6_PATTERN, sanitized_text)))
        for idx, ip in enumerate(ips, 1):
            # Skip standard localhost/broadcast loopbacks if needed, but scrub all for zero-trust
            placeholder = f"[ANON_IP_{idx}]"
            rehydrate_map[placeholder] = ip
            sanitized_text = sanitized_text.replace(ip, placeholder)
            metrics["ips"] += 1

        # 3. Scrub Credentials / Secrets
        secrets = list(set(re.findall(cls.CREDENTIAL_PATTERN, sanitized_text)))
        for idx, secret in enumerate(secrets, 1):
            placeholder = f"[REDACTED_SECRET_{idx}]"
            rehydrate_map[placeholder] = secret
            sanitized_text = sanitized_text.replace(secret, placeholder)
            metrics["secrets"] += 1

        # 4. Scrub Financial / SSNs
        financials = list(set(re.findall(cls.SSN_FINANCIAL_PATTERN, sanitized_text)))
        for idx, item in enumerate(financials, 1):
            placeholder = f"[REDACTED_PII_{idx}]"
            rehydrate_map[placeholder] = item
            sanitized_text = sanitized_text.replace(item, placeholder)
            metrics["financial"] += 1

        # Calculate Total Scrubbed Items
        metrics["total"] = sum(metrics.values())

        # 5. Check & Sanitize Prompt Injection Vectors
        sanitized_text = cls.sanitize_prompt_injection(sanitized_text)

        return sanitized_text, rehydrate_map, metrics

    @classmethod
    def rehydrate(cls, sanitized_text: str, rehydrate_map: Dict[str, str]) -> str:
        """
        Re-hydrates anonymized placeholders back into their original values
        for local SOC analyst UI rendering.
        """
        if not sanitized_text or not rehydrate_map:
            return sanitized_text

        result = sanitized_text
        for placeholder, original in rehydrate_map.items():
            result = result.replace(placeholder, original)
        return result

    @classmethod
    def sanitize_prompt_injection(cls, text: str) -> str:
        """
        Detects and neutralizes prompt injection override tokens in ingested security logs.
        """
        injection_keywords = [
            r"(?i)ignore previous instructions",
            r"(?i)system prompt:",
            r"(?i)you are now a",
            r"(?i)override instructions"
        ]
        sanitized = text
        for kw in injection_keywords:
            sanitized = re.sub(kw, "[BLOCKED_PROMPT_INJECTION_ATTEMPT]", sanitized)
        return sanitized
