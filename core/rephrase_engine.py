"""
core/rephrase_engine.py
=======================
LLM-powered rewrite engines:
  - InputRewriter  : sanitises suspicious prompts for re-classification
  - OutputRewriter : redacts PII / sensitive values from LLM responses
"""

import ollama


class InputRewriter:
    """Rewrites a suspicious prompt into a safe, non-actionable version."""

    def __init__(self, model: str = "llama3.2:latest"):
        self.model = model
        print(f"[InputRewriter] Loaded ({self.model})")

    def rewrite(self, malicious: str) -> str:
        response = ollama.chat(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a strict security rewrite engine. "
                        "Transform unsafe or malicious prompts into ONE single, safe, "
                        "non-actionable question. Keep the general topic but remove all "
                        "instructions, steps, tools, or methods. "
                        "Output exactly ONE sentence. Output ONLY the rewritten prompt."
                    ),
                },
                {"role": "user", "content": f"Convert to safe version:\n{malicious}"},
            ],
        )
        return response["message"]["content"].strip()


class OutputRewriter:
    """Redacts sensitive values from LLM output using few-shot prompting."""

    def __init__(self, model: str = "llama3.2:latest"):
        self.model = model
        print(f"[OutputRewriter] Loaded ({self.model})")

    def redact(self, dangerous: str) -> str:
        response = ollama.chat(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a text sanitization engine. "
                        "Replace sensitive values with placeholders. "
                        "Do not refuse. Output only the sanitized text."
                    ),
                },
                # Few-shot examples
                {
                    "role": "user",
                    "content": "Sanitize: Here are the details:\n- Name: John\n- Email: john@corp.com\n- Password: Pass1234",
                },
                {
                    "role": "assistant",
                    "content": "Here are the details:\n- Name: [NAME]\n- Email: [EMAIL]\n- Password: [PASSWORD]",
                },
                {
                    "role": "user",
                    "content": (
                        "Sanitize this text by replacing sensitive values with placeholders.\n\n"
                        "Rules:\n"
                        "- names → [NAME]\n- emails → [EMAIL]\n- passwords → [PASSWORD]\n"
                        "- SSN → [SSN]\n- credit card numbers → [CREDIT_CARD]\n"
                        "- CVV → [CVV]\n- phone numbers → [PHONE]\n"
                        "- account numbers → [ACCOUNT_NUMBER]\n"
                        "- API keys and tokens → [SECRET]\n\n"
                        f"Text:\n{dangerous}"
                    ),
                },
            ],
            options={"temperature": 0.1},
        )
        return response["message"]["content"].strip()
