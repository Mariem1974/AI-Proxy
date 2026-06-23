"""
alerts/soc_alerter.py
======================
SOC alerting: sends security events via Telegram bot and/or Gmail SMTP.
"""

import os
import smtplib
from email.message import EmailMessage
from datetime import datetime


class SOCAlerter:
    """Sends security alerts to configured channels (Telegram + Email)."""

    def send_telegram(self, title: str, body: str, chat_id: str) -> bool:
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        if not token or not chat_id:
            print("[SOCAlerter] Telegram skipped — TELEGRAM_BOT_TOKEN not set")
            return False
        try:
            import requests
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            response = requests.post(
                url, json={"chat_id": chat_id, "text": f"{title}\n\n{body}"}, timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"[SOCAlerter] Telegram failed: {e}")
            return False

    def send_email(self, title: str, body: str, to_email: str) -> bool:
        smtp_user = os.getenv("SMTP_USER", "").strip()
        smtp_pass = os.getenv("SMTP_PASS", "").strip()
        if not smtp_user or not smtp_pass or not to_email:
            print("[SOCAlerter] Email skipped — SMTP_USER or SMTP_PASS not set")
            return False
        try:
            msg = EmailMessage()
            msg["From"] = smtp_user
            msg["To"] = to_email
            msg["Subject"] = title
            msg.set_content(body)
            with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
                smtp.starttls()
                smtp.login(smtp_user, smtp_pass)
                smtp.send_message(msg)
            return True
        except Exception as e:
            print(f"[SOCAlerter] Email failed: {e}")
            return False

    def alert(
        self,
        severity: str,
        user_id: int,
        username: str,
        content: str,
        detection_type: str,
        action: str,
        settings: dict,
    ):
        """
        Send alert to all configured channels.

        content: the text that triggered the event.
                 - For INPUT detections  → this is the user prompt
                 - For OUTPUT detections → this is the LLM response
        """
        title = f"[AI-PROXY] {severity.upper()} - {detection_type}"

        # ── Label the content correctly depending on where the event was triggered
        OUTPUT_DETECTIONS = {"PII_OUTPUT", "OUTPUT_SPACY", "OUTPUT_CONTEXT"}
        if detection_type in OUTPUT_DETECTIONS:
            content_label = "LLM Response (triggered the event)"
        else:
            content_label = "User Prompt (triggered the event)"

        body = (
            f"User      : {username} (ID: {user_id})\n"
            f"Detection : {detection_type}\n"
            f"Action    : {action}\n"
            f"Severity  : {severity.upper()}\n"
            f"Timestamp : {datetime.utcnow().isoformat()}\n"
            f"\n"
            f"--- {content_label} ---\n"
            f"{content[:500]}"
            f"{'...' if len(content) > 500 else ''}"
        )

        if settings.get("enable_telegram") and settings.get("telegram_chat_id"):
            ok = self.send_telegram(title, body, settings["telegram_chat_id"])
            if ok:
                print(f"[SOCAlerter] Telegram alert sent for {detection_type}")

        if settings.get("enable_email") and settings.get("email_address"):
            ok = self.send_email(title, body, settings["email_address"])
            if ok:
                print(f"[SOCAlerter] Email alert sent for {detection_type}")
