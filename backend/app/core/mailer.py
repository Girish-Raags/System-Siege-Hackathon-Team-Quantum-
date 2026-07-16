"""
Minimal SMTP mailer for transactional email (currently just OTP codes).

If SMTP_HOST isn't configured, WebGuard logs the message instead of sending
it, so local/dev environments keep working without a real mail server.
"""
import logging
import smtplib
from email.message import EmailMessage

from app.config import settings

logger = logging.getLogger("webguard.mailer")


def send_email(to_email: str, subject: str, body: str) -> None:
    if not settings.SMTP_HOST:
        logger.info("[DEV MAILER] To: %s | Subject: %s\n%s", to_email, subject, body)
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
    msg["To"] = to_email
    msg.set_content(body)

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
        if settings.SMTP_USE_TLS:
            server.starttls()
        if settings.SMTP_USERNAME:
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        server.send_message(msg)


def send_otp_email(to_email: str, code: str, purpose: str) -> None:
    action = "signing up for" if purpose == "signup" else "signing in to"
    subject = "Your WebGuard verification code"
    body = (
        f"Your WebGuard verification code is: {code}\n\n"
        f"Use this code to finish {action} WebGuard. It expires in "
        f"{settings.OTP_EXPIRE_MINUTES} minutes.\n\n"
        "If you didn't request this, you can safely ignore this email."
    )
    send_email(to_email, subject, body)
