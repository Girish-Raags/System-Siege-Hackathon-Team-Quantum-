"""
SMTP mailer for transactional email (currently just OTP codes).

Behavior:
- If SMTP_HOST is unset, falls back to logging the message (dev mode).
- If SMTP_HOST IS set, it actually connects and sends -- and raises
  MailerError with a clear message if that fails, instead of silently
  pretending the email went out.
"""
import logging
import smtplib
import ssl
from email.message import EmailMessage

from app.config import settings

logger = logging.getLogger("webguard.mailer")


class MailerError(RuntimeError):
    """Raised when a real SMTP send fails, so callers can surface a clear
    error instead of telling the user a code was emailed when it wasn't."""


def send_email(to_email: str, subject: str, body: str) -> None:
    if not settings.SMTP_HOST:
        # Dev fallback: no SMTP configured, log instead of sending.
        logger.info("[DEV MAILER] To: %s | Subject: %s\n%s", to_email, subject, body)
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
    msg["To"] = to_email
    msg.set_content(body)

    try:
        if settings.SMTP_PORT == 465 or settings.SMTP_USE_SSL:
            # Implicit TLS from the start of the connection (e.g. port 465).
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, context=context, timeout=15) as server:
                if settings.SMTP_USERNAME:
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.send_message(msg)
        else:
            # Plain connection upgraded via STARTTLS (e.g. port 587).
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
                server.ehlo()
                if settings.SMTP_USE_TLS:
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                if settings.SMTP_USERNAME:
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.send_message(msg)
    except smtplib.SMTPAuthenticationError as e:
        logger.error("SMTP auth failed sending to %s: %s", to_email, e)
        raise MailerError(
            "Email server rejected the credentials (SMTP_USERNAME / SMTP_PASSWORD). "
            "For Gmail, use an App Password, not your normal login password."
        ) from e
    except (smtplib.SMTPException, OSError, TimeoutError) as e:
        logger.error("Failed to send email to %s: %s", to_email, e)
        raise MailerError(f"Could not send email via SMTP: {e}") from e

    logger.info("Sent email to %s | Subject: %s", to_email, subject)


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
