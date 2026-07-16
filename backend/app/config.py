"""
Central configuration for WebGuard.
All values can be overridden with environment variables (see .env.example).
"""
import os
from datetime import timedelta


class Settings:
    APP_NAME: str = "WebGuard"

    # --- Storage ---
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./webguard.db")

    # --- Auth ---
    SECRET_KEY: str = os.getenv("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION_" + os.urandom(8).hex())
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

    # --- Monitoring ---
    DEFAULT_CHECK_INTERVAL_SECONDS: int = int(os.getenv("DEFAULT_CHECK_INTERVAL_SECONDS", "300"))
    MIN_CHECK_INTERVAL_SECONDS: int = int(os.getenv("MIN_CHECK_INTERVAL_SECONDS", "60"))
    REQUEST_TIMEOUT_SECONDS: float = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "10"))

    # Change-score threshold (0-100) above which a scan is flagged as a possible
    # defacement / anomaly. Tunable per deployment.
    ANOMALY_THRESHOLD: float = float(os.getenv("ANOMALY_THRESHOLD", "18.0"))

    # --- AI (optional) ---
    # If unset, WebGuard automatically falls back to deterministic rule-based
    # risk scoring so the platform is fully functional without an API key.
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")

    # --- Bootstrap admin (created on first startup if no users exist) ---
    BOOTSTRAP_ADMIN_EMAIL: str = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "admin@webguard.local")
    BOOTSTRAP_ADMIN_PASSWORD: str = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "ChangeMe123!")

    CORS_ORIGINS: list = os.getenv("CORS_ORIGINS", "*").split(",")

    # --- One-time codes (login / signup verification) ---
    OTP_LENGTH: int = int(os.getenv("OTP_LENGTH", "5"))
    OTP_EXPIRE_MINUTES: int = int(os.getenv("OTP_EXPIRE_MINUTES", "10"))
    OTP_MAX_ATTEMPTS: int = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))

    # --- Outbound email (SMTP) ---
    # If SMTP_HOST is unset, WebGuard logs the email instead of sending it,
    # the same "fully functional without external config" fallback pattern
    # used for AI risk scoring.
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    # STARTTLS (typical for port 587) vs implicit TLS (typical for port 465).
    SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
    SMTP_USE_SSL: bool = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
    SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "no-reply@webguard.local")
    SMTP_FROM_NAME: str = os.getenv("SMTP_FROM_NAME", "WebGuard")


settings = Settings()
