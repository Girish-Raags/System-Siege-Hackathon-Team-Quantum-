import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.models import OtpCode, OtpPurpose


def _hash_code(code: str, email: str) -> str:
    # Salt with SECRET_KEY + email so a leaked DB row can't be brute-forced
    # offline any faster than hitting the API's rate limits would allow.
    return hashlib.sha256(f"{settings.SECRET_KEY}:{email.lower()}:{code}".encode()).hexdigest()


def generate_code() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(settings.OTP_LENGTH))


def create_otp(
    db: Session,
    email: str,
    purpose: OtpPurpose,
    pending_full_name: Optional[str] = None,
    pending_hashed_password: Optional[str] = None,
) -> str:
    """Invalidates any previous unconsumed code for this email/purpose and
    creates a fresh one. Returns the plaintext code (only ever held in
    memory / the outgoing email, never stored)."""
    email = email.lower()
    db.query(OtpCode).filter(
        OtpCode.email == email,
        OtpCode.purpose == purpose,
        OtpCode.consumed_at.is_(None),
    ).update({OtpCode.consumed_at: datetime.utcnow()})

    code = generate_code()
    otp = OtpCode(
        email=email,
        purpose=purpose,
        code_hash=_hash_code(code, email),
        pending_full_name=pending_full_name,
        pending_hashed_password=pending_hashed_password,
        expires_at=datetime.utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES),
    )
    db.add(otp)
    db.commit()
    return code


def latest_pending(db: Session, email: str, purpose: OtpPurpose) -> Optional[OtpCode]:
    return (
        db.query(OtpCode)
        .filter(OtpCode.email == email.lower(), OtpCode.purpose == purpose)
        .order_by(OtpCode.created_at.desc())
        .first()
    )


def verify_otp(db: Session, email: str, code: str, purpose: OtpPurpose) -> OtpCode:
    """Returns the matching, now-consumed OtpCode row if the code is valid,
    else raises ValueError with a user-facing message."""
    email = email.lower()
    otp = (
        db.query(OtpCode)
        .filter(OtpCode.email == email, OtpCode.purpose == purpose, OtpCode.consumed_at.is_(None))
        .order_by(OtpCode.created_at.desc())
        .first()
    )
    if not otp:
        raise ValueError("No pending verification code for this email. Request a new one.")
    if otp.expires_at < datetime.utcnow():
        raise ValueError("Code expired. Request a new one.")
    if otp.attempts >= settings.OTP_MAX_ATTEMPTS:
        raise ValueError("Too many attempts. Request a new code.")

    otp.attempts += 1
    if otp.code_hash != _hash_code(code, email):
        db.commit()
        raise ValueError("Incorrect code.")

    otp.consumed_at = datetime.utcnow()
    db.commit()
    return otp
