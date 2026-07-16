from typing import Union

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, OtpPurpose, OtpCode
from app.schemas import (
    Token, SignupRequest, OtpRequiredResponse, OtpVerifyRequest, OtpResendRequest,
)
from app.core.security import verify_password, create_access_token, hash_password
from app.core.audit import log_action
from app.core.otp import create_otp, verify_otp, latest_pending
from app.core.mailer import send_otp_email, MailerError
from app.config import settings

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _client_ip(request: Request):
    return request.client.host if request.client else None


def _issue_token(user: User) -> Token:
    token = create_access_token({"sub": user.email, "role": user.role.value})
    return Token(access_token=token, role=user.role.value, email=user.email)


def _is_admin_email(email: str) -> bool:
    return email.lower() == settings.BOOTSTRAP_ADMIN_EMAIL.lower()


@router.post("/login", response_model=Union[Token, OtpRequiredResponse])
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    # The built-in bootstrap admin signs in directly. Every other account
    # must confirm a one-time code emailed to them before getting a token.
    if _is_admin_email(user.email):
        log_action(db, "login", user=user, ip_address=_client_ip(request))
        return _issue_token(user)

    code = create_otp(db, user.email, OtpPurpose.login)
    try:
        send_otp_email(user.email, code, "login")
    except MailerError as e:
        raise HTTPException(status_code=502, detail=str(e))
    log_action(db, "login_otp_requested", user=user, ip_address=_client_ip(request))
    return OtpRequiredResponse(email=user.email, purpose="login")


@router.post("/signup", response_model=OtpRequiredResponse, status_code=202)
def signup(payload: SignupRequest, db: Session = Depends(get_db)):
    email = payload.email.lower()
    if _is_admin_email(email):
        raise HTTPException(status_code=400, detail="That email is reserved for the built-in admin account.")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered.")

    code = create_otp(
        db, email, OtpPurpose.signup,
        pending_full_name=payload.name,
        pending_hashed_password=hash_password(payload.password),
    )
    try:
        send_otp_email(email, code, "signup")
    except MailerError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return OtpRequiredResponse(email=email, purpose="signup")


@router.post("/otp/verify", response_model=Token)
def otp_verify(payload: OtpVerifyRequest, request: Request, db: Session = Depends(get_db)):
    try:
        purpose = OtpPurpose(payload.purpose)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid purpose.")

    try:
        otp = verify_otp(db, payload.email, payload.code, purpose)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    email = payload.email.lower()

    if purpose == OtpPurpose.signup:
        # Guard against a race between two signup attempts for the same email.
        if db.query(User).filter(User.email == email).first():
            raise HTTPException(status_code=400, detail="Email already registered.")
        user = User(
            email=email,
            full_name=otp.pending_full_name,
            hashed_password=otp.pending_hashed_password,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        log_action(db, "signup", user=user, ip_address=_client_ip(request))
    else:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Account not found.")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is disabled")
        log_action(db, "login", user=user, ip_address=_client_ip(request))

    return _issue_token(user)


@router.post("/otp/resend", response_model=OtpRequiredResponse)
def otp_resend(payload: OtpResendRequest, db: Session = Depends(get_db)):
    try:
        purpose = OtpPurpose(payload.purpose)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid purpose.")

    email = payload.email.lower()

    try:
        if purpose == OtpPurpose.login:
            user = db.query(User).filter(User.email == email).first()
            if user:  # don't reveal whether the account exists either way
                code = create_otp(db, email, OtpPurpose.login)
                send_otp_email(email, code, "login")
        else:
            prior = latest_pending(db, email, OtpPurpose.signup)
            if not prior or not prior.pending_hashed_password:
                raise HTTPException(status_code=400, detail="Start the signup form again.")
            code = create_otp(
                db, email, OtpPurpose.signup,
                pending_full_name=prior.pending_full_name,
                pending_hashed_password=prior.pending_hashed_password,
            )
            send_otp_email(email, code, "signup")
    except MailerError as e:
        raise HTTPException(status_code=502, detail=str(e))

    return OtpRequiredResponse(email=email, purpose=payload.purpose)
