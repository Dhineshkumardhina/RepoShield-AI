"""Authentication and session management API endpoints."""
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from ....core.audit import record_audit_event
from ....core.auth import get_current_user, get_current_user_optional
from ....core.config import settings
from ....core.errors import AccountInactiveError, UnauthorizedError, ValidationError
from ....core.security import create_access_token, hash_password, verify_password
from ....db.session import get_db
from ....models.user import User
from ....schemas.auth import LogoutResponse, TokenResponse, UserLogin, UserRead, UserRegister

router = APIRouter()


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new security practitioner account",
)
def register(
    user_in: UserRegister,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    # 1. Normalize and check uniqueness
    normalized_email = user_in.email.strip().lower()
    existing = db.query(User).filter(User.email == normalized_email).first()
    if existing:
        raise ValidationError("An account with this email address already exists.")

    # 2. Hash password with bcrypt
    hashed = hash_password(user_in.password)

    # 3. Create active user record
    user = User(
        email=normalized_email,
        password_hash=hashed,
        account_status="active",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # 4. Generate JWT access token
    access_token = create_access_token({"sub": user.id, "email": user.email})
    expires_in_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # 5. Set secure HTTP-only session cookie
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=access_token,
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
        max_age=expires_in_seconds,
        path="/",
    )

    # 6. Record sanitized audit event
    record_audit_event(
        db=db,
        action="USER_REGISTRATION_SUCCESS",
        resource_type="user",
        resource_identifier=user.id,
        actor_id=user.id,
        metadata={"email": user.email},
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in_seconds,
        user=UserRead.model_validate(user),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate user and establish session",
)
def login(
    user_in: UserLogin,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    normalized_email = user_in.email.strip().lower()
    user = db.query(User).filter(User.email == normalized_email).first()

    if not user or not verify_password(user_in.password, user.password_hash):
        record_audit_event(
            db=db,
            action="LOGIN_FAILED_CREDENTIALS",
            resource_type="auth",
            resource_identifier=None,
            actor_id=user.id if user else None,
            metadata={"email": normalized_email},
        )
        raise UnauthorizedError("Invalid email or password.")

    if user.account_status != "active":
        record_audit_event(
            db=db,
            action="LOGIN_BLOCKED_INACTIVE_ACCOUNT",
            resource_type="user",
            resource_identifier=user.id,
            actor_id=user.id,
            metadata={"status": user.account_status},
        )
        raise AccountInactiveError("This account is currently inactive or suspended.")

    access_token = create_access_token({"sub": user.id, "email": user.email})
    expires_in_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # Set secure HTTP-only session cookie
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=access_token,
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
        max_age=expires_in_seconds,
        path="/",
    )

    record_audit_event(
        db=db,
        action="USER_LOGIN_SUCCESS",
        resource_type="user",
        resource_identifier=user.id,
        actor_id=user.id,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in_seconds,
        user=UserRead.model_validate(user),
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="Clear session credentials and log out",
)
def logout(
    response: Response,
    current_user: User = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
) -> LogoutResponse:
    response.delete_cookie(
        key=settings.COOKIE_NAME,
        path="/",
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
    )

    if current_user:
        record_audit_event(
            db=db,
            action="USER_LOGOUT",
            resource_type="user",
            resource_identifier=current_user.id,
            actor_id=current_user.id,
        )

    return LogoutResponse(success=True, message="Successfully logged out.")


@router.get(
    "/me",
    response_model=UserRead,
    summary="Get authenticated user profile and session state",
)
def get_me(
    current_user: User = Depends(get_current_user),
) -> UserRead:
    return UserRead.model_validate(current_user)
