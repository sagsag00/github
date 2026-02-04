from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.orm import Session
from jose import jwt
import datetime
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import secrets 
import re

from app.database import get_db
from app.models import User, LoginAttempt, RevokedToken
from app.schemas import UserCreate, UserResponse, UserLogin
from app.password import get_password_hash, verify_password
from app.jwt import create_access_token, create_refresh_token, SECRET_KEY, ALGORITHM
from app.config import settings

router = APIRouter(prefix="/auth", tags=["auth"])
SECURE_COOKIES = settings.SECURE_COOKIES

if settings.RATE_LIMIT_BACKEND:
    limiter = Limiter(key_func=get_remote_address, storage_uri=settings.RATE_LIMIT_BACKEND)
else:
    limiter = Limiter(key_func=get_remote_address)

# User Redis in production
csrf_tokens = {}

PASSWORD_MIN_LENGTH = 8
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_DIGIT = True
PASSWORD_REQUIRE_SPECIAL = True

MAX_LOGIN_ATTEMPTS = 15
LOCKOUT_DURATION_MINUTES = 15

DUMMY_PASS = get_password_hash("dummy_password")

def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password meets strength requirements."""
    try:
        if len(password) < PASSWORD_MIN_LENGTH:
            return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters long"
        
        if PASSWORD_REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"

        if PASSWORD_REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        
        if PASSWORD_REQUIRE_DIGIT and not re.search(r"\d", password):
            return False, "Password must contain at least one digit"
        
        if PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        return True, "Password is valid"
    except Exception:
        return False, "Encounterd an unknown problem"

def generate_csrf_token() -> str:
    """Generate a secure CSRF token."""
    return secrets.token_urlsafe(32)

def verify_csrf_token(token: str, session_id: str) -> bool:
    """Verify CSRF token matches the session"""
    stored_token = csrf_tokens.get(session_id)
    if not stored_token:
        return False
    return secrets.compare_digest(stored_token, token)

def check_account_lockout(username: str, db: Session) -> None:
    """Check if account is locked due to too many failed attempts."""
    cutoff_time = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=LOCKOUT_DURATION_MINUTES)
    
    failed_attempts = db.query(LoginAttempt).filter(
        LoginAttempt.username == username,
        LoginAttempt.success == False,
        LoginAttempt.timestamp > cutoff_time
    ).count()
    
    if failed_attempts >= MAX_LOGIN_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked due to too many failed login attempts. Try again in {LOCKOUT_DURATION_MINUTES} minutes."
        )
        
def record_login_attempt(username: str, success: bool, ip_address: str, db: Session) -> None:
    """Record login attempt for tracking and lockout purposes."""
    attempt = LoginAttempt(
        username=username,
        success=success,
        ip_address=ip_address,
        timestamp=datetime.datetime.now(datetime.UTC)
    )
    db.add(attempt)
    db.commit()
    
def cleanup_old_login_attempts(db: Session) -> None:
    """Clean up login attempts older than lockout duration."""
    cutoff_time = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=LOCKOUT_DURATION_MINUTES)
    db.query(LoginAttempt).filter(LoginAttempt.timestamp < cutoff_time).delete()
    db.commit()
    
def is_token_revoked(jti: str, db: Session) -> bool:
    """Check if a token has been revoked"""
    return db.query(RevokedToken).filter(RevokedToken.jti == jti).first() is not None

def revoke_token(jti: str, expires_at: datetime, db: Session) -> None:
    """Add token to revocation list"""
    revoked = RevokedToken(
        jti=jti,
        revoked_at=datetime.datetime.now(datetime.UTC),
        expires_at=expires_at
    )
    db.add(revoked)
    db.commit()
    
def cleanup_expired_tokens(db: Session) -> None:
    """Remove expired tokens from revocation list"""
    db.query(RevokedToken).filter(RevokedToken.expires_at < datetime.datetime.now(datetime.UTC)).delete()
    db.commit()
    
@router.post("/register", response_model=UserResponse)
@limiter.limit("50/hour")
def register_user(request: Request, user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user"""
    
    is_valid, message = validate_password_strength(user.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already exists"
        )
    
    new_user = User(
        username=user.username,
        email=user.email,
        password_hash=get_password_hash(user.password)
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user

@router.post("/login")
@limiter.limit("100/hour")
def login(request: Request, response: Response, credentials: UserLogin, db: Session = Depends(get_db)):
    "Login to the site"
    
    cleanup_old_login_attempts(db)
    check_account_lockout(credentials.username, db)
    
    try:
        data = _login_user(credentials, db)
        
        record_login_attempt(
            username=credentials.username,
            success=True,
            ip_address=get_remote_address(request),
            db=db
        )
        
        session_id = secrets.token_urlsafe(32)
        csrf_token = generate_csrf_token()
        csrf_tokens[session_id] = csrf_token
        
        response.set_cookie(
            key="access_token",
            value=data["access_token"],
            httponly=True,
            secure=SECURE_COOKIES,
            samesite="lax",
            max_age=60*60
        )
        
        response.set_cookie(
            key="refresh_token",
            value=data["refresh_token"],
            httponly=True,
            secure=SECURE_COOKIES,
            samesite="lax",
            max_age=60*60*24*14
        )
        
        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            secure=SECURE_COOKIES,
            samesite="lax",
            max_age=60*60*24*14
        )
        
        return {
            "status": "ok",
            "csrf_token": csrf_token
        }
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            record_login_attempt(
                credentials.username,
                False, 
                get_remote_address(request),
                db
            )
            raise

def _login_user(credentials: UserLogin, db: Session):
    """Internal login logic"""
    user = db.query(User).filter(User.username == credentials.username).first()
    
    # Dummy hash for timing attack protection
    password_hash = user.password_hash if user else DUMMY_PASS
    
    if not user or not verify_password(credentials.password, password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    return {
        "access_token": create_access_token({"sub": str(user.id)}),
        "refresh_token": create_refresh_token({"sub": str(user.id)}),
    }
    
def _get_user(token, token_type: str, db: Session):
    """Decode and validate JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        jti = payload.get("jti")
        
        if payload.get("type") != token_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"    
            )
            
        if jti and is_token_revoked(jti, db):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    return user_id, jti
    
@router.post("/refresh")
@limiter.limit("20/hour")
def refresh_token(request: Request, response: Response, db: Session = Depends(get_db)):
    """Refresh access token."""
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing"    
        )
    
    cleanup_expired_tokens(db)
    user_id, _ = _get_user(refresh_token, "refresh", db)
        
    new_access_token = create_access_token({"sub": user_id})
    
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=SECURE_COOKIES,
        samesite="lax",
        max_age=60*60
    )
    
    return {"status": "ok"}

@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """Logout and revoke tokens."""
    csrf_token = request.headers.get("X-CSRF-Token")
    session_id = request.cookies.get("session_id")
    
    print(f"csrf: {not not csrf_token} session: {not not session_id}")
    
    if not csrf_token or not session_id or not verify_csrf_token(csrf_token, session_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token"
        )
        
    access_token = request.cookies.get("access_token")
    refresh_token_value = request.cookies.get("refresh_token")
    
    if access_token:
        try: 
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            jti = payload.get("jti")
            exp = payload.get("exp")
            if jti and exp:
                revoke_token(jti, datetime.fromtimestamp(exp), db)
        except:
            pass
    
    if refresh_token_value:
        try:
            payload = jwt.decode(refresh_token_value, SECRET_KEY, algorithms=[ALGORITHM])
            jti = payload.get("jti")
            exp = payload.get("exp")
            if jti and exp:
                revoke_token(jti, datetime.fromtimestamp(exp), db)
        except:
            pass
        
    if session_id:
        csrf_tokens.pop(session_id, None)
    
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie("session_id")
    
    return {"status": "ok"}

def get_current_user(request: Request, db: Session = Depends(get_db)):
    """Get the current authenticated user."""
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Not authenticated"
        )
        
    user_id, _ = _get_user(token, "access", db)    
    
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user

def verify_csrf(request: Request):
    """Dependency to verify CSRF token."""
    csrf_token = request.headers.get("X-CSRF-Token")
    session_id = request.cookies.get("session_id")
    
    if not csrf_token or not session_id or not verify_csrf_token(csrf_token, session_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token"
        )
    return True

@router.get("/protected")
def protected_route(user = Depends(get_current_user)):
    return {
        "message": "Welcome home",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email
        }
    }
    
@router.post("/protected/action")
def protected_action(
    request: Request,
    csrf_valid: bool = Depends(verify_csrf),
    user: User = Depends(get_current_user)
):
    return {
        "message": "Action completed successfully",
        "user": user.username
    }