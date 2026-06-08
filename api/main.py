"""
Livestrym API
Clean, production-grade FastAPI backend.
Handles user accounts, authentication, and rebroadcast logging.
"""

import os
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Enum, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
import requests
import enum
from dotenv import load_dotenv

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
DATABASE_URL   = os.getenv("DATABASE_URL", "sqlite:///./livestrym.db")
# Railway gives postgres:// — SQLAlchemy needs postgresql://
# Also switch driver to pg8000 (pure Python — no libpq system dependency)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+pg8000://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+pg8000://", 1)
SECRET_KEY     = os.getenv("SECRET_KEY", "change-this-in-production")
ALGORITHM      = "HS256"
TOKEN_EXPIRE_H = 24
YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY", "")
ADMIN_PASSWORD  = os.getenv("ADMIN_PASSWORD", "livestrym-admin-2025")
ADMIN_EMAIL     = os.getenv("ADMIN_EMAIL", "")
SCANNER_SECRET  = os.getenv("SCANNER_SECRET", "")          # required — set in Railway env vars
SENDGRID_KEY    = os.getenv("SENDGRID_API_KEY", "")
FROM_EMAIL      = os.getenv("FROM_EMAIL", "hello@livestrym.io")

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("livestrym.api")

# ── Database ──────────────────────────────────────────────────────────────────
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ── Enums ─────────────────────────────────────────────────────────────────────
class TierEnum(str, enum.Enum):
    free     = "free"
    pro      = "pro"
    business = "business"

class StatusEnum(str, enum.Enum):
    pending  = "pending"
    approved = "approved"
    rejected = "rejected"

# ── Models ────────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id               = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    full_name        = Column(String, nullable=False)
    email            = Column(String, unique=True, nullable=False, index=True)
    hashed_password  = Column(String, nullable=False)
    org_name         = Column(String, nullable=False)
    channel_url      = Column(String, nullable=False)
    channel_id       = Column(String, nullable=True)
    account_type     = Column(String, default="ministry")
    tier             = Column(Enum(TierEnum), default=TierEnum.free)
    status           = Column(Enum(StatusEnum), default=StatusEnum.pending)
    is_active        = Column(Boolean, default=True)
    created_at       = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    verified_at      = Column(DateTime, nullable=True)
    # ── Stream key (for SRS ingest — Sprint 2) ────────────────
    stream_key       = Column(String, nullable=True,
                              default=lambda: __import__("secrets").token_urlsafe(32))
    # ── Notification preferences ──────────────────────────────
    telegram_chat_id = Column(String, nullable=True)
    whatsapp_number  = Column(String, nullable=True)
    webhook_url      = Column(String, nullable=True)
    # ── Relationships ─────────────────────────────────────────
    detections       = relationship("Detection", back_populates="owner",
                                    cascade="all, delete-orphan")

class Detection(Base):
    __tablename__ = "detections"
    id               = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id         = Column(String, ForeignKey("users.id"), nullable=True)
    stream_url       = Column(String, nullable=False)
    stream_title     = Column(String, nullable=True)
    channel_name     = Column(String, nullable=True)
    channel_id       = Column(String, nullable=True)
    thumbnail_url    = Column(String, nullable=True)
    concurrent_viewers = Column(String, nullable=True)
    confidence_score = Column(String, nullable=True)
    detected_at      = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    reported         = Column(Boolean, default=False)
    owner            = relationship("User", back_populates="detections")

# ── Auth ──────────────────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_H)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

def get_current_user(token: str, db: Session) -> User:
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    user = db.query(User).filter(User.id == payload.get("sub")).first()
    if not user or user.status != StatusEnum.approved:
        raise HTTPException(status_code=401, detail="Account not found or not approved.")
    return user

# ── YouTube Verification ──────────────────────────────────────────────────────
def verify_youtube_channel(channel_url: str) -> dict:
    """
    Verify a YouTube channel meets ministry requirements.
    Returns approved, channel_id, channel_name, reason.
    """
    if not YOUTUBE_API_KEY:
        return {"approved": True, "auto": False, "channel_id": None,
                "channel_name": None, "reason": "No API key — manual review required"}

    # Extract handle from URL
    handle = None
    url = channel_url.strip().rstrip("/")
    if "/@" in url:
        handle = url.split("/@")[-1].split("/")[0]
    elif "/channel/" in url:
        handle = url.split("/channel/")[-1].split("/")[0]
    elif "/c/" in url:
        handle = url.split("/c/")[-1].split("/")[0]

    if not handle:
        return {"approved": False, "auto": False, "channel_id": None,
                "channel_name": None, "reason": "Could not parse YouTube channel URL."}

    try:
        # Try by handle
        r = requests.get(
            "https://www.googleapis.com/youtube/v3/channels",
            params={"part": "snippet,statistics", "forHandle": handle, "key": YOUTUBE_API_KEY},
            timeout=10
        )
        data  = r.json()
        items = data.get("items", [])

        if not items:
            # Try by ID
            r = requests.get(
                "https://www.googleapis.com/youtube/v3/channels",
                params={"part": "snippet,statistics", "id": handle, "key": YOUTUBE_API_KEY},
                timeout=10
            )
            items = r.json().get("items", [])

        if not items:
            return {"approved": False, "auto": False, "channel_id": None,
                    "channel_name": None, "reason": "Channel not found on YouTube."}

        channel      = items[0]
        channel_id   = channel["id"]
        snippet      = channel.get("snippet", {})
        stats        = channel.get("statistics", {})
        channel_name = snippet.get("title", "")

        # Run checks
        checks = {}

        # Age check
        published = snippet.get("publishedAt", "")
        if published:
            created  = datetime.fromisoformat(published.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created).days
            checks["age"] = age_days >= 90
        else:
            checks["age"] = False

        # Video count
        checks["videos"] = int(stats.get("videoCount", 0)) >= 5

        # Subscriber count
        checks["subscribers"] = int(stats.get("subscriberCount", 0)) >= 100

        failed = [k for k, v in checks.items() if not v]

        if not failed:
            return {"approved": True, "auto": True, "channel_id": channel_id,
                    "channel_name": channel_name, "reason": "All checks passed."}
        else:
            return {"approved": False, "auto": False, "channel_id": channel_id,
                    "channel_name": channel_name,
                    "reason": f"Failed: {', '.join(failed)}. Flagged for manual review."}

    except Exception as e:
        log.error(f"YouTube verification error: {e}")
        return {"approved": False, "auto": False, "channel_id": None,
                "channel_name": None, "reason": "Verification error. Manual review required."}

# ── Email ─────────────────────────────────────────────────────────────────────
def send_email(to: str, subject: str, body_html: str):
    if not SENDGRID_KEY:
        log.info(f"[Email not configured] Would send to {to}: {subject}")
        return
    try:
        import sendgrid
        from sendgrid.helpers.mail import Mail
        sg  = sendgrid.SendGridAPIClient(api_key=SENDGRID_KEY)
        msg = Mail(from_email=FROM_EMAIL, to_emails=to,
                   subject=subject, html_content=body_html)
        sg.client.mail.send.post(request_body=msg.get())
        log.info(f"Email sent to {to}")
    except Exception as e:
        log.error(f"Email failed: {e}")

def send_welcome_email(to: str, name: str):
    send_email(to, "Welcome to Livestrym",
        f"""<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto">
        <h2 style="color:#2f7cf6">Welcome to Livestrym, {name}</h2>
        <p>Your account has been approved. Livestrym is now protecting your live streams.</p>
        <p>Sign in at <a href="https://livestrym.io/dashboard">livestrym.io/dashboard</a></p>
        <p style="color:#888;font-size:13px">The Livestrym Team</p>
        </div>""")

def send_pending_email(to: str, name: str):
    send_email(to, "Livestrym — Account Under Review",
        f"""<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto">
        <h2 style="color:#2f7cf6">Account Under Review</h2>
        <p>Hi {name}, thank you for signing up for Livestrym.</p>
        <p>We are reviewing your channel and will respond within 48 hours.</p>
        <p style="color:#888;font-size:13px">The Livestrym Team</p>
        </div>""")

def notify_admin_review(user: User, reason: str):
    if not ADMIN_EMAIL:
        log.info(f"[Admin review needed] {user.org_name} — {reason}")
        return
    send_email(ADMIN_EMAIL, f"Livestrym — Review needed: {user.org_name}",
        f"""<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto">
        <h2 style="color:#f59e0b">Manual Review Required</h2>
        <p><b>Name:</b> {user.full_name}</p>
        <p><b>Email:</b> {user.email}</p>
        <p><b>Organization:</b> {user.org_name}</p>
        <p><b>Channel:</b> {user.channel_url}</p>
        <p><b>Reason:</b> {reason}</p>
        </div>""")

# ── Schemas ───────────────────────────────────────────────────────────────────
class SignupRequest(BaseModel):
    full_name:    str
    email:        EmailStr
    password:     str
    org_name:     str
    channel_url:  str
    account_type: str = "ministry"

class LoginRequest(BaseModel):
    email:    EmailStr
    password: str

class DetectionIn(BaseModel):
    stream_url:          str
    stream_title:        Optional[str] = None
    channel_name:        Optional[str] = None
    channel_id:          Optional[str] = None
    thumbnail_url:       Optional[str] = None
    concurrent_viewers:  Optional[str] = None
    confidence_score:    Optional[str] = None
    owner_id:            Optional[str] = None   # which customer's content was stolen

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Livestrym API",
    description="Live stream protection platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
)

# ── CORS — tighten in production (replace * with your actual frontend domain) ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_URL", "*")],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Scanner-Secret"],
)

# ── Security headers — applied to every response ──────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "camera=(), microphone=(), geolocation=()"
    # Remove server fingerprint — MutableHeaders uses del not pop
    try:
        del response.headers["server"]
    except KeyError:
        pass
    return response

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    _run_migrations()
    log.info("Livestrym API started. Database ready.")
    # ── Seed admin account ────────────────────────────────────────────────────
   # _seed_admin()

def _run_migrations():
    """
    Safe additive column migrations.
    Uses IF NOT EXISTS — safe to run on every startup.
    Never drops or modifies existing data.
    Add new ALTER TABLE lines here as schema grows.
    """
    import sqlalchemy as sa
    migrations = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS stream_key VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_chat_id VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS whatsapp_number VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS webhook_url VARCHAR",
        "ALTER TABLE detections ADD COLUMN IF NOT EXISTS owner_id VARCHAR",
        "ALTER TABLE detections ADD COLUMN IF NOT EXISTS thumbnail_url VARCHAR",
        "ALTER TABLE detections ADD COLUMN IF NOT EXISTS reported BOOLEAN DEFAULT FALSE",
    ]
    db = SessionLocal()
    try:
        for sql in migrations:
            try:
                db.execute(sa.text(sql))
                db.commit()
            except Exception as e:
                db.rollback()
                log.debug(f"Migration note: {sql[:50]} — {e}")
        log.info(f"Migrations complete — {len(migrations)} statements processed.")
    except Exception as e:
        log.error(f"Migration error: {e}")
    finally:
        db.close()


    """Creates the admin account on first startup if it doesn't exist.
    Uses ADMIN_EMAIL and ADMIN_PASSWORD from environment variables.
    Safe to call multiple times — skips if admin already exists.
    """
    if not ADMIN_EMAIL:
        log.warning("ADMIN_EMAIL not set — skipping admin seed. Set it in Railway env vars.")
        return
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == ADMIN_EMAIL).first()
        if existing:
            log.info(f"Admin account already exists: {ADMIN_EMAIL}")
            return
        import secrets as sec
        admin = User(
            id              = str(uuid.uuid4()),
            full_name       = "Livestrym Admin",
            email           = ADMIN_EMAIL,
            hashed_password = hash_password(ADMIN_PASSWORD),
            org_name        = "Livestrym",
            channel_url     = "https://livestrym.io",
            channel_id      = "admin",
            account_type    = "admin",
            tier            = TierEnum.business,
            status          = StatusEnum.approved,
            is_active       = True,
            verified_at     = datetime.now(timezone.utc),
            stream_key      = sec.token_urlsafe(32),
        )
        db.add(admin)
        db.commit()
        log.info(f"Admin account created: {ADMIN_EMAIL}")
    except Exception as e:
        log.error(f"Admin seed failed: {e}")
        db.rollback()
    finally:
        db.close()

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "Livestrym API", "version": "1.0.0"}

@app.get("/api/scanner/channels")
def scanner_get_channels(
    request: Request,
    db: Session = Depends(get_db)
):
    """Returns all active protected channels for the ARQ scanner worker.
    Called every 5 minutes by the worker to build the channel registry.
    Requires X-Scanner-Secret header.
    """
    secret = request.headers.get("X-Scanner-Secret", "")
    if not SCANNER_SECRET or secret != SCANNER_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized.")

    users = db.query(User).filter(
        User.status == StatusEnum.approved,
        User.is_active == True
    ).all()

    channels = []
    for user in users:
        if user.channel_id and user.channel_id != "admin":
            channels.append({
                "channel_id":   user.channel_id,
                "channel_name": user.org_name or user.full_name,
                "owner_id":     user.id,
                "channel_url":  user.channel_url or "",
                "keywords":     [
                    user.org_name,
                    f"{user.org_name} live",
                    f"{user.org_name} service",
                ] if user.org_name else ["livestream"],
            })

    log.info(f"Scanner registry: {len(channels)} active channels")
    return channels

@app.post("/api/admin/seed")
def seed_database(request: Request, db: Session = Depends(get_db)):
    """One-time endpoint to seed initial data.
    Requires admin auth. Safe to call multiple times — skips existing records.
    """
    check_admin(request)
    results = []

    # Re-run admin seed in case it failed on startup
    existing_admin = db.query(User).filter(User.email == ADMIN_EMAIL).first()
    if existing_admin:
        results.append(f"Admin already exists: {ADMIN_EMAIL}")
    else:
        _seed_admin()
        results.append(f"Admin created: {ADMIN_EMAIL}")

    return {"seeded": True, "results": results}

@app.post("/api/admin/reset-password")
def reset_admin_password(request: Request, db: Session = Depends(get_db)):
    """Resets admin account password to match current ADMIN_PASSWORD env var.
    Use this when ADMIN_PASSWORD env var changes after the account was seeded.
    Requires the CURRENT ADMIN_PASSWORD in the Authorization header to execute.
    After use, remove or disable this endpoint.
    """
    check_admin(request)
    admin = db.query(User).filter(User.email == ADMIN_EMAIL).first()
    if not admin:
        raise HTTPException(status_code=404, detail="Admin account not found.")
    admin.hashed_password = hash_password(ADMIN_PASSWORD)
    db.commit()
    log.info(f"Admin password reset for: {ADMIN_EMAIL}")
    return {"message": f"Password reset for {ADMIN_EMAIL}. Login with new ADMIN_PASSWORD."}

def admin_stats(request: Request, db: Session = Depends(get_db)):
    """Dashboard stats for admin — total users, detections, pending approvals."""
    check_admin(request)
    total_users      = db.query(User).count()
    pending_users    = db.query(User).filter(User.status == StatusEnum.pending).count()
    approved_users   = db.query(User).filter(User.status == StatusEnum.approved).count()
    total_detections = db.query(Detection).count()
    return {
        "total_users":      total_users,
        "pending_users":    pending_users,
        "approved_users":   approved_users,
        "total_detections": total_detections,
    }

# ── Auth Routes ───────────────────────────────────────────────────────────────
@app.post("/api/signup")
def signup(data: SignupRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered.")

    import secrets as sec
    user = User(
        full_name        = data.full_name.strip(),
        email            = data.email.lower().strip(),
        hashed_password  = hash_password(data.password),
        org_name         = data.org_name.strip(),
        channel_url      = data.channel_url.strip(),
        account_type     = data.account_type,
        tier             = TierEnum.free,
        status           = StatusEnum.pending,
        stream_key       = sec.token_urlsafe(32),
    )

    # Business accounts go straight to pending payment
    if data.account_type == "business":
        db.add(user)
        db.commit()
        db.refresh(user)
        return {"message": "Business account created. Complete payment to activate.",
                "user_id": user.id, "next": "payment"}

    # Ministry accounts — verify YouTube channel
    verification      = verify_youtube_channel(data.channel_url)
    user.channel_id   = verification.get("channel_id")

    if verification.get("auto"):
        user.status      = StatusEnum.approved
        user.verified_at = datetime.now(timezone.utc)
        db.add(user)
        db.commit()
        db.refresh(user)
        send_welcome_email(user.email, user.full_name)
        log.info(f"Auto-approved: {user.email}")
        return {"message": "Account approved. Welcome to Livestrym.",
                "user_id": user.id, "next": "login"}
    else:
        db.add(user)
        db.commit()
        db.refresh(user)
        send_pending_email(user.email, user.full_name)
        notify_admin_review(user, verification.get("reason", ""))
        log.info(f"Pending review: {user.email} — {verification.get('reason')}")
        return {"message": "Account under review. You will hear from us within 48 hours.",
                "user_id": user.id, "next": "pending"}

@app.post("/api/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email.lower().strip()).first()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    if user.status != StatusEnum.approved:
        raise HTTPException(status_code=403,
            detail="Account pending review. Please wait for approval.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated.")

    token = create_token({"sub": user.id, "email": user.email, "tier": user.tier.value})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id":           user.id,
            "full_name":    user.full_name,
            "email":        user.email,
            "org_name":     user.org_name,
            "tier":         user.tier.value,
            "account_type": user.account_type,
        }
    }

@app.get("/api/me")
def me(token: str, db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    detection_count = db.query(Detection).filter(
        Detection.owner_id == user.id
    ).count()
    return {
        "id":              user.id,
        "full_name":       user.full_name,
        "email":           user.email,
        "org_name":        user.org_name,
        "channel_url":     user.channel_url,
        "channel_id":      user.channel_id,
        "tier":            user.tier.value,
        "account_type":    user.account_type,
        "status":          user.status.value,
        "stream_key":      user.stream_key,
        "telegram_chat_id": user.telegram_chat_id,
        "whatsapp_number": user.whatsapp_number,
        "detection_count": detection_count,
        "created_at":      user.created_at.isoformat(),
    }

# ── User Settings Routes ──────────────────────────────────────────────────────
class NotificationSettings(BaseModel):
    telegram_chat_id: Optional[str] = None
    whatsapp_number:  Optional[str] = None
    webhook_url:      Optional[str] = None

@app.put("/api/me/notifications")
def update_notifications(
    data: NotificationSettings,
    token: str,
    db: Session = Depends(get_db)
):
    """Update notification channel preferences."""
    user = get_current_user(token, db)
    if data.telegram_chat_id is not None:
        user.telegram_chat_id = data.telegram_chat_id
    if data.whatsapp_number is not None:
        user.whatsapp_number = data.whatsapp_number
    if data.webhook_url is not None:
        user.webhook_url = data.webhook_url
    db.commit()
    return {"message": "Notification settings updated."}

@app.post("/api/me/rotate-stream-key")
def rotate_stream_key(token: str, db: Session = Depends(get_db)):
    """Generate a new stream key. Old key immediately invalidated."""
    import secrets as sec
    user = get_current_user(token, db)
    user.stream_key = sec.token_urlsafe(32)
    db.commit()
    log.info(f"Stream key rotated for {user.email}")
    return {"stream_key": user.stream_key,
            "message": "Stream key rotated. Update your encoder settings."}

@app.get("/api/stream-status")
def stream_status(token: str, db: Session = Depends(get_db)):
    """
    Returns live stream status for the dashboard.
    Checks the most recent detection to infer if a broadcast is active.
    In Sprint 2 this will use SRS on_publish state directly.
    """
    user = get_current_user(token, db)

    # Get recent detections (last 24 hours) for this user
    from datetime import timedelta
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    recent = db.query(Detection).filter(
        Detection.owner_id == user.id,
        Detection.detected_at >= since
    ).order_by(Detection.detected_at.desc()).all()

    # Total all-time detections
    total = db.query(Detection).filter(
        Detection.owner_id == user.id
    ).count()

    # Total unique pirate channels caught
    unique_pirates = db.query(Detection.channel_id).filter(
        Detection.owner_id == user.id,
        Detection.channel_id != None
    ).distinct().count()

    # Most recent detection
    last = recent[0] if recent else None

    return {
        "is_live":          False,   # Sprint 2: SRS will set this via on_publish
        "title":            None,    # matches dashboard data.title
        "stream_title":     None,
        "stream_url":       user.channel_url,
        "channel_id":       user.channel_id,
        "org_name":         user.org_name,
        "stream_key":       user.stream_key,
        "tier":             user.tier.value,
        "scan_count":       len(recent),   # matches dashboard data.scan_count
        "stats": {
            "total_detections":    total,
            "detections_24h":      len(recent),
            "unique_pirates":      unique_pirates,
            "last_detected_at":    last.detected_at.isoformat() if last else None,
            "last_pirate_channel": last.channel_name if last else None,
        }
    }

# ── Detection Routes ──────────────────────────────────────────────────────────
@app.post("/api/detections")
def log_detection(
    data: DetectionIn,
    x_scanner_secret: str = Header(None),
    db: Session = Depends(get_db)
):
    """Called by the scanner when a rebroadcast is confirmed.
    Requires X-Scanner-Secret header — only the internal scanner may call this.
    """
    if not SCANNER_SECRET or x_scanner_secret != SCANNER_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized.")

    # Find owner by owner_id or by channel_id match
    owner_id = data.owner_id
    if not owner_id and data.channel_id:
        user = db.query(User).filter(User.channel_id == data.channel_id).first()
        if user:
            owner_id = user.id

    detection = Detection(
        owner_id            = owner_id,
        stream_url          = data.stream_url,
        stream_title        = data.stream_title,
        channel_name        = data.channel_name,
        channel_id          = data.channel_id,
        thumbnail_url       = data.thumbnail_url,
        concurrent_viewers  = data.concurrent_viewers,
        confidence_score    = data.confidence_score,
    )
    db.add(detection)
    db.commit()
    db.refresh(detection)
    log.info(f"Detection logged: {data.channel_name} at {data.confidence_score}")
    return {"id": detection.id, "detected_at": detection.detected_at.isoformat()}

@app.get("/api/detections")
def get_detections(token: str, db: Session = Depends(get_db)):
    """Get detections for the logged-in user only — filtered by owner_id."""
    user = get_current_user(token, db)
    detections = db.query(Detection).filter(
        Detection.owner_id == user.id
    ).order_by(Detection.detected_at.desc()).limit(100).all()
    return [
        {
            "id":                  d.id,
            "stream_url":          d.stream_url,
            "stream_title":        d.stream_title,
            "channel_name":        d.channel_name,
            "concurrent_viewers":  d.concurrent_viewers,
            "confidence_score":    d.confidence_score,
            "detected_at":         d.detected_at.isoformat(),
            "reported":            d.reported,
            "thumbnail_url":       d.thumbnail_url,
        }
        for d in detections
    ]

# ── Admin Routes ──────────────────────────────────────────────────────────────
def check_admin(request: Request):
    """Validates admin token from Authorization: Bearer <token> header.
    Reads directly from request object — bypasses FastAPI header parsing issues.
    """
    authorization = request.headers.get("Authorization") or \
                    request.headers.get("authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization header.")
    token = authorization.removeprefix("Bearer ").strip()
    if token != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin token.")

@app.get("/api/admin/users")
def admin_get_users(
    request: Request,
    db: Session = Depends(get_db)
):
    check_admin(request)
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [
        {"id": u.id, "full_name": u.full_name, "email": u.email,
         "org_name": u.org_name, "tier": u.tier.value,
         "status": u.status.value, "created_at": u.created_at.isoformat()}
        for u in users
    ]

@app.post("/api/admin/approve/{user_id}")
def admin_approve(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    check_admin(request)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.status      = StatusEnum.approved
    user.verified_at = datetime.now(timezone.utc)
    db.commit()
    send_welcome_email(user.email, user.full_name)
    return {"message": f"Approved: {user.email}"}

@app.post("/api/admin/reject/{user_id}")
def admin_reject(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    check_admin(request)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.status = StatusEnum.rejected
    db.commit()
    return {"message": f"Rejected: {user.email}"}

@app.post("/api/admin/set-tier/{user_id}")
def admin_set_tier(
    user_id: str,
    tier: str,
    request: Request,
    db: Session = Depends(get_db)
):
    check_admin(request)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.tier = TierEnum(tier)
    db.commit()
    return {"message": f"Tier updated to {tier} for {user.email}"}

@app.get("/api/admin/detections")
def admin_get_detections(
    request: Request,
    db: Session = Depends(get_db)
):
    check_admin(request)
    detections = db.query(Detection).order_by(Detection.detected_at.desc()).limit(200).all()
    return [
        {"id": d.id, "stream_url": d.stream_url, "channel_name": d.channel_name,
         "confidence_score": d.confidence_score, "detected_at": d.detected_at.isoformat()}
        for d in detections
    ]

# ── Website ───────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def website():
    web_path = os.path.join(os.path.dirname(__file__), "..", "web", "index.html")
    if os.path.exists(web_path):
        with open(web_path, encoding="utf-8") as f:
            return f.read()
    return "<h1>Livestrym — coming soon</h1>"

@app.get("/signup", response_class=HTMLResponse)
def signup_page():
    return _serve_web("signup.html")

@app.get("/dashboard/login", response_class=HTMLResponse)
def login_page():
    return _serve_web("login.html")

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page():
    return _serve_web("dashboard.html")

def _serve_web(filename: str) -> str:
    path = os.path.join(os.path.dirname(__file__), "..", "web", filename)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return f.read()
    return f"<h1>{filename} — coming soon</h1>"