"""CareCircle modular-monolith API. PostgreSQL is required for deployment."""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import date, datetime, time, timedelta, timezone
import hashlib
import hmac
import json
import logging
import re
import secrets
import uuid
import base64
import binascii
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator

from . import settings
from . import db
from .crypto import decrypt, encrypt, decrypt_token, encrypt_token
from .security import password_hash, password_verify, random_token, token_hash, verify_signature


def now() -> datetime:
    return datetime.now(timezone.utc)


def india_now() -> datetime:
    return now().astimezone(ZoneInfo("Asia/Kolkata"))


def stamp(value: datetime | None = None) -> str:
    return (value or now()).isoformat()


def uid() -> str:
    return str(uuid.uuid4())


def phone_digits(value: str | None) -> str:
    return re.sub(r"\D", "", value or "")


def phone_login_hash(value: str | None) -> str | None:
    digits=phone_digits(value)
    return token_hash(digits,settings.APP_SECRET) if len(digits)>=7 else None


def json_dump(value) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if len(settings.APP_SECRET) < 32:
        raise RuntimeError("APP_SECRET must be at least 32 characters in every environment.")
    if settings.APP_ENV == "production":
        if not settings.DATA_ENCRYPTION_KEY or not settings.TOKEN_ENCRYPTION_KEY:
            raise RuntimeError("DATA_ENCRYPTION_KEY and TOKEN_ENCRYPTION_KEY are required in production.")
        try:
            from cryptography.fernet import Fernet
            Fernet(settings.DATA_ENCRYPTION_KEY.encode())
            Fernet(settings.TOKEN_ENCRYPTION_KEY.encode())
        except ImportError as exc:
            raise RuntimeError("Install the cryptography dependency before starting production.") from exc
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Production encryption keys must be valid Fernet keys.") from exc
    db.migrate()
    yield


app = FastAPI(title="CareCircle API", version="1.0.0", lifespan=lifespan,
              docs_url=None if settings.APP_ENV == "production" else "/docs",
              redoc_url=None,
              openapi_url=None if settings.APP_ENV == "production" else "/openapi.json")
logger = logging.getLogger("carecircle.http")


@app.middleware("http")
async def security_and_access_log(request: Request, call_next):
    request_id = uid()
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; script-src 'self' https://checkout.razorpay.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://checkout.razorpay.com; frame-src https://api.razorpay.com https://checkout.razorpay.com"
    if settings.COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith(("/api/", "/webhooks/")):
        response.headers["Cache-Control"] = "no-store"
    logger.info(json_dump({"request_id":request_id,"method":request.method,"path":request.url.path,"status":response.status_code}))
    return response


class FamilyAccountSetup(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    phone: str = Field(min_length=7, max_length=30)
    relationship: str = Field(min_length=2, max_length=60)
    account_type: str = Field(default="guardian", pattern="^(guardian|elder)$")

    @field_validator("phone")
    @classmethod
    def account_phone_valid(cls, value):
        value=value.strip()
        if len(re.sub(r"\D", "", value)) < 7:
            raise ValueError("Enter the nominee or family member's valid phone number.")
        return value


class FamilyAccountUpdate(FamilyAccountSetup):
    pass


class IdentityVerificationSubmission(BaseModel):
    guardian_identity_reference: str = Field(default="", max_length=240)
    elder_identity_reference: str = Field(default="", max_length=240)
    relationship_proof_type: str = Field(default="", max_length=80)
    relationship_proof_reference: str = Field(default="", max_length=240)
    consent_confirmed: bool


class IdentityVerificationReview(BaseModel):
    status: str = Field(pattern="^(verified|rejected)$")
    review_note: str = Field(default="", max_length=1000)


class ClientProfileSetup(BaseModel):
    display_name: str = Field(min_length=1, max_length=100)
    age: int | None = Field(default=None, ge=18, le=120)
    phone: str = Field(min_length=7, max_length=30)
    whatsapp_id: str | None = Field(default=None, max_length=30)
    language: str = Field(min_length=2, max_length=40)
    city: str = Field(min_length=1, max_length=100)
    service_area: str = Field(min_length=1, max_length=100)
    notification_name: str = Field(min_length=1, max_length=100)
    notification_relationship: str = Field(min_length=2, max_length=60)
    notification_phone: str = Field(min_length=7, max_length=30)
    notification_contact_consent: bool
    consent_confirmed: bool
    family_access: bool
    monitoring_consent: bool = False
    voice_ai_consent: bool = False

    @field_validator("phone", "notification_phone")
    @classmethod
    def phone_has_enough_digits(cls, value):
        value = value.strip()
        if len(re.sub(r"\D", "", value)) < 7:
            raise ValueError("Enter a valid phone number with at least 7 digits.")
        return value


class Registration(BaseModel):
    email: str = Field(min_length=6, max_length=254)
    password: str = Field(min_length=12, max_length=200)
    role: str
    phone: str | None = Field(default=None, max_length=30)
    admin_invite_code: str = Field(default="", max_length=200)
    client_profile: ClientProfileSetup | None = None
    family_account: FamilyAccountSetup | None = None

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value):
        value = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Enter a valid email address.")
        return value

    @field_validator("role")
    @classmethod
    def allowed_role(cls, value):
        if value not in {"family", "contributor", "operator"}:
            raise ValueError("Choose Elder, Guardian / relative, Helper / contributor, or Main admin.")
        return value


class Login(BaseModel):
    email: str
    password: str


class ProfileInput(BaseModel):
    display_name: str = Field(min_length=1, max_length=100)
    age: int | None = Field(default=None, ge=18, le=120)
    phone: str | None = Field(default=None, max_length=30)
    whatsapp_id: str | None = Field(default=None, max_length=30)
    language: str = Field(default="English", max_length=40)
    city: str = Field(min_length=1, max_length=100)
    service_area: str = Field(min_length=1, max_length=100)
    consent_confirmed: bool
    family_access: bool = False
    monitoring_consent: bool = False
    voice_ai_consent: bool = False
    notification_name: str = Field(default="", max_length=100)
    notification_relationship: str = Field(default="", max_length=60)
    notification_phone: str | None = Field(default=None, max_length=30)
    notification_contact_consent: bool = False
    retention_days: int = Field(default=30, ge=1, le=365)


class NotificationContactUpdate(BaseModel):
    elder_phone: str = Field(min_length=7, max_length=30)
    elder_whatsapp_id: str | None = Field(default=None, max_length=30)
    notification_name: str = Field(min_length=1, max_length=100)
    notification_relationship: str = Field(min_length=2, max_length=60)
    notification_phone: str = Field(min_length=7, max_length=30)
    notification_contact_consent: bool

    @field_validator("elder_phone", "notification_phone")
    @classmethod
    def contact_phone_valid(cls, value):
        value = value.strip()
        if len(re.sub(r"\D", "", value)) < 7:
            raise ValueError("Enter a valid phone number including its country code.")
        return value


class ContributorInput(BaseModel):
    display_name: str = Field(min_length=1, max_length=100)
    date_of_birth: date
    profession: str = Field(min_length=2, max_length=100)
    identity_document_type: str = Field(pattern="^(Aadhaar verification reference|Passport|Driving licence|Voter ID|Other)$")
    identity_reference: str = Field(min_length=5, max_length=240)
    identity_consent: bool
    city: str = Field(min_length=1, max_length=100)
    service_area: str = Field(min_length=1, max_length=100)
    languages: list[str] = Field(min_length=1, max_length=5)
    tasks: list[str] = Field(min_length=1, max_length=8)

    @field_validator("identity_reference")
    @classmethod
    def identity_reference_is_not_aadhaar(cls, value):
        digits = re.sub(r"\D", "", value)
        if len(digits) == 12:
            raise ValueError("Do not enter an Aadhaar number. Enter an authorized verification transaction reference instead.")
        return value.strip()


class AdminGigInput(BaseModel):
    client_name: str = Field(min_length=1, max_length=100)
    client_phone: str = Field(min_length=7, max_length=30)
    client_address: str = Field(min_length=8, max_length=500)
    contact_name: str = Field(min_length=1, max_length=100)
    contact_phone: str = Field(min_length=7, max_length=30)
    city: str = Field(min_length=1, max_length=100)
    service_area: str = Field(min_length=1, max_length=100)
    category: str = Field(min_length=2, max_length=80)
    service_date: date
    start_time: time
    duration_hours: int = Field(ge=1, le=8)
    fare_inr: int = Field(ge=100, le=100000)
    language: str = Field(min_length=1, max_length=40)
    instructions: str = Field(default="", max_length=1000)
    consent_confirmed: bool

    @field_validator("client_phone", "contact_phone")
    @classmethod
    def valid_phone_digits(cls, value):
        value=value.strip()
        if len(re.sub(r"\D", "", value)) < 7:
            raise ValueError("Enter a valid phone number with at least 7 digits.")
        return value


class AvatarUpdate(BaseModel):
    data_url: str = Field(min_length=40, max_length=1_400_000)


class BookingInput(BaseModel):
    profile_id: str
    category: str
    service_date: date
    start_time: time
    duration_hours: int = Field(ge=1, le=8)
    fare_inr: int = Field(ge=100, le=100000)
    language: str = Field(min_length=1, max_length=40)
    instructions: str = Field(default="", max_length=1000)


class ReminderInput(BaseModel):
    profile_id: str
    title: str = Field(min_length=1, max_length=120)
    due_at: datetime


class ReadingInput(BaseModel):
    profile_id: str
    provider: str = Field(min_length=2, max_length=80)
    metric: str
    value: float
    unit: str
    observed_at: datetime
    event_key: str | None = None


class IncidentInput(BaseModel):
    booking_id: str | None = None
    profile_id: str | None = None
    category: str = Field(min_length=2, max_length=80)
    description: str = Field(min_length=5, max_length=3000)


class ClientReportInput(BaseModel):
    profile_id: str
    category: str = Field(min_length=2, max_length=80)
    description: str = Field(min_length=5, max_length=3000)
    severity: str = "routine"
    language: str = Field(default="English", max_length=40)

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, value):
        if value not in {"routine", "yellow", "red"}:
            raise ValueError("Choose routine, yellow, or red severity.")
        return value


class ClientReadingInput(BaseModel):
    profile_id: str
    metric: str
    value: float
    unit: str
    observed_at: datetime = Field(default_factory=now)


def _audit(conn, actor, action, entity_type, entity_id, metadata=None):
    conn.execute("INSERT INTO audit_log(id,actor_user_id,action,entity_type,entity_id,metadata,created_at) VALUES(?,?,?,?,?,?,?)",
                 (uid(), actor, action, entity_type, entity_id, json_dump(metadata or {}), stamp()))


def _role(actor, *roles):
    if actor["role"] not in roles:
        raise HTTPException(403, "This role cannot perform that action.")


def _actor(request: Request):
    if not settings.APP_SECRET:
        raise HTTPException(503, "APP_SECRET is not configured.")
    token = request.cookies.get("carecircle_session")
    if not token:
        raise HTTPException(401, "Sign in to continue.")
    digest = token_hash(token, settings.APP_SECRET)
    with db.transaction() as conn:
        row = conn.one("SELECT s.csrf_hash,s.expires_at,u.id,u.email,u.role,u.is_active FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?", (digest,))
    if not row or row["expires_at"] < stamp() or not row["is_active"]:
        raise HTTPException(401, "Session expired. Sign in again.")
    return {"id": row["id"], "email": row["email"], "role": row["role"], "csrf_hash": row["csrf_hash"]}


def _write_actor(request: Request, x_csrf_token: str | None = Header(default=None)):
    actor = _actor(request)
    if not x_csrf_token or not hmac.compare_digest(token_hash(x_csrf_token, settings.APP_SECRET), actor["csrf_hash"]):
        raise HTTPException(403, "CSRF verification failed.")
    return actor


def _limited(request: Request, bucket: str, limit=12):
    ip = request.client.host if request.client else "unknown"
    key = token_hash(bucket+":"+ip, settings.APP_SECRET)
    current = now()
    with db.transaction() as conn:
        row = conn.one("SELECT * FROM auth_rate_limits WHERE key_hash=?", (key,))
        if not row or current-datetime.fromisoformat(row["window_started_at"]) >= timedelta(minutes=15):
            conn.execute("INSERT INTO auth_rate_limits(key_hash,window_started_at,attempts) VALUES(?,?,1) ON CONFLICT(key_hash) DO UPDATE SET window_started_at=excluded.window_started_at,attempts=1", (key, stamp(current)))
        elif row["attempts"] >= limit:
            raise HTTPException(429, "Too many attempts. Try again in 15 minutes.")
        else:
            conn.execute("UPDATE auth_rate_limits SET attempts=attempts+1 WHERE key_hash=?", (key,))


def _has_profile_access(conn, profile_id, user_id):
    return bool(conn.one("SELECT 1 FROM profiles p WHERE p.id=? AND p.owner_user_id=? UNION SELECT 1 FROM care_profile_access WHERE profile_id=? AND user_id=?",(profile_id,user_id,profile_id,user_id)))


def _profile(conn, profile_id, actor, allow_operator=True):
    row = conn.one("SELECT * FROM profiles WHERE id=?", (profile_id,))
    if not row:
        raise HTTPException(404, "Profile not found.")
    if actor["role"] == "operator" and allow_operator:
        _audit(conn, actor["id"], "sensitive_profile_access", "profile", profile_id)
        return row
    if not row["consent_confirmed"] or not _has_profile_access(conn,profile_id,actor["id"]):
        raise HTTPException(403, "Profile access requires the owner’s consent and authorization.")
    if row["owner_user_id"] != actor["id"]:
        _audit(conn,actor["id"],"linked_elder_profile_access","profile",profile_id)
    return row


def _require_identity_verified(conn, actor, profile_id):
    row=conn.one("SELECT status FROM identity_verification_requests WHERE elder_profile_id=? ORDER BY submitted_at DESC LIMIT 1",(profile_id,))
    if not row or row["status"]!="verified":
        raise HTTPException(403,"Complete guardian, elder, and relationship verification before booking or scheduling reminders.")


def _link_verified_elder_account(conn, profile_id, granted_by):
    profile=conn.one("SELECT phone,whatsapp_ciphertext FROM profiles WHERE id=?",(profile_id,))
    if not profile: return
    possible={phone_login_hash(decrypt(value)) for value in (profile["phone"],profile["whatsapp_ciphertext"]) if value}
    possible.discard(None)
    if not possible: return
    accounts=conn.all("SELECT id,account_phone_hash FROM users WHERE role='family' AND account_type='elder' AND is_active=1 AND account_phone_hash IS NOT NULL")
    linked=next((account for account in accounts if account["account_phone_hash"] in possible),None)
    if linked and linked["id"]!=granted_by:
        conn.execute("INSERT INTO care_profile_access(profile_id,user_id,granted_by,linked_at) VALUES(?,?,?,?) ON CONFLICT(profile_id,user_id) DO NOTHING",(profile_id,linked["id"],granted_by,stamp()))
        _audit(conn,granted_by,"elder_account_linked_to_verified_profile","profile",profile_id,{"elder_user_id":linked["id"]})


def _link_existing_verified_profiles_for_elder(conn, elder_user_id):
    profiles=conn.all("SELECT p.id,p.owner_user_id FROM profiles p JOIN identity_verification_requests v ON v.elder_profile_id=p.id WHERE v.status='verified' AND p.owner_user_id<>?",(elder_user_id,))
    for profile in profiles:
        _link_verified_elder_account(conn,profile["id"],profile["owner_user_id"])


def _profile_output(row):
    return {"id": row["id"], "display_name": decrypt(row["display_name"]), "age": row["age"],
            "phone": decrypt(row["phone"]) if row["phone"] else None,
            "whatsapp_id": decrypt(row["whatsapp_ciphertext"]) if row["whatsapp_ciphertext"] else None,
            "notification_name": decrypt(row["notification_name"]) if row["notification_name"] else "",
            "notification_relationship": decrypt(row["notification_relationship"]) if row["notification_relationship"] else "",
            "notification_phone": decrypt(row["notification_phone_ciphertext"]) if row["notification_phone_ciphertext"] else None,
            "notification_contact_consent": bool(row["notification_contact_consent"]),
            "language": row["language"], "city": decrypt(row["city"]), "service_area": decrypt(row["service_area"]),
            "consent_confirmed": bool(row["consent_confirmed"]), "family_access": bool(row["family_access"]),
            "monitoring_consent": bool(row["monitoring_consent"]), "voice_ai_consent": bool(row["voice_ai_consent"]),
            "retention_days": row["retention_days"]}


def _canonical_task(value: str) -> str:
    key=value.strip().casefold()
    return {"errand support":"errands","errand":"errands","walking accompaniment":"walking","walk":"walking","walks":"walking","meal":"meal assistance","medication reminder":"medication reminder","medicine reminder":"medication reminder"}.get(key,key)


def _eligible_matches(conn, city, area, language, category, excluded=None):
    category = _canonical_task(category)
    rows = conn.all("SELECT c.*,u.email FROM contributors c JOIN users u ON u.id=c.user_id WHERE c.identity_state='approved' AND c.training_complete=1 AND c.qualification_passed=1 AND c.availability=1")
    candidates = []
    for row in rows:
        languages = json.loads(row["languages"])
        tasks = {_canonical_task(task) for task in json.loads(row["tasks"])}
        if row["user_id"] == excluded or category not in tasks:
            continue
        if decrypt(row["city"]).casefold() != city.casefold() or decrypt(row["service_area"]).casefold() != area.casefold():
            continue
        if language.casefold() not in [x.casefold() for x in languages]:
            continue
        busy = conn.one("SELECT COUNT(*) AS n FROM bookings WHERE contributor_user_id=? AND (status IN ('confirmed','in_progress') OR (status='offered' AND helper_accepted_at IS NOT NULL))", (row["user_id"],))["n"]
        candidates.append((busy, row))
    candidates.sort(key=lambda item: (item[0], item[1]["created_at"]))
    return [item[1] for item in candidates]


def _new_notification(conn, profile_id, message_type, payload, when=None):
    created = stamp()
    conn.execute("INSERT INTO notifications(id,profile_id,channel,message_type,payload,status,attempts,next_attempt_at,created_at,updated_at) VALUES(?,?,'whatsapp',?,?,'queued',0,?,?,?)",
                 (uid(), profile_id, message_type, json_dump(payload), stamp(when), created, created))


def _queue_alert_notification(conn, profile_id, title, severity):
    _new_notification(conn, profile_id, "alert", {"title":title[:120],"status":severity,"parameters":[severity.upper(),title[:120]]})


@app.get("/api/health")
def health():
    try:
        with db.transaction() as conn:
            conn.one("SELECT 1 AS ready")
        return {"status": "ok", "database": "connected", "environment": settings.APP_ENV}
    except Exception:
        return JSONResponse(status_code=503, content={"status": "unavailable", "database": "disconnected"})


@app.get("/api/system/status")
def system_status():
    worker_status = "BLOCKED: worker heartbeat is missing"
    try:
        with db.transaction() as conn:
            beat = conn.one("SELECT last_seen_at FROM worker_heartbeat WHERE name='carecircle-worker'")
        if beat and now()-datetime.fromisoformat(beat["last_seen_at"]) < timedelta(seconds=60):
            worker_status = "ready"
    except Exception:
        worker_status = "BLOCKED: database is unavailable"
    return {"providers": {"worker": {"configured": worker_status == "ready", "status": worker_status},
                          "personalized_baseline": {"configured": False, "status": "BLOCKED: no client-specific model is trained; current summaries and alert rules are descriptive only"},
                          "wearable_streaming": {"configured": bool(settings.INTEGRATION_KEY), "status": "ready for authenticated partner ingestion" if settings.INTEGRATION_KEY else "BLOCKED: wearable connector and ingestion key are not configured"},
                          "whatsapp": {"configured": settings.configured_provider("whatsapp"), "status": "ready" if settings.configured_provider("whatsapp") else "BLOCKED: WhatsApp credentials, webhook token, app secret, and approved booking, reminder, and alert templates are required"},
                          "voice_ai": {"configured": settings.configured_provider("voice_ai"), "status": "ready" if settings.configured_provider("voice_ai") else "BLOCKED: transcription and language-model credentials are required"},
                          "fitbit": {"configured": settings.configured_provider("fitbit"), "status": "ready" if settings.configured_provider("fitbit") else "BLOCKED: Fitbit app approval, OAuth credentials, redirect URI, and token-encryption key are required"},
                          "razorpay": {"configured": settings.configured_provider("razorpay"), "status": "ready" if settings.configured_provider("razorpay") else "BLOCKED: Razorpay test keys and webhook secret are required"},
                          "partner_network": {"configured": settings.configured_provider("partner"), "status": "BLOCKED: no approved partner adapter contract and credentials are available"}},
            "simulators": "disabled in production; test events must be labelled synthetic"}


@app.get("/api/helpdesk")
def helpdesk_contact(actor=Depends(_actor)):
    return {"name":settings.HELPDESK_NAME,"phone":settings.HELPDESK_PHONE,"email":settings.HELPDESK_EMAIL,"hours":settings.HELPDESK_HOURS,"configured":bool(settings.HELPDESK_PHONE or settings.HELPDESK_EMAIL)}


@app.get("/api/client/overview")
def client_overview(actor=Depends(_actor)):
    _role(actor, "family")
    month = india_now().strftime("%Y-%m")
    with db.transaction() as conn:
        totals = conn.one("SELECT COUNT(*) AS visits,COALESCE(SUM(price_inr),0) AS booked_inr FROM bookings WHERE customer_user_id=? AND substr(service_date,1,7)=? AND status NOT IN ('cancelled')", (actor["id"], month))
        open_alerts = conn.one("SELECT COUNT(*) AS count FROM alerts a JOIN profiles p ON p.id=a.profile_id WHERE (p.owner_user_id=? OR p.id IN (SELECT profile_id FROM care_profile_access WHERE user_id=?)) AND a.status!='closed'", (actor["id"],actor["id"]))["count"]
        active_helpers = conn.one("SELECT COUNT(DISTINCT contributor_user_id) AS count FROM bookings WHERE customer_user_id=? AND substr(service_date,1,7)=? AND contributor_user_id IS NOT NULL AND status NOT IN ('cancelled','unfilled')", (actor["id"], month))["count"]
    return {"month":month,"visits":totals["visits"],"booked_inr":totals["booked_inr"],"monthly_limit_inr":settings.MAX_MONTHLY_CLIENT_SPEND,"remaining_inr":max(0,settings.MAX_MONTHLY_CLIENT_SPEND-totals["booked_inr"]),"active_helpers":active_helpers,"open_alerts":open_alerts}


@app.post("/api/auth/register", status_code=201)
def register(data: Registration, request: Request):
    _limited(request, "register", 6)
    if data.role != "contributor":
        raise HTTPException(403, "Public account creation is for helpers only. The main admin account is managed directly in the database.")
    if len(data.password) < 12 or not re.search(r"[A-Za-z]", data.password) or not re.search(r"\d", data.password):
        raise HTTPException(422, "Password must be at least 12 characters and include letters and a number.")
    if data.role == "family" and not data.family_account:
        raise HTTPException(422, "Add the nominee or family member's own profile details before creating a client account.")
    if data.role == "family" and data.family_account.account_type == "elder" and not data.client_profile:
        raise HTTPException(422, "Complete your elder care profile and notification contact before creating an elder account.")
    if data.role == "family" and data.family_account.account_type == "guardian" and data.client_profile:
        raise HTTPException(422, "Create the guardian account first; add and verify the elder profile after signing in.")
    if data.role == "operator" and (not settings.ADMIN_INVITE_CODE or not hmac.compare_digest(data.admin_invite_code, settings.ADMIN_INVITE_CODE)):
        raise HTTPException(403, "Main admin signup requires the configured administrator invite code.")
    if data.role == "contributor" and len(phone_digits(data.phone))<7:
        raise HTTPException(422,"Enter a phone number with at least 7 digits so the helper can also sign in by phone.")
    if data.role != "family" and data.family_account:
        raise HTTPException(422, "Only Elder or Guardian / relative profiles can create care profiles.")
    if data.role != "family" and data.client_profile:
        raise HTTPException(422, "Only Elder profiles can create an elder care profile during registration.")
    if data.role == "contributor" and data.client_profile:
        raise HTTPException(422, "Helper accounts do not create elder care profiles during registration.")
    if data.role == "contributor" and data.family_account:
        raise HTTPException(422, "Helper accounts do not create a nominee profile during registration.")
    if data.client_profile and (not data.client_profile.consent_confirmed or not data.client_profile.notification_contact_consent or not data.client_profile.family_access):
        raise HTTPException(422, "Confirm the elder's consent, notification contact permission, and visit-request access to continue.")
    ident, created = uid(), stamp()
    with db.transaction() as conn:
        account=data.family_account
        account_phone=account.phone.strip() if account else data.phone.strip() if data.phone else ""
        phone_hash=phone_login_hash(account_phone)
        if phone_hash and conn.one("SELECT id FROM users WHERE account_phone_hash=?",(phone_hash,)):
            raise HTTPException(409,"An account already uses that phone number. Sign in with it or use a different number.")
        inserted = conn.execute("INSERT INTO users(id,email,password_hash,role,created_at,account_name,account_phone_ciphertext,account_relationship,account_type,account_phone_hash) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(email) DO NOTHING",
                                (ident, data.email, password_hash(data.password), data.role, created, encrypt(account.name.strip()) if account else "", encrypt(account_phone) if account_phone else None, encrypt(account.relationship.strip()) if account else "", account.account_type if account else "guardian",phone_hash))
        if inserted.rowcount != 1:
            raise HTTPException(409, "An account already uses that email.")
        _audit(conn, ident, "account_registered", "user", ident, {"role": data.role})
        profile_id = None
        if data.client_profile:
            p = data.client_profile
            elder_whatsapp = (p.whatsapp_id or p.phone).strip()
            profile_id = uid()
            conn.execute("INSERT INTO profiles(id,owner_user_id,display_name,age,phone,whatsapp_ciphertext,whatsapp_id_hash,language,city,service_area,consent_confirmed,family_access,monitoring_consent,voice_ai_consent,retention_days,created_at,notification_name,notification_phone_ciphertext,notification_relationship,notification_contact_consent) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,30,?,?,?,?,?)",
                         (profile_id, ident, encrypt(p.display_name.strip()), p.age, encrypt(p.phone.strip()), encrypt(elder_whatsapp), token_hash("".join(c for c in elder_whatsapp if c.isdigit()), settings.APP_SECRET), p.language.strip(), encrypt(p.city.strip()), encrypt(p.service_area.strip()), 1, 1, int(p.monitoring_consent), int(p.voice_ai_consent), created, encrypt(p.notification_name.strip()), encrypt(p.notification_phone.strip()), encrypt(p.notification_relationship.strip()), 1))
            _audit(conn, ident, "client_profile_created_with_consent", "profile", profile_id, {"notification_contact_consent":True,"monitoring":p.monitoring_consent,"voice_ai":p.voice_ai_consent})
        if account and account.account_type=="elder":
            _link_existing_verified_profiles_for_elder(conn,ident)
    message="Guardian account created. Sign in to add the elder profile and complete identity and relationship verification." if account and account.account_type=="guardian" else "Account and client care profile created. Sign in to continue."
    return {"id": ident, "profile_id": profile_id, "email": data.email, "role": data.role, "account_type":account.account_type if account else "guardian", "message": message}


@app.post("/api/auth/login")
def login(data: Login, request: Request, response: Response):
    _limited(request, "login", 10)
    identifier = data.email.strip()
    with db.transaction() as conn:
        if "@" in identifier:
            user = conn.one("SELECT * FROM users WHERE email=?", (identifier.lower(),))
        else:
            hashed=phone_login_hash(identifier)
            user=conn.one("SELECT * FROM users WHERE account_phone_hash=?",(hashed,)) if hashed else None
            if not user and len(phone_digits(identifier))>=7:
                # Older local accounts predate phone-login hashes. Resolve their
                # encrypted contact once without exposing it in SQL/logs.
                legacy=conn.all("SELECT id,account_phone_ciphertext FROM users WHERE account_phone_ciphertext IS NOT NULL AND account_phone_hash IS NULL")
                match=next((r for r in legacy if phone_digits(decrypt(r["account_phone_ciphertext"]))==phone_digits(identifier)),None)
                if match:
                    conn.execute("UPDATE users SET account_phone_hash=? WHERE id=?",(hashed,match["id"]))
                    user=conn.one("SELECT * FROM users WHERE id=?",(match["id"],))
    if not user or not user["is_active"] or not password_verify(data.password, user["password_hash"]):
        raise HTTPException(401, "Email or password was not accepted.")
    session, csrf = random_token(), random_token(24)
    expires = now() + timedelta(hours=settings.SESSION_HOURS)
    with db.transaction() as conn:
        conn.execute("INSERT INTO sessions(token_hash,csrf_hash,user_id,expires_at,created_at) VALUES(?,?,?,?,?)",
                     (token_hash(session, settings.APP_SECRET), token_hash(csrf, settings.APP_SECRET), user["id"], stamp(expires), stamp()))
        _audit(conn, user["id"], "signed_in", "session", user["id"])
    response.set_cookie("carecircle_session", session, max_age=settings.SESSION_HOURS * 3600, httponly=True,
                        secure=settings.COOKIE_SECURE, samesite="lax", path="/")
    return {"user": {"id": user["id"], "email": user["email"], "role": user["role"]}, "csrf_token": csrf, "expires_at": stamp(expires)}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, actor=Depends(_write_actor)):
    token = request.cookies.get("carecircle_session", "")
    with db.transaction() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(token, settings.APP_SECRET),))
        _audit(conn, actor["id"], "signed_out", "session", actor["id"])
    response.delete_cookie("carecircle_session", path="/", samesite="lax")
    return {"ok": True}


@app.get("/api/auth/me")
def me(actor=Depends(_actor)):
    with db.transaction() as conn:
        user=conn.one("SELECT account_name,account_phone_ciphertext,account_relationship,account_type,avatar_data_url FROM users WHERE id=?",(actor["id"],))
    return {"id": actor["id"], "email": actor["email"], "role": actor["role"],
            "account_type": user["account_type"] if user else "guardian",
            "account_name": decrypt(user["account_name"]) if user and user["account_name"] else "",
            "account_phone": decrypt(user["account_phone_ciphertext"]) if user and user["account_phone_ciphertext"] else "",
            "account_relationship": decrypt(user["account_relationship"]) if user and user["account_relationship"] else "",
            "avatar_data_url": user["avatar_data_url"] if user else ""}


@app.patch("/api/account/avatar")
def update_account_avatar(data: AvatarUpdate, actor=Depends(_write_actor)):
    match=re.fullmatch(r"data:(image/png|image/jpeg|image/webp);base64,([A-Za-z0-9+/]+={0,2})",data.data_url)
    if not match: raise HTTPException(422,"Upload a PNG, JPEG, or WebP profile image.")
    try: image=base64.b64decode(match.group(2),validate=True)
    except (binascii.Error,ValueError): raise HTTPException(422,"The profile image is not valid base64 data.")
    if not image or len(image)>1_000_000: raise HTTPException(413,"Profile images must be smaller than 1 MB.")
    mime=match.group(1)
    valid=(mime=="image/png" and image.startswith(b"\x89PNG\r\n\x1a\n")) or (mime=="image/jpeg" and image.startswith(b"\xff\xd8\xff")) or (mime=="image/webp" and image[:4]==b"RIFF" and image[8:12]==b"WEBP")
    if not valid: raise HTTPException(422,"The file contents do not match the selected image format.")
    with db.transaction() as conn:
        conn.execute("UPDATE users SET avatar_data_url=? WHERE id=?",(data.data_url,actor["id"]))
        _audit(conn,actor["id"],"profile_avatar_updated","user",actor["id"])
    return {"avatar_data_url":data.data_url}


@app.patch("/api/account/profile")
def update_account_profile(data:FamilyAccountUpdate,actor=Depends(_write_actor)):
    _role(actor,"family")
    with db.transaction() as conn:
        phone_hash=phone_login_hash(data.phone)
        duplicate=conn.one("SELECT id FROM users WHERE account_phone_hash=? AND id<>?",(phone_hash,actor["id"])) if phone_hash else None
        if duplicate: raise HTTPException(409,"That phone number is already linked to another account.")
        conn.execute("UPDATE users SET account_name=?,account_phone_ciphertext=?,account_relationship=?,account_phone_hash=? WHERE id=?",(encrypt(data.name.strip()),encrypt(data.phone.strip()),encrypt(data.relationship.strip()),phone_hash,actor["id"]))
        _audit(conn,actor["id"],"family_account_profile_updated","user",actor["id"])
    return {"account_name":data.name.strip(),"account_phone":data.phone.strip(),"account_relationship":data.relationship.strip()}


@app.get("/api/auth/csrf")
def rotate_csrf(request: Request, actor=Depends(_actor)):
    session = request.cookies.get("carecircle_session", "")
    csrf = random_token(24)
    with db.transaction() as conn:
        conn.execute("UPDATE sessions SET csrf_hash=? WHERE token_hash=?", (token_hash(csrf, settings.APP_SECRET), token_hash(session, settings.APP_SECRET)))
    return {"csrf_token": csrf}


@app.get("/api/profiles")
def list_profiles(actor=Depends(_actor)):
    with db.transaction() as conn:
        rows = conn.all("SELECT * FROM profiles WHERE owner_user_id=? OR id IN (SELECT profile_id FROM care_profile_access WHERE user_id=?) ORDER BY created_at DESC", (actor["id"],actor["id"])) if actor["role"] == "family" else conn.all("SELECT * FROM profiles ORDER BY created_at DESC") if actor["role"] == "operator" else []
        if actor["role"] == "operator":
            _audit(conn, actor["id"], "profile_list_access", "profiles", "all")
    return [_profile_output(row) for row in rows]


@app.post("/api/profiles", status_code=201)
def create_profile(data: ProfileInput, actor=Depends(_write_actor)):
    _role(actor, "family")
    if not data.consent_confirmed:
        raise HTTPException(422, "The elderly person’s explicit consent must be confirmed before creating this profile.")
    ident, created = uid(), stamp()
    phone = encrypt(data.phone)
    wa_cipher = encrypt(data.whatsapp_id.strip()) if data.whatsapp_id else None
    notification_phone = encrypt(data.notification_phone.strip()) if data.notification_phone else None
    city, area = encrypt(data.city.strip()), encrypt(data.service_area.strip())
    wa_hash = token_hash("".join(c for c in data.whatsapp_id if c.isdigit()), settings.APP_SECRET) if data.whatsapp_id else None
    with db.transaction() as conn:
        conn.execute("INSERT INTO profiles(id,owner_user_id,display_name,age,phone,whatsapp_ciphertext,whatsapp_id_hash,language,city,service_area,consent_confirmed,family_access,monitoring_consent,voice_ai_consent,retention_days,created_at,notification_name,notification_phone_ciphertext,notification_relationship,notification_contact_consent) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (ident, actor["id"], encrypt(data.display_name.strip()), data.age, phone, wa_cipher, wa_hash, data.language, city, area, int(data.consent_confirmed), int(data.family_access), int(data.monitoring_consent), int(data.voice_ai_consent), data.retention_days, created, encrypt(data.notification_name.strip()) if data.notification_name else "", notification_phone, encrypt(data.notification_relationship.strip()) if data.notification_relationship else "", int(data.notification_contact_consent)))
        _audit(conn, actor["id"], "profile_created_with_consent", "profile", ident, {"monitoring": data.monitoring_consent, "voice_ai": data.voice_ai_consent})
        row = conn.one("SELECT * FROM profiles WHERE id=?", (ident,))
    return _profile_output(row)


@app.patch("/api/profiles/{profile_id}/consent")
def update_profile_consent(profile_id: str, body: dict, actor=Depends(_write_actor)):
    _role(actor, "family")
    allowed = {"family_access", "monitoring_consent", "voice_ai_consent", "notification_contact_consent"}
    if not body or any(k not in allowed or not isinstance(v, bool) for k,v in body.items()):
        raise HTTPException(422, "Update one or more consent controls using boolean values.")
    with db.transaction() as conn:
        row = _profile(conn, profile_id, actor, allow_operator=False)
        fields = list(body)
        assignment = ",".join(f"{field}=?" for field in fields)
        conn.execute(f"UPDATE profiles SET {assignment} WHERE id=?", tuple(int(body[field]) for field in fields)+(profile_id,))
        if body.get("voice_ai_consent") is False:
            conn.execute("UPDATE voice_jobs SET status='blocked',last_error='Consent withdrawn',updated_at=? WHERE id IN (SELECT v.id FROM voice_jobs v JOIN messages m ON m.id=v.message_id WHERE m.profile_id=?) AND status IN ('queued','retry','processing')", (stamp(),profile_id))
        _audit(conn, actor["id"], "profile_consent_updated", "profile", profile_id, {k:v for k,v in body.items()})
        updated = conn.one("SELECT * FROM profiles WHERE id=?", (profile_id,))
    return _profile_output(updated)


@app.patch("/api/profiles/{profile_id}/notification-contact")
def update_notification_contact(profile_id: str, data: NotificationContactUpdate, actor=Depends(_write_actor)):
    _role(actor, "family")
    if not data.notification_contact_consent:
        raise HTTPException(422, "The elder and notification contact must agree before WhatsApp alerts can be sent to this number.")
    elder_whatsapp = (data.elder_whatsapp_id or data.elder_phone).strip()
    with db.transaction() as conn:
        _profile(conn, profile_id, actor, allow_operator=False)
        conn.execute("UPDATE profiles SET phone=?,whatsapp_ciphertext=?,whatsapp_id_hash=?,notification_name=?,notification_phone_ciphertext=?,notification_relationship=?,notification_contact_consent=1 WHERE id=?",
                     (encrypt(data.elder_phone.strip()),encrypt(elder_whatsapp),token_hash("".join(c for c in elder_whatsapp if c.isdigit()),settings.APP_SECRET),encrypt(data.notification_name.strip()),encrypt(data.notification_phone.strip()),encrypt(data.notification_relationship.strip()),profile_id))
        _audit(conn, actor["id"], "notification_contact_updated", "profile", profile_id)
        updated=conn.one("SELECT * FROM profiles WHERE id=?",(profile_id,))
    return _profile_output(updated)


@app.get("/api/contributor")
def get_contributor(actor=Depends(_actor)):
    _role(actor, "contributor", "operator")
    with db.transaction() as conn:
        row = conn.one("SELECT c.*,u.account_phone_ciphertext FROM contributors c JOIN users u ON u.id=c.user_id WHERE c.user_id=?", (actor["id"],))
        account=conn.one("SELECT account_phone_ciphertext FROM users WHERE id=?",(actor["id"],))
    if not row:
        return {"status": "not_started", "identity_state": "pending", "training_complete": False, "qualification_passed": False, "availability": False,"phone":decrypt(account["account_phone_ciphertext"]) if account and account["account_phone_ciphertext"] else ""}
    return {"user_id": row["user_id"], "display_name": decrypt(row["display_name"]), "city": decrypt(row["city"]),
            "service_area": decrypt(row["service_area"]), "languages": json.loads(row["languages"]), "tasks": json.loads(row["tasks"]),
            "phone": decrypt(row["account_phone_ciphertext"]) if row["account_phone_ciphertext"] else "", "date_of_birth": row["date_of_birth"],
            "age": row["age"], "profession": decrypt(row["profession"]) if row["profession"] else "",
            "identity_document_type": row["identity_document_type"], "identity_reference_submitted": bool(row["identity_reference_ciphertext"]),
            "identity_state": row["identity_state"], "training_complete": bool(row["training_complete"]),
            "qualification_passed": bool(row["qualification_passed"]), "availability": bool(row["availability"]), "payout_inr": row["payout_inr"]}


@app.get("/api/contributor/reviews")
def contributor_reviews(actor=Depends(_actor)):
    _role(actor,"contributor")
    with db.transaction() as conn:
        _audit(conn,actor["id"],"contributor_reviews_access","feedback",actor["id"])
        rows=conn.all("SELECT f.rating,f.comment,f.created_at,b.category,b.service_date FROM feedback f JOIN bookings b ON b.id=f.booking_id WHERE b.contributor_user_id=? ORDER BY f.created_at DESC LIMIT 50",(actor["id"],))
    return rows


@app.post("/api/contributor/onboarding", status_code=201)
def contributor_onboarding(data: ContributorInput, actor=Depends(_write_actor)):
    _role(actor, "contributor")
    if not data.identity_consent: raise HTTPException(422,"Consent to identity reference review is required.")
    today=india_now().date()
    age=today.year-data.date_of_birth.year-((today.month,today.day)<(data.date_of_birth.month,data.date_of_birth.day))
    if data.date_of_birth>=today or age<18 or age>100:
        raise HTTPException(422,"Helpers must be between 18 and 100 years old and provide a valid date of birth.")
    allowed = {"errands", "meal assistance", "companionship", "walking accompaniment", "medication reminder"}
    tasks = [x.strip().lower() for x in data.tasks]
    if any(x not in allowed for x in tasks):
        raise HTTPException(422, "Only listed basic assistance tasks are available. Higher-risk personal care and medical tasks are prohibited.")
    city, area = encrypt(data.city), encrypt(data.service_area)
    payout = settings.DEFAULT_CONTRIBUTOR_PAYOUT
    with db.transaction() as conn:
        exists = conn.one("SELECT user_id FROM contributors WHERE user_id=?", (actor["id"],))
        if exists:
            raise HTTPException(409, "Onboarding has already been submitted; ask an operator to review your record.")
        inserted = conn.execute("INSERT INTO contributors(user_id,display_name,service_area,city,languages,tasks,identity_state,training_complete,qualification_passed,availability,payout_inr,created_at,date_of_birth,age,profession,identity_document_type,identity_reference_ciphertext) VALUES(?,?,?,?,?,?,'pending',0,0,0,?,?,?,?,?,?,?) ON CONFLICT(user_id) DO NOTHING",
                                (actor["id"], encrypt(data.display_name.strip()), area, city, json_dump(data.languages), json_dump(tasks), payout, stamp(), data.date_of_birth.isoformat(), age, encrypt(data.profession.strip()), data.identity_document_type, encrypt(data.identity_reference.strip())))
        if inserted.rowcount != 1:
            raise HTTPException(409, "Onboarding has already been submitted.")
        _audit(conn, actor["id"], "contributor_onboarding_submitted", "contributor", actor["id"])
    return {"status": "pending_review", "identity_state": "pending", "training_complete": False, "qualification_passed": False}


@app.get("/api/contributor/training")
def training_modules(actor=Depends(_actor)):
    _role(actor, "contributor")
    return {"modules": ["Safety, boundaries, consent, and escalation", "Privacy, scams, and incident reporting", "Basic assistance and prohibited medical tasks"],
            "qualification": "Submit answers to POST /api/contributor/training/complete. Passing is not practical competency verification.",
            "questions": ["In an immediate emergency, what do you do?", "Can a contributor change medication dosage?", "What should you do if a user reports a fall?"]}


@app.post("/api/contributor/training/complete")
def training_complete(answers: list[str], actor=Depends(_write_actor)):
    _role(actor, "contributor")
    expected = ["call emergency services and notify the coordinator", "no", "call emergency services when warranted and notify the coordinator"]
    passed = len(answers) == 3 and all(a.strip().casefold() == e for a, e in zip(answers, expected))
    with db.transaction() as conn:
        row = conn.one("SELECT user_id FROM contributors WHERE user_id=?", (actor["id"],))
        if not row:
            raise HTTPException(409, "Complete contributor onboarding before training.")
        conn.execute("UPDATE contributors SET training_complete=?,qualification_passed=? WHERE user_id=?", (int(passed), int(passed), actor["id"]))
        _audit(conn, actor["id"], "training_attempt", "contributor", actor["id"], {"passed": passed})
    return {"passed": passed, "training_complete": passed, "qualification_passed": passed, "identity_state": "pending"}


@app.patch("/api/contributor/availability")
def contributor_availability(body: dict, actor=Depends(_write_actor)):
    _role(actor, "contributor")
    available = bool(body.get("available"))
    with db.transaction() as conn:
        row = conn.one("SELECT identity_state,training_complete,qualification_passed FROM contributors WHERE user_id=?", (actor["id"],))
        if not row:
            raise HTTPException(409, "Complete onboarding first.")
        if available and (row["identity_state"] != "approved" or not row["training_complete"] or not row["qualification_passed"]):
            raise HTTPException(403, "Availability requires operator-approved identity review and completed training.")
        conn.execute("UPDATE contributors SET availability=? WHERE user_id=?", (int(available), actor["id"]))
        _audit(conn, actor["id"], "contributor_availability_changed", "contributor", actor["id"], {"available": available})
    return {"availability": available}


@app.get("/api/bookings")
def list_bookings(actor=Depends(_actor)):
    with db.transaction() as conn:
        feedback_ids=set()
        if actor["role"] == "operator":
            rows = conn.all("SELECT b.*,p.display_name AS person FROM bookings b JOIN profiles p ON p.id=b.profile_id ORDER BY b.service_date,b.start_time")
        elif actor["role"] == "family":
            rows = conn.all("SELECT b.*,p.display_name AS person FROM bookings b JOIN profiles p ON p.id=b.profile_id WHERE b.customer_user_id=? OR p.id IN (SELECT profile_id FROM care_profile_access WHERE user_id=?) ORDER BY b.service_date,b.start_time", (actor["id"],actor["id"]))
            feedback_ids={r["booking_id"] for r in conn.all("SELECT booking_id FROM feedback") }
        else:
            rows = conn.all("SELECT b.*,p.display_name AS person,p.phone AS client_phone,p.address_ciphertext,p.notification_name AS contact_name,p.notification_phone_ciphertext AS contact_phone FROM bookings b JOIN profiles p ON p.id=b.profile_id WHERE b.contributor_user_id=? OR (b.status IN ('searching','offered') AND (b.contributor_user_id IS NULL OR b.contributor_user_id=?) AND NOT EXISTS (SELECT 1 FROM booking_ignored i WHERE i.helper_user_id=? AND i.booking_id=b.id)) ORDER BY b.service_date,b.start_time", (actor["id"],actor["id"],actor["id"]))
            contributor=conn.one("SELECT * FROM contributors WHERE user_id=?",(actor["id"],))
            if contributor and contributor["identity_state"]=="approved" and contributor["training_complete"] and contributor["qualification_passed"] and contributor["availability"]:
                rows=[row for row in rows if row["contributor_user_id"]==actor["id"] or actor["id"] in {match["user_id"] for match in _eligible_matches(conn,decrypt(row["city"]),decrypt(row["service_area"]),row["language"],row["category"])}]
            else:
                rows=[row for row in rows if row["contributor_user_id"]==actor["id"]]
        if actor["role"] == "operator":
            _audit(conn, actor["id"], "booking_queue_access", "bookings", "all")
        helper_data={}
        if actor["role"]=="family":
            for booking in rows:
                if booking["contributor_user_id"] and booking["helper_accepted_at"]:
                    helper_data[booking["id"]]=conn.one("SELECT c.display_name,u.account_phone_ciphertext,(SELECT AVG(f.rating) FROM feedback f JOIN bookings rb ON rb.id=f.booking_id WHERE rb.contributor_user_id=u.id) AS average_rating,(SELECT COUNT(*) FROM feedback f JOIN bookings rb ON rb.id=f.booking_id WHERE rb.contributor_user_id=u.id) AS rating_count FROM contributors c JOIN users u ON u.id=c.user_id WHERE u.id=?",(booking["contributor_user_id"],))
        progress_data={}
        if actor["role"]=="contributor":
            for booking in rows:
                progress_data[booking["id"]]=conn.one("SELECT status,created_at FROM booking_updates WHERE booking_id=? ORDER BY created_at DESC LIMIT 1",(booking["id"],))
    result=[]
    for row in rows:
        item={**{k: row[k] for k in ("id","profile_id","category","service_date","start_time","duration_hours","language","status","price_inr","payout_inr","payment_state","contributor_user_id","created_at")}, "person": decrypt(row["person"]), "city": decrypt(row["city"]), "service_area": decrypt(row["service_area"]),"helper_accepted":bool(row["helper_accepted_at"])}
        if actor["role"]=="family":
            item["booked_by_me"]=row["customer_user_id"]==actor["id"]
            item["helper_accepted"]=bool(row["helper_accepted_at"])
            helper=helper_data.get(row["id"])
            item["helper"]={"name":decrypt(helper["display_name"]),"phone":decrypt(helper["account_phone_ciphertext"]) if helper["account_phone_ciphertext"] else None,"average_rating":round(helper["average_rating"],1) if helper["average_rating"] is not None else None,"rating_count":helper["rating_count"]} if helper else None
            item["arrival_code"]=decrypt(row["checkin_otp_ciphertext"]) if row["checkin_otp_ciphertext"] else None
            item["departure_code"]=decrypt(row["checkout_otp_ciphertext"]) if row["checkout_otp_ciphertext"] else None
            item["feedback_submitted"]=row["id"] in feedback_ids
        elif actor["role"]=="contributor":
            update=progress_data.get(row["id"])
            item["progress"]={"status":update["status"],"updated_at":update["created_at"]} if update else {"status":"accepted","updated_at":row["helper_accepted_at"]}
            if row["contributor_user_id"]==actor["id"] and row["helper_accepted_at"]:
                instructions=row["instructions"]
                if instructions and (instructions.startswith("dpapi:v1:") or instructions.startswith("gAAAA")): instructions=decrypt(instructions)
                item["client_details"]={"name":decrypt(row["person"]),"phone":decrypt(row["client_phone"]) if row["client_phone"] else "","address":decrypt(row["address_ciphertext"]) if row["address_ciphertext"] else decrypt(row["service_area"]),"contact_name":decrypt(row["contact_name"]) if row["contact_name"] else "","contact_phone":decrypt(row["contact_phone"]) if row["contact_phone"] else "","instructions":instructions}
        result.append(item)
    return result


@app.get("/api/bookings/fare")
def booking_fare(duration_hours: int=1, actor=Depends(_actor)):
    if actor["role"]!="family" or not 1<=duration_hours<=4:
        raise HTTPException(422,"Choose a supported visit duration.")
    return {"duration_hours":duration_hours,"suggested_fare_inr":settings.DEFAULT_HOURLY_PRICE*duration_hours,"currency":"INR","payment_method":"in_app_only"}


@app.post("/api/bookings", status_code=201)
def create_booking(data: BookingInput, actor=Depends(_write_actor)):
    _role(actor, "family")
    local_now = india_now()
    if data.service_date < local_now.date() or (data.service_date == local_now.date() and data.start_time < local_now.time().replace(tzinfo=None)):
        raise HTTPException(422, "Booking must be scheduled in the future.")
    forbidden = re.compile(r"toileting|intimate hygiene|lifting|injection|dosage|medical procedure", re.I)
    if forbidden.search(data.category) or data.duration_hours > 4:
        raise HTTPException(422, "This task or duration requires additional safeguards and is not enabled in this MVP.")
    allowed_tasks = {"errand support", "meal assistance", "companionship", "walking accompaniment", "medication reminder"}
    if data.category.strip().casefold() not in allowed_tasks:
        raise HTTPException(422, "Select a supported basic assistance task.")
    ident, created = uid(), stamp()
    checkin, checkout = f"{secrets.randbelow(900000)+100000}", f"{secrets.randbelow(900000)+100000}"
    otp_expiry = stamp(datetime.combine(data.service_date, data.start_time).replace(tzinfo=ZoneInfo("Asia/Kolkata"))+timedelta(hours=data.duration_hours+4))
    with db.transaction() as conn:
        profile = _profile(conn, data.profile_id, actor, allow_operator=False)
        _require_identity_verified(conn, actor, data.profile_id)
        if not profile["consent_confirmed"] or not profile["family_access"]:
            raise HTTPException(403, "The elderly person’s consent must allow family booking access.")
        city, area = decrypt(profile["city"]), decrypt(profile["service_area"])
        month = data.service_date.strftime("%Y-%m")
        month_spend = conn.one("SELECT COALESCE(SUM(price_inr),0) AS total FROM bookings WHERE customer_user_id=? AND substr(service_date,1,7)=? AND status NOT IN ('cancelled')", (actor["id"], month))["total"]
        price = data.fare_inr
        payout = round(price * settings.DEFAULT_CONTRIBUTOR_PAYOUT / settings.DEFAULT_HOURLY_PRICE)
        if month_spend + price > settings.MAX_MONTHLY_CLIENT_SPEND:
            raise HTTPException(422, f"This visit would exceed your monthly support budget of ₹{settings.MAX_MONTHLY_CLIENT_SPEND:,}. Current booked total: ₹{month_spend:,}.")
        matches = _eligible_matches(conn, city, area, data.language, data.category.strip().lower())
        assignee = matches[0]["user_id"] if matches else None
        status = "offered" if assignee else "searching"
        conn.execute("INSERT INTO bookings(id,customer_user_id,profile_id,contributor_user_id,category,service_date,start_time,duration_hours,city,service_area,language,instructions,status,price_inr,payout_inr,checkin_otp_hash,checkout_otp_hash,otp_expires_at,created_at,updated_at,checkin_otp_ciphertext,checkout_otp_ciphertext) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (ident, actor["id"], data.profile_id, assignee, data.category, data.service_date.isoformat(), data.start_time.strftime("%H:%M"), data.duration_hours, profile["city"], profile["service_area"], data.language, data.instructions, status, price, payout, token_hash(checkin, settings.APP_SECRET+ident), token_hash(checkout, settings.APP_SECRET+ident), otp_expiry, created, created, encrypt(checkin), encrypt(checkout)))
        _audit(conn, actor["id"], "booking_created", "booking", ident, {"status": status, "automated_match": bool(assignee)})
        _new_notification(conn, data.profile_id, "booking_update", {"booking_id": ident, "status": status})
    return {"id": ident, "status": status, "payment_state":"unpaid", "assigned_contributor_id": assignee, "price_inr": price, "payout_inr": payout,
            "message": "Booking request created. Pay in the app to confirm the service. Separate arrival and departure confirmation codes are available to the client in booking details."}


def _booking(conn, ident, actor):
    row = conn.one("SELECT * FROM bookings WHERE id=?", (ident,))
    if not row:
        raise HTTPException(404, "Booking not found.")
    if actor["role"] == "operator":
        _audit(conn, actor["id"], "booking_detail_access", "booking", ident)
    elif row["customer_user_id"] != actor["id"] and row["contributor_user_id"] != actor["id"] and not (actor["role"]=="family" and _has_profile_access(conn,row["profile_id"],actor["id"])):
        raise HTTPException(403, "You are not authorized to access this booking.")
    return row


@app.post("/api/bookings/{booking_id}/accept")
def accept_booking(booking_id: str, actor=Depends(_write_actor)):
    _role(actor, "contributor")
    with db.transaction() as conn:
        person = conn.one("SELECT * FROM contributors WHERE user_id=?", (actor["id"],))
        if not person or person["identity_state"] != "approved" or not person["training_complete"] or not person["qualification_passed"] or not person["availability"]:
            raise HTTPException(403, "Only approved, trained, qualified, available contributors may accept bookings.")
        row = conn.one("SELECT * FROM bookings WHERE id=?", (booking_id,))
        if not row or row["status"] not in ("searching", "offered"):
            raise HTTPException(409, "Booking is unavailable for acceptance.")
        if row["contributor_user_id"] and row["contributor_user_id"] != actor["id"]:
            raise HTTPException(409, "This booking offer is assigned to another contributor.")
        if decrypt(person["city"]).casefold() != decrypt(row["city"]).casefold() or decrypt(person["service_area"]).casefold() != decrypt(row["service_area"]).casefold():
            raise HTTPException(403, "Contributor is outside the requested service area.")
        task_key = _canonical_task(row["category"])
        if task_key not in {_canonical_task(task) for task in json.loads(person["tasks"])}:
            raise HTTPException(403, "Contributor is not qualified for this task category.")
        if row["language"].casefold() not in [x.casefold() for x in json.loads(person["languages"])]:
            raise HTTPException(403, "Contributor does not match the requested language.")
        next_status="confirmed" if row["payment_state"]=="paid" else "offered"
        updated = conn.execute("UPDATE bookings SET contributor_user_id=?,helper_accepted_at=COALESCE(helper_accepted_at,?),status=?,updated_at=? WHERE id=? AND status IN ('searching','offered') AND (contributor_user_id IS NULL OR contributor_user_id=?)", (actor["id"],stamp(),next_status,stamp(),booking_id,actor["id"]))
        if updated.rowcount != 1:
            raise HTTPException(409, "Another contributor accepted this booking first.")
        _audit(conn, actor["id"], "booking_accepted", "booking", booking_id,{"payment_pending":row["payment_state"]!="paid"})
        _new_notification(conn, row["profile_id"], "booking_update", {"booking_id": booking_id, "status": next_status})
    return {"id": booking_id, "status": next_status,"message":"Helper accepted. Keep the organization updated as you travel and complete the task."}


@app.post("/api/bookings/{booking_id}/ignore", status_code=201)
def ignore_gig(booking_id: str, actor=Depends(_write_actor)):
    _role(actor,"contributor")
    with db.transaction() as conn:
        row=conn.one("SELECT id,status,contributor_user_id FROM bookings WHERE id=?",(booking_id,))
        if not row or row["status"] not in ("searching","offered") or row["contributor_user_id"] not in (None,actor["id"]):
            raise HTTPException(409,"This gig is no longer available to ignore.")
        conn.execute("INSERT INTO booking_ignored(helper_user_id,booking_id,created_at) VALUES(?,?,?) ON CONFLICT(helper_user_id,booking_id) DO NOTHING",(actor["id"],booking_id,stamp()))
        _audit(conn,actor["id"],"gig_ignored","booking",booking_id)
    return {"id":booking_id,"ignored":True}


@app.post("/api/bookings/{booking_id}/progress", status_code=201)
def update_gig_progress(booking_id: str, body: dict, actor=Depends(_write_actor)):
    _role(actor,"contributor")
    progress=str(body.get("status",""))
    sequence=["on_way","reached","helping","done"]
    if progress not in sequence: raise HTTPException(422,"Choose a valid task update.")
    with db.transaction() as conn:
        row=conn.one("SELECT id,contributor_user_id,helper_accepted_at,status FROM bookings WHERE id=?",(booking_id,))
        if not row or row["contributor_user_id"]!=actor["id"] or not row["helper_accepted_at"]:
            raise HTTPException(403,"Accept this gig before sending progress updates.")
        latest=conn.one("SELECT status FROM booking_updates WHERE booking_id=? ORDER BY created_at DESC LIMIT 1",(booking_id,))
        expected=sequence[(sequence.index(latest["status"])+1)] if latest and latest["status"] in sequence[:-1] else "on_way" if not latest else None
        if progress!=expected:
            raise HTTPException(409,"Send task updates in order: on the way, reached, helping, then done.")
        created=stamp()
        conn.execute("INSERT INTO booking_updates(id,booking_id,helper_user_id,status,created_at) VALUES(?,?,?,?,?)",(uid(),booking_id,actor["id"],progress,created))
        if progress=="done": conn.execute("UPDATE bookings SET status='completed',checkout_at=?,updated_at=? WHERE id=?",(created,created,booking_id))
        _audit(conn,actor["id"],"gig_progress_updated","booking",booking_id,{"status":progress})
    return {"id":booking_id,"status":progress,"updated_at":created,"organization_notified":True}


@app.post("/api/admin/gigs", status_code=201)
def create_admin_gig(data: AdminGigInput, actor=Depends(_write_actor)):
    _role(actor,"operator")
    if not data.consent_confirmed: raise HTTPException(422,"Confirm the client authorized sharing these task details with the assigned helper.")
    local_now=india_now()
    if data.service_date<local_now.date() or (data.service_date==local_now.date() and data.start_time<local_now.time().replace(tzinfo=None)):
        raise HTTPException(422,"The gig must be scheduled for a future time.")
    category=data.category.strip()
    if category.casefold() not in {"errand support","meal assistance","companionship","walking accompaniment","medication reminder"}:
        raise HTTPException(422,"Choose a supported basic assistance task.")
    profile_id,booking_id,created=uid(),uid(),stamp()
    checkin,checkout=f"{secrets.randbelow(900000)+100000}",f"{secrets.randbelow(900000)+100000}"
    expires=stamp(datetime.combine(data.service_date,data.start_time).replace(tzinfo=ZoneInfo("Asia/Kolkata"))+timedelta(hours=data.duration_hours+4))
    payout=round(data.fare_inr*settings.DEFAULT_CONTRIBUTOR_PAYOUT/settings.DEFAULT_HOURLY_PRICE)
    with db.transaction() as conn:
        conn.execute("INSERT INTO profiles(id,owner_user_id,display_name,age,phone,whatsapp_ciphertext,whatsapp_id_hash,language,city,service_area,consent_confirmed,family_access,monitoring_consent,voice_ai_consent,retention_days,created_at,notification_name,notification_phone_ciphertext,notification_relationship,notification_contact_consent,address_ciphertext) VALUES(?,?,?,NULL,?,NULL,NULL,?,?,?,?,0,0,0,30,?,?,?,?,1,?)",(profile_id,actor["id"],encrypt(data.client_name.strip()),encrypt(data.client_phone.strip()),data.language.strip(),encrypt(data.city.strip()),encrypt(data.service_area.strip()),1,created,encrypt(data.contact_name.strip()),encrypt(data.contact_phone.strip()),encrypt("Emergency contact"),encrypt(data.client_address.strip())))
        conn.execute("INSERT INTO bookings(id,customer_user_id,profile_id,contributor_user_id,category,service_date,start_time,duration_hours,city,service_area,language,instructions,status,price_inr,payout_inr,checkin_otp_hash,checkout_otp_hash,otp_expires_at,created_at,updated_at,checkin_otp_ciphertext,checkout_otp_ciphertext,payment_state) VALUES(?,?,?,NULL,?,?,?,?,?,?,?,?, 'searching',?,?,?,?,?,?,?,?,?,'unpaid')",(booking_id,actor["id"],profile_id,category,data.service_date.isoformat(),data.start_time.strftime("%H:%M"),data.duration_hours,encrypt(data.city.strip()),encrypt(data.service_area.strip()),data.language.strip(),encrypt(data.instructions.strip()),data.fare_inr,payout,token_hash(checkin,settings.APP_SECRET+booking_id),token_hash(checkout,settings.APP_SECRET+booking_id),expires,created,created,encrypt(checkin),encrypt(checkout)))
        _audit(conn,actor["id"],"admin_gig_created","booking",booking_id,{"category":category,"service_date":data.service_date.isoformat()})
        _new_notification(conn,profile_id,"booking_update",{"booking_id":booking_id,"status":"searching"})
    return {"id":booking_id,"status":"searching","profile_id":profile_id,"price_inr":data.fare_inr,"payout_inr":payout}


@app.get("/api/admin/gigs")
def admin_gigs(actor=Depends(_actor)):
    _role(actor,"operator")
    with db.transaction() as conn:
        _audit(conn,actor["id"],"admin_gig_queue_access","bookings","all")
        rows=conn.all("SELECT b.*,p.display_name AS person,c.display_name AS helper FROM bookings b JOIN profiles p ON p.id=b.profile_id LEFT JOIN contributors c ON c.user_id=b.contributor_user_id WHERE b.customer_user_id=? ORDER BY b.created_at DESC LIMIT 100",(actor["id"],))
        result=[]
        for row in rows:
            last=conn.one("SELECT status,created_at FROM booking_updates WHERE booking_id=? ORDER BY created_at DESC LIMIT 1",(row["id"],))
            result.append({"id":row["id"],"client":decrypt(row["person"]),"category":row["category"],"service_date":row["service_date"],"start_time":row["start_time"],"service_area":decrypt(row["service_area"]),"status":row["status"],"helper":decrypt(row["helper"]) if row["helper"] else "Awaiting helper","progress":last["status"] if last else "pending","progress_at":last["created_at"] if last else None,"fare_inr":row["price_inr"],"payout_inr":row["payout_inr"]})
    return result


@app.post("/api/bookings/{booking_id}/cancel")
def cancel_booking(booking_id: str, actor=Depends(_write_actor)):
    with db.transaction() as conn:
        row = _booking(conn, booking_id, actor)
        _role(actor, "family", "contributor", "operator")
        if actor["role"] == "contributor" and row["contributor_user_id"] != actor["id"]:
            raise HTTPException(403, "Only the assigned contributor may cancel this booking.")
        if row["status"] in ("completed", "cancelled", "in_progress"):
            raise HTTPException(409, "This booking cannot be cancelled in its current state.")
        if actor["role"] == "family":
            new_contributor, status = None, "cancelled"
        else:
            replacement = _eligible_matches(conn, decrypt(row["city"]), decrypt(row["service_area"]), row["language"], row["category"].lower(), row["contributor_user_id"])
            if replacement:
                new_contributor, status = replacement[0]["user_id"], "offered"
            else:
                new_contributor, status = None, "unfilled"
        conn.execute("UPDATE bookings SET contributor_user_id=?,helper_accepted_at=NULL,status=?,updated_at=? WHERE id=?", (new_contributor, status, stamp(), booking_id))
        conn.execute("INSERT INTO cancellation_events(id,booking_id,initiated_by,cancelled_contributor_id,replacement_contributor_id,result,created_at) VALUES(?,?,?,?,?,?,?)", (uid(),booking_id,actor["id"],row["contributor_user_id"],new_contributor,status,stamp()))
        _audit(conn, actor["id"], "booking_cancelled_replacement_search", "booking", booking_id, {"reassigned": bool(new_contributor), "partner_adapter_configured": settings.configured_provider("partner")})
        _new_notification(conn, row["profile_id"], "booking_update", {"booking_id": booking_id, "status": status})
    return {"id": booking_id, "status": status, "replacement_contributor_id": new_contributor,
            "partner_fallback": "BLOCKED: requires configured approved partner network" if not new_contributor else "not_needed"}


@app.post("/api/bookings/{booking_id}/check-in")
def check_in(booking_id: str, body: dict, actor=Depends(_write_actor)):
    _role(actor, "contributor")
    code = str(body.get("otp", ""))
    with db.transaction() as conn:
        row = _booking(conn, booking_id, actor)
        if row["contributor_user_id"] != actor["id"] or row["status"] != "confirmed":
            raise HTTPException(409, "Only the assigned contributor may start a confirmed booking.")
        if datetime.fromisoformat(row["otp_expires_at"]) < now():
            raise HTTPException(422, "Check-in OTP has expired. Contact the coordinator to issue new session codes.")
        session_start = datetime.combine(date.fromisoformat(row["service_date"]), time.fromisoformat(row["start_time"])).replace(tzinfo=ZoneInfo("Asia/Kolkata")).astimezone(timezone.utc)
        if now() < session_start-timedelta(minutes=30):
            raise HTTPException(409, "Check-in is not available more than 30 minutes before the scheduled start.")
        if not hmac.compare_digest(token_hash(code, settings.APP_SECRET+booking_id), row["checkin_otp_hash"]):
            _audit(conn, actor["id"], "check_in_otp_rejected", "booking", booking_id)
            raise HTTPException(422, "Check-in OTP is invalid.")
        conn.execute("UPDATE bookings SET status='in_progress',checkin_at=?,updated_at=? WHERE id=?", (stamp(), stamp(), booking_id))
        _audit(conn, actor["id"], "booking_check_in", "booking", booking_id)
    return {"id": booking_id, "status": "in_progress"}


@app.post("/api/bookings/{booking_id}/check-out")
def check_out(booking_id: str, body: dict, actor=Depends(_write_actor)):
    _role(actor, "contributor")
    code = str(body.get("otp", ""))
    with db.transaction() as conn:
        row = _booking(conn, booking_id, actor)
        if row["contributor_user_id"] != actor["id"] or row["status"] != "in_progress":
            raise HTTPException(409, "Only the assigned contributor may complete an active session.")
        if datetime.fromisoformat(row["otp_expires_at"]) < now():
            raise HTTPException(422, "Check-out OTP has expired. Contact the coordinator for a human completion review.")
        session_start = datetime.combine(date.fromisoformat(row["service_date"]), time.fromisoformat(row["start_time"])).replace(tzinfo=ZoneInfo("Asia/Kolkata")).astimezone(timezone.utc)
        if now() < session_start:
            raise HTTPException(409, "Check-out is not available before the scheduled session start.")
        if not hmac.compare_digest(token_hash(code, settings.APP_SECRET+booking_id), row["checkout_otp_hash"]):
            _audit(conn, actor["id"], "check_out_otp_rejected", "booking", booking_id)
            raise HTTPException(422, "Check-out OTP is invalid.")
        conn.execute("UPDATE bookings SET status='completed',checkout_at=?,updated_at=? WHERE id=?", (stamp(), stamp(), booking_id))
        _audit(conn, actor["id"], "booking_completed", "booking", booking_id, {"payout_inr": row["payout_inr"]})
    return {"id": booking_id, "status": "completed", "payout_state": "pending_payment_settlement"}


@app.post("/api/bookings/{booking_id}/feedback", status_code=201)
def add_feedback(booking_id: str, body: dict, actor=Depends(_write_actor)):
    _role(actor, "family")
    rating = int(body.get("rating", 0))
    if not 1 <= rating <= 5:
        raise HTTPException(422, "Rating must be between 1 and 5.")
    with db.transaction() as conn:
        row = _booking(conn, booking_id, actor)
        if row["status"] != "completed":
            raise HTTPException(403, "Feedback is available after the session is completed.")
        existing=conn.one("SELECT id FROM feedback WHERE booking_id=?",(booking_id,))
        if existing:
            conn.execute("UPDATE feedback SET rating=?,comment=? WHERE id=?",(rating,str(body.get("comment",""))[:1000],existing["id"]))
        else:
            conn.execute("INSERT INTO feedback(id,booking_id,customer_user_id,rating,comment,created_at) VALUES(?,?,?,?,?,?)", (uid(), booking_id, actor["id"], rating, str(body.get("comment", ""))[:1000], stamp()))
        _audit(conn, actor["id"], "booking_feedback", "booking", booking_id, {"rating": rating})
    return {"booking_id": booking_id, "rating": rating}


@app.post("/api/incidents", status_code=201)
def create_incident(data: IncidentInput, actor=Depends(_write_actor)):
    ident = uid()
    with db.transaction() as conn:
        if data.booking_id:
            booking = _booking(conn, data.booking_id, actor)
            profile_id = booking["profile_id"]
        else:
            profile_id = data.profile_id
            if actor["role"] == "family":
                _profile(conn, profile_id, actor, allow_operator=False)
            elif actor["role"] == "contributor":
                raise HTTPException(422, "Contributor incidents must reference a booking.")
            else:
                _role(actor, "operator")
        conn.execute("INSERT INTO incidents(id,booking_id,profile_id,filed_by,category,description,status,created_at,updated_at) VALUES(?,?,?,?,?,?,'open',?,?)", (ident, data.booking_id, profile_id, actor["id"], data.category, data.description, stamp(), stamp()))
        _audit(conn, actor["id"], "incident_filed", "incident", ident)
        if data.category.lower() in ("fall", "urgent", "emergency"):
            title = "Urgent user-reported incident"
            conn.execute("INSERT INTO alerts(id,profile_id,category,title,source,status,created_at,updated_at) VALUES(?,?,'red',?,'user_report','open',?,?)", (uid(), profile_id, title, stamp(), stamp()))
            _queue_alert_notification(conn, profile_id, title, "red")
    return {"id": ident, "status": "open"}


@app.get("/api/incidents")
def list_incidents(actor=Depends(_actor)):
    if actor["role"] != "operator":
        raise HTTPException(403, "Operator role required.")
    with db.transaction() as conn:
        _audit(conn, actor["id"], "incident_queue_access", "incidents", "all")
        return conn.all("SELECT * FROM incidents ORDER BY created_at DESC")


@app.post("/api/admin/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: str, body: dict, actor=Depends(_write_actor)):
    _role(actor, "operator")
    resolution = str(body.get("resolution", "")).strip()
    if len(resolution) < 4:
        raise HTTPException(422, "A human resolution note is required.")
    with db.transaction() as conn:
        row = conn.one("SELECT id,status FROM incidents WHERE id=?", (incident_id,))
        if not row:
            raise HTTPException(404, "Incident not found.")
        if row["status"] != "open":
            raise HTTPException(409, "Incident is already closed.")
        conn.execute("UPDATE incidents SET status='closed',resolution=?,updated_at=? WHERE id=?", (resolution[:1000],stamp(),incident_id))
        _audit(conn, actor["id"], "incident_resolved", "incident", incident_id, {"resolution":resolution[:200]})
    return {"id":incident_id,"status":"closed"}


@app.get("/api/alerts")
def list_alerts(actor=Depends(_actor)):
    with db.transaction() as conn:
        if actor["role"] == "operator":
            _audit(conn, actor["id"], "alert_queue_access", "alerts", "all")
            return conn.all("SELECT * FROM alerts ORDER BY CASE category WHEN 'red' THEN 0 WHEN 'yellow' THEN 1 ELSE 2 END,created_at")
        if actor["role"] == "family":
            return conn.all("SELECT a.* FROM alerts a JOIN profiles p ON p.id=a.profile_id WHERE p.owner_user_id=? OR p.id IN (SELECT profile_id FROM care_profile_access WHERE user_id=?) ORDER BY a.created_at DESC", (actor["id"],actor["id"]))
        return []


@app.post("/api/admin/alerts", status_code=201)
def operator_create_alert(body: dict, actor=Depends(_write_actor)):
    _role(actor, "operator")
    category = body.get("category", "yellow")
    title = str(body.get("title", "")).strip()
    profile_id = str(body.get("profile_id", ""))
    source = str(body.get("source", "operator_report"))[:80]
    if category not in {"yellow", "red"} or not title or len(title) > 160:
        raise HTTPException(422, "Provide a short title and yellow or red severity.")
    ident = uid()
    with db.transaction() as conn:
        profile = conn.one("SELECT id FROM profiles WHERE id=?", (profile_id,))
        if not profile:
            raise HTTPException(404, "Profile not found.")
        conn.execute("INSERT INTO alerts(id,profile_id,category,title,source,status,created_at,updated_at) VALUES(?,?,?,?,?,'open',?,?)", (ident, profile_id, category, title, source, stamp(), stamp()))
        _queue_alert_notification(conn, profile_id, title, category)
        _audit(conn, actor["id"], "operator_alert_created", "alert", ident, {"category": category})
    return {"id": ident, "status": "open", "category": category}


@app.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str, actor=Depends(_write_actor)):
    _role(actor, "operator")
    with db.transaction() as conn:
        row = conn.one("SELECT * FROM alerts WHERE id=?", (alert_id,))
        if not row:
            raise HTTPException(404, "Alert not found.")
        if row["status"] == "closed":
            raise HTTPException(409, "Closed alert cannot be acknowledged.")
        conn.execute("UPDATE alerts SET status='acknowledged',assigned_user_id=?,updated_at=? WHERE id=?", (actor["id"], stamp(), alert_id))
        _audit(conn, actor["id"], "alert_acknowledged", "alert", alert_id, {"category": row["category"]})
    return {"id": alert_id, "status": "acknowledged"}


@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: str, body: dict, actor=Depends(_write_actor)):
    _role(actor, "operator")
    note = str(body.get("response_note", "")).strip()
    if len(note) < 4:
        raise HTTPException(422, "A response note is required to close an alert.")
    with db.transaction() as conn:
        row = conn.one("SELECT * FROM alerts WHERE id=?", (alert_id,))
        if not row:
            raise HTTPException(404, "Alert not found.")
        if row["status"] == "open":
            raise HTTPException(409, "A human operator must acknowledge and assign an alert before closure.")
        if row["category"] == "red" and not row["assigned_user_id"]:
            raise HTTPException(409, "A red alert must be acknowledged and assigned before it can close.")
        conn.execute("UPDATE alerts SET status='closed',response_note=?,updated_at=? WHERE id=?", (note[:1000], stamp(), alert_id))
        _audit(conn, actor["id"], "alert_resolved", "alert", alert_id, {"response_note": note[:200]})
    return {"id": alert_id, "status": "closed"}


@app.post("/api/reminders", status_code=201)
def schedule_reminder(data: ReminderInput, actor=Depends(_write_actor)):
    _role(actor, "family")
    if data.due_at <= now():
        raise HTTPException(422, "Reminder time must be in the future.")
    ident = uid()
    with db.transaction() as conn:
        profile = _profile(conn, data.profile_id, actor, allow_operator=False)
        _require_identity_verified(conn, actor, data.profile_id)
        if not profile["consent_confirmed"]:
            raise HTTPException(403, "Profile consent is required.")
        conn.execute("INSERT INTO reminders(id,profile_id,created_by,title,due_at,status,attempts,next_attempt_at,created_at) VALUES(?,?,?,?,?,'scheduled',0,?,?)", (ident, data.profile_id, actor["id"], data.title, stamp(data.due_at), stamp(data.due_at), stamp()))
        _audit(conn, actor["id"], "reminder_scheduled", "reminder", ident)
    return {"id": ident, "status": "scheduled", "delivery": "background worker"}


@app.get("/api/reminders")
def get_reminders(actor=Depends(_actor)):
    with db.transaction() as conn:
        if actor["role"] == "family":
            return conn.all("SELECT r.* FROM reminders r JOIN profiles p ON p.id=r.profile_id WHERE p.owner_user_id=? OR p.id IN (SELECT profile_id FROM care_profile_access WHERE user_id=?) ORDER BY due_at", (actor["id"],actor["id"]))
        if actor["role"] == "operator":
            return conn.all("SELECT * FROM reminders ORDER BY due_at")
    return []


@app.post("/api/reminders/{reminder_id}/cancel")
def cancel_reminder(reminder_id: str, actor=Depends(_write_actor)):
    _role(actor, "family")
    with db.transaction() as conn:
        row=conn.one("SELECT r.id,r.status FROM reminders r JOIN profiles p ON p.id=r.profile_id WHERE r.id=? AND (p.owner_user_id=? OR p.id IN (SELECT profile_id FROM care_profile_access WHERE user_id=?))",(reminder_id,actor["id"],actor["id"]))
        if not row:
            raise HTTPException(404,"Reminder not found.")
        if row["status"] not in ("scheduled","queued","blocked","failed"):
            raise HTTPException(409,"This reminder has already been delivered or cancelled.")
        conn.execute("UPDATE reminders SET status='cancelled' WHERE id=?",(reminder_id,))
        _audit(conn,actor["id"],"reminder_cancelled","reminder",reminder_id)
    return {"id":reminder_id,"status":"cancelled"}


@app.get("/api/profiles/{profile_id}/identity-verification")
def identity_verification_status(profile_id: str, actor=Depends(_actor)):
    _role(actor,"family")
    with db.transaction() as conn:
        _profile(conn,profile_id,actor,allow_operator=False)
        row=conn.one("SELECT status,review_note,submitted_at FROM identity_verification_requests WHERE elder_profile_id=? ORDER BY submitted_at DESC LIMIT 1",(profile_id,))
    return {"status":row["status"] if row else "not_submitted","review_note":row["review_note"] if row else "","submitted_at":row["submitted_at"] if row else None}


@app.post("/api/profiles/{profile_id}/identity-verification",status_code=201)
def submit_identity_verification(profile_id:str,data:IdentityVerificationSubmission,actor=Depends(_write_actor)):
    _role(actor,"family")
    with db.transaction() as conn:
        _profile(conn,profile_id,actor,allow_operator=False)
        account=conn.one("SELECT account_type FROM users WHERE id=?",(actor["id"],))
        if account["account_type"]=="elder":
            if len(data.elder_identity_reference.strip())<4:
                raise HTTPException(422,"Enter the verification reference from the authorized identity provider.")
            guardian_ref=data.elder_identity_reference.strip();relationship_type="Self";relationship_ref="self-account"
        else:
            if len(data.guardian_identity_reference.strip())<4 or len(data.elder_identity_reference.strip())<4 or len(data.relationship_proof_type.strip())<2 or len(data.relationship_proof_reference.strip())<4:
                raise HTTPException(422,"Both identity-provider references and the relationship-proof reference are required.")
            guardian_ref=data.guardian_identity_reference.strip();relationship_type=data.relationship_proof_type.strip();relationship_ref=data.relationship_proof_reference.strip()
        if not data.consent_confirmed:
            raise HTTPException(422,"Confirm consent to submit these verification references for human review.")
        ident=uid();created=stamp()
        if conn.one("SELECT owner_user_id FROM profiles WHERE id=?",(profile_id,))["owner_user_id"]!=actor["id"]:
            raise HTTPException(403,"Only the account that manages this elder profile can submit relationship verification.")
        conn.execute("INSERT INTO identity_verification_requests(id,guardian_user_id,elder_profile_id,guardian_identity_reference_ciphertext,elder_identity_reference_ciphertext,relationship_proof_reference_ciphertext,relationship_proof_type,status,submitted_at,updated_at) VALUES(?,?,?,?,?,?,?,'pending',?,?) ON CONFLICT(elder_profile_id) DO UPDATE SET guardian_user_id=excluded.guardian_user_id,guardian_identity_reference_ciphertext=excluded.guardian_identity_reference_ciphertext,elder_identity_reference_ciphertext=excluded.elder_identity_reference_ciphertext,relationship_proof_reference_ciphertext=excluded.relationship_proof_reference_ciphertext,relationship_proof_type=excluded.relationship_proof_type,status='pending',reviewed_by=NULL,review_note='',submitted_at=excluded.submitted_at,updated_at=excluded.updated_at",(ident,actor["id"],profile_id,encrypt(guardian_ref),encrypt(data.elder_identity_reference.strip()),encrypt(relationship_ref),relationship_type,created,created))
        conn.execute("DELETE FROM care_profile_access WHERE profile_id=?",(profile_id,))
        _audit(conn,actor["id"],"identity_verification_submitted","profile",profile_id)
    return {"profile_id":profile_id,"status":"pending"}


@app.get("/api/admin/identity-verifications")
def identity_verification_queue(actor=Depends(_actor)):
    _role(actor,"operator")
    with db.transaction() as conn:
        rows=conn.all("SELECT v.*,p.display_name,p.notification_relationship,u.account_name FROM identity_verification_requests v JOIN profiles p ON p.id=v.elder_profile_id JOIN users u ON u.id=v.guardian_user_id ORDER BY CASE v.status WHEN 'pending' THEN 0 ELSE 1 END,v.submitted_at DESC LIMIT 200")
        _audit(conn,actor["id"],"identity_verification_queue_accessed","identity_verification_requests","all")
    return [{"id":r["id"],"profile_id":r["elder_profile_id"],"elder_name":decrypt(r["display_name"]),"guardian_name":decrypt(r["account_name"]) if r["account_name"] else "Guardian","relationship":decrypt(r["notification_relationship"]) if r["notification_relationship"] else "","guardian_identity_reference":decrypt(r["guardian_identity_reference_ciphertext"]),"elder_identity_reference":decrypt(r["elder_identity_reference_ciphertext"]),"relationship_proof_type":r["relationship_proof_type"],"relationship_proof_reference":decrypt(r["relationship_proof_reference_ciphertext"]) if r["relationship_proof_reference_ciphertext"] else "","status":r["status"],"review_note":r["review_note"],"submitted_at":r["submitted_at"]} for r in rows]


@app.patch("/api/admin/identity-verifications/{verification_id}")
def review_identity_verification(verification_id:str,data:IdentityVerificationReview,actor=Depends(_write_actor)):
    _role(actor,"operator")
    if data.status=="rejected" and len(data.review_note.strip())<5:
        raise HTTPException(422,"Add a short reason so the family can correct the verification submission.")
    with db.transaction() as conn:
        row=conn.one("SELECT * FROM identity_verification_requests WHERE id=?",(verification_id,))
        if not row: raise HTTPException(404,"Verification request not found.")
        conn.execute("UPDATE identity_verification_requests SET status=?,reviewed_by=?,review_note=?,updated_at=? WHERE id=?",(data.status,actor["id"],data.review_note.strip(),stamp(),verification_id))
        if data.status=="verified": _link_verified_elder_account(conn,row["elder_profile_id"],row["guardian_user_id"])
        else: conn.execute("DELETE FROM care_profile_access WHERE profile_id=?",(row["elder_profile_id"],))
        _audit(conn,actor["id"],"identity_verification_reviewed","identity_verification_request",verification_id,{"status":data.status})
    return {"id":verification_id,"status":data.status}


@app.get("/api/messages")
def get_messages(actor=Depends(_actor)):
    with db.transaction() as conn:
        if actor["role"] == "operator":
            _audit(conn, actor["id"], "message_queue_access", "messages", "all")
            return conn.all("SELECT id,provider,profile_id,direction,kind,received_at,status,intent,transcript FROM messages ORDER BY received_at DESC LIMIT 200")
        if actor["role"] == "family":
            return conn.all("SELECT m.id,m.provider,m.profile_id,m.direction,m.kind,m.received_at,m.status,m.intent,m.transcript FROM messages m JOIN profiles p ON p.id=m.profile_id WHERE p.owner_user_id=? OR p.id IN (SELECT profile_id FROM care_profile_access WHERE user_id=?) ORDER BY m.received_at DESC LIMIT 200", (actor["id"],actor["id"]))
    return []


@app.post("/api/client/reports", status_code=201)
def create_client_report(data: ClientReportInput, actor=Depends(_write_actor)):
    _role(actor, "family")
    profile_id = data.profile_id
    category = data.category.strip()
    description = data.description.strip()
    if len(description) < 5:
        raise HTTPException(422, "Please add a little more detail so the team can follow up.")
    ident, created = uid(), stamp()
    normalized = category.casefold()
    is_emergency = data.severity == "red" or any(word in normalized for word in ("fall", "emergency"))
    severity = "red" if data.severity == "red" else "yellow" if data.severity == "yellow" else None
    if any(word in normalized for word in ("fall", "emergency")):
        severity = "red"
    elif severity is None and any(word in normalized for word in ("medical", "scam", "safety")):
        severity = "yellow"
    with db.transaction() as conn:
        profile = _profile(conn, profile_id, actor, allow_operator=False)
        if not profile["consent_confirmed"]:
            raise HTTPException(403, "Active profile consent is required to send a report.")
        conn.execute("INSERT INTO incidents(id,profile_id,filed_by,category,description,status,created_at,updated_at) VALUES(?,?,?, ?,?,'open',?,?)", (ident, profile_id, actor["id"], category, description, created, created))
        conn.execute("INSERT INTO messages(id,provider,provider_message_id,profile_id,direction,kind,received_at,status,intent,transcript) VALUES(?, 'client_portal', ?, ?, 'inbound', 'text', ?, 'human_review', ?, ?)", (uid(), "client:"+ident, profile_id, created, "urgent" if severity == "red" else category, description))
        alert_id = None
        if severity:
            alert_id = uid()
            title = f"Client report · {category}"[:160]
            conn.execute("INSERT INTO alerts(id,profile_id,category,title,source,status,created_at,updated_at) VALUES(?,?,?,?,?,'open',?,?)", (alert_id, profile_id, severity, title, "client_report", created, created))
            _queue_alert_notification(conn, profile_id, title, severity)
        _audit(conn, actor["id"], "client_report_submitted", "incident", ident, {"category":category,"severity":severity or "routine","language":data.language})
    return {"id": ident, "status": "received_for_human_review", "alert_id": alert_id, "emergency_guidance": "For immediate danger, call 112 now. This service is not an emergency response service." if is_emergency else None}


@app.get("/api/profiles/{profile_id}/readings")
def profile_readings(profile_id: str, actor=Depends(_actor)):
    with db.transaction() as conn:
        profile = _profile(conn, profile_id, actor, allow_operator=True)
        if not profile["monitoring_consent"] and actor["role"] != "operator":
            raise HTTPException(403, "Wearable or health reading consent is not active.")
        rows = conn.all("SELECT id,provider,metric,value,unit,observed_at,quality FROM sensor_readings WHERE profile_id=? ORDER BY observed_at DESC LIMIT 50", (profile_id,))
        summary = conn.all("SELECT metric,COUNT(*) AS count,AVG(value) AS average,MIN(value) AS minimum,MAX(value) AS maximum FROM sensor_readings WHERE profile_id=? AND observed_at>=? GROUP BY metric", (profile_id, stamp(now()-timedelta(days=30))))
        if actor["role"] == "operator":
            _audit(conn, actor["id"], "profile_readings_access", "profile", profile_id)
    return {"readings": rows, "descriptive_30_day_summary": summary, "model_status": "No personalized model trained. These are descriptive measurements and are not a diagnosis."}


@app.post("/api/client/readings", status_code=201)
def create_client_reading(data: ClientReadingInput, actor=Depends(_write_actor)):
    _role(actor, "family")
    allowed = {"heart_rate":(20,250,"bpm"),"spo2":(50,100,"%"),"bp_systolic":(50,300,"mmHg"),"bp_diastolic":(20,200,"mmHg"),"skin_temperature":(20,45,"c"),"motion":(0,1000,"count"),"fall_alert":(0,1,"boolean")}
    if data.metric not in allowed:
        raise HTTPException(422, "Choose a supported reading type.")
    lower, upper, unit = allowed[data.metric]
    if not lower <= data.value <= upper or data.unit.casefold() != unit.casefold():
        raise HTTPException(422, "Reading failed range or unit validation.")
    if data.observed_at > now()+timedelta(minutes=5):
        raise HTTPException(422, "Reading timestamp cannot be in the future.")
    ident, created = uid(), stamp()
    with db.transaction() as conn:
        profile = _profile(conn, data.profile_id, actor, allow_operator=False)
        if not profile["monitoring_consent"]:
            raise HTTPException(403, "Turn on monitoring consent for this profile before recording health readings.")
        conn.execute("INSERT INTO sensor_readings(id,profile_id,provider,metric,value,unit,observed_at,quality,event_key) VALUES(?,?, 'client_entry', ?,?,?,?,'self_reported',NULL)", (ident,data.profile_id,data.metric,data.value,data.unit,stamp(data.observed_at)))
        category = None
        title = ""
        if data.metric == "fall_alert" and data.value == 1:
            category,title = "red","Client-reported fall · urgent human follow-up"
        elif data.metric == "heart_rate" and (data.value < settings.ALERT_HR_LOW or data.value > settings.ALERT_HR_HIGH):
            category,title = "yellow","Self-reported heart rate outside configurable review range"
        elif data.metric == "spo2" and data.value < settings.ALERT_SPO2_LOW:
            category,title = "yellow","Self-reported SpO₂ outside configurable review range"
        alert_id = None
        if category:
            alert_id = uid()
            conn.execute("INSERT INTO alerts(id,profile_id,category,title,source,status,created_at,updated_at) VALUES(?,?,?,?,?,'open',?,?)", (alert_id,data.profile_id,category,title,"client_reading",created,created))
            _queue_alert_notification(conn, data.profile_id, title, category)
        _audit(conn, actor["id"], "client_reading_recorded", "sensor_reading", ident, {"metric":data.metric,"unit":data.unit})
    return {"id":ident,"status":"recorded_for_human_review" if category else "recorded","alert_id":alert_id,"model_status":"No personalized model trained; thresholds are configurable review rules, not clinical advice."}


@app.post("/api/admin/messages/{message_id}/review")
def review_message(message_id: str, body: dict, actor=Depends(_write_actor)):
    _role(actor, "operator")
    note = str(body.get("note", "")).strip()
    if len(note) < 4:
        raise HTTPException(422, "Add a concise human review note.")
    with db.transaction() as conn:
        row = conn.one("SELECT id,status FROM messages WHERE id=?", (message_id,))
        if not row:
            raise HTTPException(404, "Message not found.")
        conn.execute("UPDATE messages SET status='reviewed' WHERE id=?", (message_id,))
        _audit(conn, actor["id"], "message_reviewed", "message", message_id, {"note":note[:200]})
    return {"id":message_id,"status":"reviewed"}


@app.post("/api/integrations/wearables/readings", status_code=201)
def ingest_reading(data: ReadingInput, x_integration_key: str | None = Header(default=None)):
    if not settings.INTEGRATION_KEY or not x_integration_key or not hmac.compare_digest(x_integration_key, settings.INTEGRATION_KEY):
        raise HTTPException(401, "Authorized wearable connector key required.")
    allowed = {"heart_rate": (20, 250, "bpm"), "spo2": (50, 100, "%"), "bp_systolic": (50, 300, "mmHg"), "bp_diastolic": (20, 200, "mmHg"), "skin_temperature": (20, 45, "c"), "motion": (0, 1000, "count"), "fall_alert": (0, 1, "boolean")}
    if data.metric not in allowed:
        raise HTTPException(422, "Unsupported metric.")
    lower, upper, unit = allowed[data.metric]
    if not lower <= data.value <= upper or data.unit.casefold() != unit:
        raise HTTPException(422, "Reading failed range or unit validation.")
    if data.observed_at > now() + timedelta(minutes=5):
        raise HTTPException(422, "Reading timestamp is in the future.")
    ident = uid()
    with db.transaction() as conn:
        profile = conn.one("SELECT monitoring_consent FROM profiles WHERE id=?", (data.profile_id,))
        if not profile or not profile["monitoring_consent"]:
            raise HTTPException(403, "Monitoring consent is not active for this profile.")
        inserted = conn.execute("INSERT INTO sensor_readings(id,profile_id,provider,metric,value,unit,observed_at,quality,event_key) VALUES(?,?,?,?,?,?,?,'validated',?) ON CONFLICT(event_key) DO NOTHING", (ident, data.profile_id, data.provider, data.metric, data.value, data.unit, stamp(data.observed_at), data.event_key))
        if inserted.rowcount != 1:
            return {"duplicate": True, "alert": None}
        alert_id = None
        category = None
        if data.metric == "fall_alert" and data.value == 1:
            category, title = "red", "Device-native fall alert · urgent follow-up"
        elif data.metric in ("spo2", "heart_rate"):
            lower = settings.ALERT_SPO2_LOW if data.metric == "spo2" else settings.ALERT_HR_LOW
            upper = settings.ALERT_HR_HIGH if data.metric == "heart_rate" else None
            baseline = conn.all("SELECT value FROM sensor_readings WHERE profile_id=? AND metric=? AND observed_at>=? ORDER BY observed_at DESC LIMIT 200", (data.profile_id, data.metric, stamp(now()-timedelta(days=30))))
            baseline_values = [float(x["value"]) for x in baseline]
            unusual_baseline = False
            if len(baseline_values) >= 20:
                mean = sum(baseline_values)/len(baseline_values)
                variance = sum((x-mean)**2 for x in baseline_values)/len(baseline_values)
                deviation = variance**0.5
                unusual_baseline = deviation > 0 and abs(data.value-mean) > 3*deviation
            outside_configured_range = data.value < lower or (upper is not None and data.value > upper)
            if outside_configured_range or unusual_baseline:
                category, title = "yellow", "Sensor value outside configurable review range or descriptive baseline"
        else:
            title = ""
        if category:
            alert_id = uid()
            conn.execute("INSERT INTO alerts(id,profile_id,category,title,source,status,event_key,created_at,updated_at) VALUES(?,?,?,?,?,'open',?,?,?)",
                         (alert_id, data.profile_id, category, title, "provider:"+data.provider, data.event_key, stamp(), stamp()))
            _queue_alert_notification(conn, data.profile_id, title, category)
            _audit(conn, None, "sensor_alert_created", "alert", alert_id, {"provider": data.provider, "synthetic": False})
    return {"id": ident, "alert_id": alert_id, "alert_category": category, "clinical_diagnosis": False}


@app.get("/api/admin/contributors")
def admin_contributors(actor=Depends(_actor)):
    _role(actor, "operator")
    with db.transaction() as conn:
        _audit(conn, actor["id"], "contributor_queue_access", "contributors", "all")
        rows = conn.all("SELECT c.*,u.account_phone_ciphertext FROM contributors c JOIN users u ON u.id=c.user_id ORDER BY c.created_at")
        return [{"user_id": r["user_id"], "display_name": decrypt(r["display_name"]), "date_of_birth": r["date_of_birth"], "age": r["age"], "profession": decrypt(r["profession"]) if r["profession"] else "", "phone": decrypt(r["account_phone_ciphertext"]) if r["account_phone_ciphertext"] else "", "identity_document_type": r["identity_document_type"], "identity_reference": decrypt(r["identity_reference_ciphertext"]) if r["identity_reference_ciphertext"] else "", "city": decrypt(r["city"]), "service_area": decrypt(r["service_area"]), "languages": json.loads(r["languages"]), "tasks": json.loads(r["tasks"]), "identity_state": r["identity_state"], "training_complete": bool(r["training_complete"]), "qualification_passed": bool(r["qualification_passed"]), "availability": bool(r["availability"])} for r in rows]


@app.patch("/api/admin/contributors/{contributor_id}")
def review_contributor(contributor_id: str, body: dict, actor=Depends(_write_actor)):
    _role(actor, "operator")
    state = body.get("identity_state")
    if state not in {"approved", "rejected", "pending"}:
        raise HTTPException(422, "Invalid identity review state.")
    with db.transaction() as conn:
        row = conn.one("SELECT * FROM contributors WHERE user_id=?", (contributor_id,))
        if not row:
            raise HTTPException(404, "Contributor not found.")
        available = 0 if state != "approved" else row["availability"]
        conn.execute("UPDATE contributors SET identity_state=?,availability=? WHERE user_id=?", (state, available, contributor_id))
        _audit(conn, actor["id"], "contributor_identity_review", "contributor", contributor_id, {"identity_state": state})
    return {"user_id": contributor_id, "identity_state": state}


@app.get("/api/admin/analytics")
def analytics(actor=Depends(_actor)):
    _role(actor, "operator")
    with db.transaction() as conn:
        totals = conn.one("SELECT COUNT(*) AS bookings, COALESCE(SUM(CASE WHEN status='completed' THEN price_inr ELSE 0 END),0) AS customer_cost, COALESCE(SUM(CASE WHEN status='completed' THEN payout_inr ELSE 0 END),0) AS contributor_compensation, SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) AS completed, SUM(CASE WHEN status='unfilled' THEN 1 ELSE 0 END) AS unfilled FROM bookings")
        platform_counts = {"users":conn.one("SELECT COUNT(*) AS n FROM users WHERE is_active=1")["n"],"profiles":conn.one("SELECT COUNT(*) AS n FROM profiles")["n"],"contributors":conn.one("SELECT COUNT(*) AS n FROM contributors")["n"],"reminders":conn.one("SELECT COUNT(*) AS n FROM reminders")["n"],"readings":conn.one("SELECT COUNT(*) AS n FROM sensor_readings")["n"],"messages":conn.one("SELECT COUNT(*) AS n FROM messages")["n"],"communities":conn.one("SELECT COUNT(*) AS n FROM communities WHERE status='active'")["n"]}
        automation = conn.one("SELECT COUNT(*) AS n FROM audit_log WHERE action IN ('booking_accepted','reminder_scheduled','booking_created') AND metadata LIKE '%true%'")
        alerts = conn.one("SELECT COUNT(*) AS total,SUM(CASE WHEN status='closed' THEN 1 ELSE 0 END) AS closed FROM alerts")
        cancel = conn.one("SELECT COUNT(*) AS total,SUM(CASE WHEN c.result='offered' THEN 1 ELSE 0 END) AS recovered FROM cancellation_events c JOIN users u ON u.id=c.initiated_by WHERE u.role='contributor'")
        match_events = conn.all("SELECT b.created_at,a.created_at AS accepted_at FROM bookings b JOIN audit_log a ON a.entity_type='booking' AND a.entity_id=b.id AND a.action='booking_accepted' WHERE b.status='completed'")
        avg_op_minutes = conn.one("SELECT AVG(CAST(json_extract(metadata,'$.operator_minutes') AS REAL)) AS minutes FROM audit_log WHERE json_extract(metadata,'$.operator_minutes') IS NOT NULL") if conn.dialect == "sqlite" else {"minutes": None}
        _audit(conn, actor["id"], "operational_analytics_access", "analytics", "summary")
    bookings = totals["bookings"] or 0
    completed = totals["completed"] or 0
    return {"source": "database records", **platform_counts, "bookings": bookings, "completed": completed,
            "fulfilment_rate": round(completed/bookings, 3) if bookings else None,
            "unfilled": totals["unfilled"] or 0, "customer_charges_inr": totals["customer_cost"],
            "contributor_compensation_inr": totals["contributor_compensation"],
            "alert_count": alerts["total"] or 0, "alert_closure_rate": round((alerts["closed"] or 0)/alerts["total"],3) if alerts["total"] else None,
            "human_operator_minutes_per_request": avg_op_minutes["minutes"],
            "contributor_cancellation_recovery_rate": round((cancel["recovered"] or 0)/cancel["total"],3) if cancel["total"] else None,
            "average_matching_seconds": round(sum((datetime.fromisoformat(x["accepted_at"])-datetime.fromisoformat(x["created_at"])).total_seconds() for x in match_events)/len(match_events),1) if match_events else None,
            "platform_contribution_before_operating_cost_inr": totals["customer_cost"]-totals["contributor_compensation"],
            "cost_per_completed_booking_inr": round(totals["customer_cost"]/completed,2) if completed else None,
            "measured_savings": None, "savings_note": "No baseline experiment has been recorded; do not claim savings from estimates."}


@app.get("/api/admin/audit")
def admin_audit(actor=Depends(_actor), limit: int = 100):
    _role(actor, "operator")
    with db.transaction() as conn:
        _audit(conn, actor["id"], "admin_activity_access", "audit_log", "recent", {"limit": max(1,min(limit,500))})
        return conn.all("SELECT a.id,a.actor_user_id,u.email AS actor_email,a.action,a.entity_type,a.entity_id,a.metadata,a.created_at FROM audit_log a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.created_at DESC LIMIT ?", (max(1,min(limit,500)),))


@app.get("/api/admin/users")
def admin_users(actor=Depends(_actor)):
    _role(actor, "operator")
    with db.transaction() as conn:
        rows = conn.all("""SELECT u.id,u.email,u.role,u.account_type,u.account_name,u.account_phone_ciphertext,u.account_relationship,u.is_active,u.created_at,
          (SELECT COUNT(*) FROM profiles p WHERE p.owner_user_id=u.id) AS profile_count,
          (SELECT MAX(a.created_at) FROM audit_log a WHERE a.actor_user_id=u.id) AS last_activity,
          c.identity_state,c.training_complete,c.qualification_passed,c.availability
          FROM users u LEFT JOIN contributors c ON c.user_id=u.id ORDER BY u.created_at DESC""")
        _audit(conn, actor["id"], "admin_user_directory_access", "users", "all", {"count": len(rows)})
    result=[]
    for row in rows:
        result.append({"id":row["id"],"email":row["email"],"role":row["role"],"account_type":row["account_type"],
          "name":decrypt(row["account_name"]) if row["account_name"] else "",
          "phone":decrypt(row["account_phone_ciphertext"]) if row["account_phone_ciphertext"] else "",
          "relationship":decrypt(row["account_relationship"]) if row["account_relationship"] else "",
          "active":bool(row["is_active"]),"created_at":row["created_at"],"last_activity":row["last_activity"],
          "profile_count":row["profile_count"],"contributor_status":row["identity_state"],
          "training_complete":bool(row["training_complete"] or 0),"qualification_passed":bool(row["qualification_passed"] or 0),
          "available":bool(row["availability"] or 0)})
    return result


@app.get("/api/payments")
def list_payments(actor=Depends(_actor)):
    with db.transaction() as conn:
        if actor["role"] == "operator":
            _audit(conn, actor["id"], "payment_records_access", "payments", "all")
            return conn.all("SELECT id,booking_id,provider,provider_order_id,provider_payment_id,amount_inr,status,refund_state,created_at,updated_at FROM payments ORDER BY created_at DESC")
        if actor["role"] == "family":
            return conn.all("SELECT p.id,p.booking_id,p.provider,p.provider_order_id,p.provider_payment_id,p.amount_inr,p.status,p.refund_state,p.created_at,p.updated_at FROM payments p JOIN bookings b ON b.id=p.booking_id WHERE b.customer_user_id=? ORDER BY p.created_at DESC", (actor["id"],))
    return []


@app.get("/webhooks/whatsapp")
def whatsapp_verify(request: Request):
    mode = request.query_params.get("hub.mode")
    token = request.query_params.get("hub.verify_token")
    challenge = request.query_params.get("hub.challenge")
    if settings.configured_provider("whatsapp") and mode == "subscribe" and hmac.compare_digest(token or "", settings.WHATSAPP_VERIFY_TOKEN):
        return Response(content=challenge or "", media_type="text/plain")
    raise HTTPException(403, "WhatsApp webhook verification failed or integration credentials are blocked.")


@app.post("/webhooks/whatsapp")
async def whatsapp_webhook(request: Request, x_hub_signature_256: str | None = Header(default=None)):
    raw = await request.body()
    if not settings.configured_provider("whatsapp"):
        raise HTTPException(503, "BLOCKED: Configure WhatsApp Cloud API credentials and webhook before use.")
    if not verify_signature(raw, x_hub_signature_256 or "", settings.WHATSAPP_APP_SECRET):
        raise HTTPException(401, "Invalid WhatsApp webhook signature.")
    payload = await request.json()
    messages = []
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})
            for message in value.get("messages", []):
                messages.append((message, value.get("contacts", [])))
    stored = 0
    with db.transaction() as conn:
        for message, contacts in messages:
            wa_id = message.get("from", "")
            if not wa_id or not message.get("id"):
                continue
            contact_hash = token_hash("".join(c for c in wa_id if c.isdigit()), settings.APP_SECRET)
            profile = conn.one("SELECT id,voice_ai_consent FROM profiles WHERE whatsapp_id_hash=?", (contact_hash,))
            kind = message.get("type", "unknown")
            text = message.get("text", {}).get("body", "") if kind == "text" else ""
            intent = "urgent" if re.search(r"fall|fell|emergency|112|ಬಿದ್ದು|ತುರ್ತು|गिर", text, re.I) else "unclassified"
            status = "human_review"
            media_id = None
            if kind == "audio":
                media_id = message.get("audio", {}).get("id")
                if profile and profile["voice_ai_consent"] and media_id:
                    status = "voice_processing_pending"
                    text = "Audio received; consented transcription is pending."
                else:
                    intent = "voice_needs_human"
                    text = "Audio received; not sent for transcription because voice consent or a valid recording was unavailable."
            message_id = uid()
            inserted = conn.execute("INSERT INTO messages(id,provider,provider_message_id,profile_id,direction,kind,received_at,status,intent,transcript) VALUES(?,'whatsapp',?,?, 'inbound',?,?,?,?,?) ON CONFLICT(provider_message_id) DO NOTHING",
                                    (message_id, message["id"], profile["id"] if profile else None, kind, stamp(), status, intent, text[:4000]))
            if inserted.rowcount != 1:
                continue
            stored += 1
            if kind == "audio" and status == "voice_processing_pending":
                conn.execute("INSERT INTO voice_jobs(id,message_id,media_id,status,attempts,next_attempt_at,created_at,updated_at) VALUES(?,?,?,'queued',0,?,?,?)",
                             (uid(), message_id, media_id, stamp(), stamp(), stamp()))
            if profile and intent == "urgent":
                conn.execute("INSERT INTO alerts(id,profile_id,category,title,source,status,created_at,updated_at) VALUES(?,?,'red','Urgent WhatsApp user report','whatsapp','open',?,?)", (uid(), profile["id"], stamp(), stamp()))
                _queue_alert_notification(conn, profile["id"], "Urgent WhatsApp user report", "red")
    return {"received": stored}


@app.post("/api/voice/transcribe")
async def web_voice_transcribe(profile_id: str = Form(...), audio: UploadFile = File(...), actor=Depends(_write_actor)):
    """Consent-gated browser voice intake. Audio is sent to configured providers, never stored here."""
    _role(actor, "family")
    if not settings.configured_provider("voice_ai"):
        raise HTTPException(503, "BLOCKED: Configure AssemblyAI and OpenAI credentials before submitting voice audio.")
    if audio.content_type not in {"audio/ogg", "audio/opus", "audio/mpeg", "audio/mp4", "audio/wav", "audio/webm", "audio/x-wav"}:
        raise HTTPException(415, "Use a supported audio format: OGG, MP3, MP4, WAV, or WebM.")
    content = await audio.read(25_000_001)
    if len(content) > 25_000_000:
        raise HTTPException(413, "Audio exceeds the 25 MB limit.")
    with db.transaction() as conn:
        profile = _profile(conn, profile_id, actor, allow_operator=False)
        if not profile["voice_ai_consent"]:
            raise HTTPException(403, "The elderly person has not consented to external speech and language processing.")
    from .adapters import extract_intent, transcribe_audio
    try:
        transcript = await transcribe_audio(content)
        intent = await extract_intent(transcript)
    except Exception:
        raise HTTPException(502, "Voice service failed; audio was not retained. Please retry or use a human coordinator.")
    ident = uid()
    english_translation = str(intent.get("translated_english") or "")[:1800]
    review_text = transcript[:2000] + ("\n\nAI-drafted English translation (human confirmation required):\n" + english_translation if english_translation else "")
    with db.transaction() as conn:
        conn.execute("INSERT INTO messages(id,provider,provider_message_id,profile_id,direction,kind,received_at,status,intent,transcript) VALUES(?,'web',?,?,'inbound','audio',?,'human_review',?,?)", (ident, ident, profile_id, stamp(), intent.get("intent", "unclear"), review_text[:4000]))
        _audit(conn, actor["id"], "consented_voice_processed", "message", ident, {"provider":"AssemblyAI+OpenAI", "intent":intent.get("intent"), "action_created":False})
        if intent.get("intent") == "urgent":
            conn.execute("INSERT INTO alerts(id,profile_id,category,title,source,status,created_at,updated_at) VALUES(?,?,'red','Urgent voice request · human review required','consented_web_voice','open',?,?)", (uid(), profile_id, stamp(), stamp()))
            _queue_alert_notification(conn, profile_id, "Urgent voice request · human review required", "red")
    return {"message_id":ident,"transcript_original":transcript,"translation_english":english_translation or None,"intent":intent,"booking_created":False,"needs_confirmation":True}


@app.post("/api/bookings/{booking_id}/payments/order")
async def payment_order(booking_id: str, actor=Depends(_write_actor)):
    _role(actor, "family")
    if not settings.configured_provider("razorpay"):
        raise HTTPException(503, "BLOCKED: Razorpay test credentials and webhook secret are not configured.")
    if not settings.RAZORPAY_KEY_ID.startswith("rzp_test_") and (settings.APP_ENV != "production" or not settings.ALLOW_LIVE_PAYMENTS):
        raise HTTPException(403, "Live payment orders are disabled. Use Razorpay test keys; live processing requires explicit production authorization.")
    import httpx
    with db.transaction() as conn:
        row = _booking(conn, booking_id, actor)
        if row["customer_user_id"] != actor["id"]:
            raise HTTPException(403, "Only the booking customer may pay.")
        if row["payment_state"] not in ("unpaid", "failed"):
            raise HTTPException(409, "Booking payment is already in progress or settled.")
    amount = row["price_inr"] * 100
    async with httpx.AsyncClient(timeout=20) as client:
        result = await client.post("https://api.razorpay.com/v1/orders", auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET), json={"amount": amount, "currency": "INR", "receipt": booking_id, "notes": {"booking_id": booking_id}})
    if result.status_code >= 300:
        raise HTTPException(502, "Payment provider could not create a test order.")
    order = result.json()
    with db.transaction() as conn:
        ident = uid()
        conn.execute("INSERT INTO payments(id,booking_id,provider,provider_order_id,amount_inr,status,created_at,updated_at) VALUES(?,?,'razorpay',?,?,'created',?,?)", (ident, booking_id, order["id"], row["price_inr"], stamp(), stamp()))
        conn.execute("UPDATE bookings SET payment_state='pending' WHERE id=?", (booking_id,))
        _audit(conn, actor["id"], "payment_order_created", "payment", ident, {"provider": "razorpay", "mode": "test" if settings.RAZORPAY_KEY_ID.startswith("rzp_test_") else "production_blocked"})
    return {"payment_id": ident, "order_id": order["id"], "amount": order["amount"], "currency": order["currency"], "key_id": settings.RAZORPAY_KEY_ID}


@app.post("/api/payments/verify")
def payment_verify(body: dict, actor=Depends(_write_actor)):
    _role(actor, "family")
    order_id, payment_id, signature = (str(body.get(x, "")) for x in ("razorpay_order_id", "razorpay_payment_id", "razorpay_signature"))
    expected = hmac.new(settings.RAZORPAY_KEY_SECRET.encode(), f"{order_id}|{payment_id}".encode(), hashlib.sha256).hexdigest() if settings.RAZORPAY_KEY_SECRET else ""
    if not expected or not hmac.compare_digest(expected, signature):
        raise HTTPException(400, "Payment signature verification failed.")
    with db.transaction() as conn:
        row = conn.one("SELECT p.*,b.customer_user_id FROM payments p JOIN bookings b ON b.id=p.booking_id WHERE p.provider_order_id=?", (order_id,))
        if not row or row["customer_user_id"] != actor["id"]:
            raise HTTPException(404, "Payment order not found for this customer.")
        if row["status"] == "captured":
            return {"payment_id": row["id"], "status": "captured"}
        if row["status"] == "authorized":
            if row["provider_payment_id"] != payment_id:
                raise HTTPException(409, "This payment order is already associated with another payment.")
            return {"payment_id": row["id"], "status": "authorized"}
        if row["status"] in ("failed", "refunded"):
            raise HTTPException(409, "This payment order is no longer eligible for authorization.")
        conn.execute("UPDATE payments SET provider_payment_id=?,status='authorized',updated_at=? WHERE id=?", (payment_id, stamp(), row["id"]))
        conn.execute("UPDATE bookings SET payment_state='authorized' WHERE id=?", (row["booking_id"],))
        _audit(conn, actor["id"], "payment_signature_verified", "payment", row["id"])
    return {"payment_id": row["id"], "status": "authorized"}


@app.post("/webhooks/razorpay")
async def razorpay_webhook(request: Request, x_razorpay_signature: str | None = Header(default=None)):
    raw = await request.body()
    if not settings.configured_provider("razorpay"):
        raise HTTPException(503, "BLOCKED: Razorpay webhook secret is not configured.")
    expected = hmac.new(settings.RAZORPAY_WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_razorpay_signature or ""):
        raise HTTPException(401, "Invalid Razorpay webhook signature.")
    payload = await request.json()
    event_id = request.headers.get("x-razorpay-event-id") or payload.get("event_id")
    if not event_id:
        raise HTTPException(400, "Webhook event id is required for idempotent processing.")
    data = payload.get("payload", {})
    entity = data.get("payment", {}).get("entity", {})
    order_id, payment_id, event = entity.get("order_id"), entity.get("id"), payload.get("event", "")
    with db.transaction() as conn:
        payment = conn.one("SELECT * FROM payments WHERE provider_order_id=?", (order_id,)) if order_id else None
        if not payment:
            raise HTTPException(404, "Payment order does not exist.")
        digest = hashlib.sha256(raw).hexdigest()
        inserted = conn.execute("INSERT INTO payment_events(event_id,payment_id,payload_hash,received_at) VALUES(?,?,?,?) ON CONFLICT(event_id) DO NOTHING", (event_id, payment["id"], digest, stamp()))
        if inserted.rowcount != 1:
            prior = conn.one("SELECT payload_hash FROM payment_events WHERE event_id=?", (event_id,))
            if prior and hmac.compare_digest(prior["payload_hash"], digest):
                return {"received": True, "duplicate": True}
            raise HTTPException(409, "Webhook event id was previously used with a different payload.")
        if event in ("payment.captured", "payment.failed"):
            if entity.get("currency") != "INR" or entity.get("amount") != payment["amount_inr"]*100:
                raise HTTPException(409, "Webhook amount or currency does not match the stored order.")
        if payment["status"] == "captured" and event not in ("refund.created", "refund.processed", "refund.failed"):
            status, booking_state = "captured", "paid"
        elif event == "payment.captured":
            status, booking_state = "captured", "paid"
        elif event == "payment.failed":
            status, booking_state = "failed", "failed"
        elif event.startswith("refund."):
            status, booking_state = payment["status"], payment["status"]
            refund = "requested" if event == "refund.created" else "processed" if event == "refund.processed" else "failed"
            conn.execute("UPDATE payments SET refund_state=?,updated_at=? WHERE id=?", (refund, stamp(), payment["id"]))
        else:
            status, booking_state = payment["status"], payment["status"]
        conn.execute("UPDATE payments SET status=?,provider_payment_id=COALESCE(?,provider_payment_id),provider_payload=?,updated_at=? WHERE id=?", (status, payment_id, json_dump(payload), stamp(), payment["id"]))
        if booking_state in ("paid", "failed"):
            if booking_state=="paid": conn.execute("UPDATE bookings SET payment_state='paid',status=CASE WHEN helper_accepted_at IS NOT NULL THEN 'confirmed' ELSE status END,updated_at=? WHERE id=?",(stamp(),payment["booking_id"]))
            else: conn.execute("UPDATE bookings SET payment_state=?,updated_at=? WHERE id=?", (booking_state,stamp(),payment["booking_id"]))
        _audit(conn, None, "razorpay_webhook_processed", "payment", payment["id"], {"event": event, "event_id": event_id})
    return {"received": True, "duplicate": False}


@app.post("/api/payments/{payment_id}/refund")
async def refund_payment(payment_id: str, actor=Depends(_write_actor)):
    _role(actor, "operator")
    if not settings.configured_provider("razorpay"):
        raise HTTPException(503, "BLOCKED: Razorpay test credentials are not configured.")
    import httpx
    with db.transaction() as conn:
        row = conn.one("SELECT * FROM payments WHERE id=?", (payment_id,))
        if not row or row["status"] != "captured" or row["refund_state"] != "none":
            raise HTTPException(409, "Only a captured, not-yet-refunded payment may be refunded.")
    async with httpx.AsyncClient(timeout=20) as client:
        result = await client.post(f"https://api.razorpay.com/v1/payments/{row['provider_payment_id']}/refund", auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET), json={"amount": row["amount_inr"]*100})
    if result.status_code >= 300:
        raise HTTPException(502, "Payment provider rejected the refund request.")
    with db.transaction() as conn:
        conn.execute("UPDATE payments SET refund_state='requested',updated_at=? WHERE id=?", (stamp(), payment_id))
        _audit(conn, actor["id"], "payment_refund_requested", "payment", payment_id)
    return {"payment_id": payment_id, "refund_state": "requested"}


@app.get("/api/integrations/fitbit/connect")
def fitbit_connect(profile_id: str, actor=Depends(_actor)):
    _role(actor, "family")
    if not settings.configured_provider("fitbit"):
        raise HTTPException(503, "BLOCKED: Fitbit developer credentials, approved intraday access, redirect URI, and encryption key are required.")
    with db.transaction() as conn:
        profile = _profile(conn, profile_id, actor, allow_operator=False)
        if not profile["monitoring_consent"]:
            raise HTTPException(403, "Explicit monitoring consent is required before connecting a wearable.")
        state = random_token(24)
        conn.execute("INSERT INTO oauth_states(state_hash,user_id,profile_id,expires_at) VALUES(?,?,?,?)", (token_hash(state, settings.APP_SECRET), actor["id"], profile_id, stamp(now()+timedelta(minutes=10))))
    from urllib.parse import urlencode
    params = urlencode({"response_type":"code","client_id":settings.FITBIT_CLIENT_ID,"redirect_uri":settings.FITBIT_REDIRECT_URI,"scope":"heartrate oxygen_saturation","state":state,"expires_in":"604800"})
    return {"authorization_url": "https://www.fitbit.com/oauth2/authorize?"+params, "provider": "Fitbit", "live_access": True}


@app.get("/api/integrations/fitbit/callback")
async def fitbit_callback(code: str, state: str):
    if not settings.configured_provider("fitbit"):
        raise HTTPException(503, "BLOCKED: Fitbit OAuth configuration is incomplete.")
    with db.transaction() as conn:
        link = conn.one("SELECT * FROM oauth_states WHERE state_hash=? AND expires_at>?", (token_hash(state, settings.APP_SECRET), stamp()))
        if not link:
            raise HTTPException(400, "OAuth state expired or invalid.")
        conn.execute("DELETE FROM oauth_states WHERE state_hash=?", (token_hash(state, settings.APP_SECRET),))
    import httpx, base64
    auth = base64.b64encode(f"{settings.FITBIT_CLIENT_ID}:{settings.FITBIT_CLIENT_SECRET}".encode()).decode()
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post("https://api.fitbit.com/oauth2/token", data={"client_id":settings.FITBIT_CLIENT_ID,"grant_type":"authorization_code","code":code,"redirect_uri":settings.FITBIT_REDIRECT_URI}, headers={"Authorization":"Basic "+auth,"Content-Type":"application/x-www-form-urlencoded"})
    if response.status_code >= 300:
        raise HTTPException(502, "Fitbit token exchange failed.")
    token = response.json()
    with db.transaction() as conn:
        conn.execute("INSERT INTO provider_tokens(profile_id,provider,access_token,refresh_token,expires_at) VALUES(?,'fitbit',?,?,?) ON CONFLICT(profile_id,provider) DO UPDATE SET access_token=excluded.access_token,refresh_token=excluded.refresh_token,expires_at=excluded.expires_at", (link["profile_id"], encrypt_token(token["access_token"]), encrypt_token(token["refresh_token"]), stamp(now()+timedelta(seconds=token.get("expires_in",3600)))))
        _audit(conn, link["user_id"], "fitbit_account_connected", "profile", link["profile_id"])
    return RedirectResponse("/?fitbit=connected", status_code=303)


@app.post("/api/integrations/fitbit/sync")
async def fitbit_sync(body: dict, actor=Depends(_write_actor)):
    _role(actor, "family")
    profile_id = str(body.get("profile_id", ""))
    day = str(body.get("date", date.today().isoformat()))
    date.fromisoformat(day)
    with db.transaction() as conn:
        profile = _profile(conn, profile_id, actor, allow_operator=False)
        if not profile["monitoring_consent"]:
            raise HTTPException(403, "Monitoring consent is not active.")
        token = conn.one("SELECT * FROM provider_tokens WHERE profile_id=? AND provider='fitbit'", (profile_id,))
        if not token:
            raise HTTPException(409, "Connect Fitbit first.")
    import httpx
    async with httpx.AsyncClient(timeout=20) as client:
        result = await client.get(f"https://api.fitbit.com/1/user/-/activities/heart/date/{day}/1d/1min.json", headers={"Authorization":"Bearer "+decrypt_token(token["access_token"]),"Accept":"application/json"})
    if result.status_code >= 300:
        raise HTTPException(502, "Fitbit returned an error. Intraday access may need provider approval.")
    data = result.json().get("activities-heart-intraday", {}).get("dataset", [])
    stored = 0
    with db.transaction() as conn:
        for item in data:
            try:
                observed = datetime.fromisoformat(day+"T"+item["time"]).replace(tzinfo=ZoneInfo("Asia/Kolkata"))
                event_key = "fitbit:"+profile_id+":"+day+":"+item["time"]
                conn.execute("INSERT INTO sensor_readings(id,profile_id,provider,metric,value,unit,observed_at,quality,event_key) VALUES(?,?,'fitbit','heart_rate',?,'bpm',?,'validated',?)", (uid(), profile_id, float(item["value"]), stamp(observed), event_key))
                stored += 1
            except Exception as exc:
                if "unique" not in str(exc).lower() and "duplicate" not in str(exc).lower():
                    raise
        _audit(conn, actor["id"], "fitbit_readings_synced", "profile", profile_id, {"reading_count": stored, "date": day})
    return {"provider":"Fitbit Web API", "date":day, "stored_readings":stored, "clinical_validation":False}


@app.get("/api/admin/overview")
def admin_overview(actor=Depends(_actor)):
    _role(actor, "operator")
    with db.transaction() as conn:
        stats = {
            "bookings": conn.one("SELECT COUNT(*) AS n FROM bookings WHERE status NOT IN ('completed','cancelled')")["n"],
            "contributors_available": conn.one("SELECT COUNT(*) AS n FROM contributors WHERE identity_state='approved' AND training_complete=1 AND qualification_passed=1 AND availability=1")["n"],
            "alerts_open": conn.one("SELECT COUNT(*) AS n FROM alerts WHERE status!='closed'")["n"],
            "incidents_open": conn.one("SELECT COUNT(*) AS n FROM incidents WHERE status='open'")["n"],
            "community_requests_pending":conn.one("SELECT COUNT(*) AS n FROM community_requests WHERE status='pending'")["n"],
            "payments_captured_inr":conn.one("SELECT COALESCE(SUM(amount_inr),0) AS n FROM payments WHERE status='captured'")["n"],
        }
        _audit(conn, actor["id"], "admin_overview_access", "dashboard", "overview")
    return stats


@app.get("/api/admin/queue")
def admin_queue(actor=Depends(_actor)):
    _role(actor, "operator")
    with db.transaction() as conn:
        data = {
            "notifications": conn.all("SELECT status,COUNT(*) AS count FROM notifications GROUP BY status"),
            "retryable_notifications": conn.all("SELECT id,message_type,status,attempts,last_error,updated_at FROM notifications WHERE status IN ('blocked','failed') ORDER BY updated_at DESC LIMIT 50"),
            "reminders": conn.all("SELECT status,COUNT(*) AS count FROM reminders GROUP BY status"),
            "voice_jobs": conn.all("SELECT status,COUNT(*) AS count FROM voice_jobs GROUP BY status"),
            "messages_needing_review": conn.one("SELECT COUNT(*) AS count FROM messages WHERE status='human_review'")["count"],
        }
        _audit(conn, actor["id"], "background_queue_access", "queue", "summary")
    return {**data, "providers": {key:val["status"] for key,val in system_status()["providers"].items()}}


class CommunityRequestInput(BaseModel):
    name: str = Field(min_length=3,max_length=100)
    topic: str = Field(min_length=3,max_length=80)
    area: str = Field(min_length=2,max_length=100)
    reason: str = Field(min_length=30,max_length=1200)


class CommunityPostInput(BaseModel):
    message: str = Field(min_length=1,max_length=1500)


@app.get("/api/communities")
def list_communities(actor=Depends(_actor)):
    with db.transaction() as conn:
        # Language circles are available immediately in a new workspace. They
        # are ordinary moderated communities once created, including their
        # membership and chat history.
        for community_id,name,language,topic in (
            ("language-kannada","Kannada Circle","Kannada","Conversation and local peer support in Kannada."),
            ("language-hindi","Hindi Circle","Hindi","Conversation and local peer support in Hindi."),
            ("language-tulu","Tulu Circle","Tulu","Conversation and local peer support in Tulu."),
        ):
            conn.execute("INSERT INTO communities(id,name,topic,area,description,created_by,status,created_at) VALUES(?,?,?,?,?,?, 'active', ?) ON CONFLICT(id) DO NOTHING",(community_id,name,language+" language", "All areas",topic,actor["id"],stamp()))
        rows=conn.all("SELECT c.*,COUNT(DISTINCT cm.user_id) AS members,MAX(CASE WHEN mine.user_id IS NULL THEN 0 ELSE 1 END) AS joined FROM communities c LEFT JOIN community_members cm ON cm.community_id=c.id LEFT JOIN community_members mine ON mine.community_id=c.id AND mine.user_id=? WHERE c.status='active' GROUP BY c.id ORDER BY c.created_at DESC",(actor["id"],))
        requests=conn.all("SELECT r.id,r.name,r.topic,r.area,r.reason,r.status,r.review_note,r.created_at,u.account_name FROM community_requests r JOIN users u ON u.id=r.requested_by WHERE r.requested_by=? ORDER BY r.created_at DESC",(actor["id"],)) if actor["role"]!="operator" else conn.all("SELECT r.id,r.name,r.topic,r.area,r.reason,r.status,r.review_note,r.created_at,u.account_name FROM community_requests r JOIN users u ON u.id=r.requested_by ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END,r.created_at DESC LIMIT 100")
        if actor["role"]=="operator": _audit(conn,actor["id"],"community_queue_access","communities","all")
    clean_requests=[]
    for item in requests:
        row=dict(item)
        row["requester_name"]=decrypt(row.get("account_name")) if row.get("account_name") else "Family member"
        row.pop("account_name",None)
        clean_requests.append(row)
    return {"communities":rows,"requests":clean_requests}


@app.post("/api/communities/requests",status_code=201)
def create_community_request(data:CommunityRequestInput,actor=Depends(_write_actor)):
    _role(actor,"family","contributor")
    if len(data.reason.strip())<30: raise HTTPException(422,"Explain the purpose, intended members, and how the community will support them (at least 30 characters).")
    ident=uid();created=stamp()
    with db.transaction() as conn:
        conn.execute("INSERT INTO community_requests(id,requested_by,name,topic,area,reason,status,created_at,updated_at) VALUES(?,?,?,?,?,?,'pending',?,?)",(ident,actor["id"],data.name.strip(),data.topic.strip(),data.area.strip(),data.reason.strip(),created,created))
        _audit(conn,actor["id"],"community_requested","community_request",ident)
    return {"id":ident,"status":"pending"}


@app.post("/api/communities/requests/{request_id}/review")
def review_community_request(request_id:str,body:dict,actor=Depends(_write_actor)):
    _role(actor,"operator")
    decision=body.get("decision");note=str(body.get("note","")).strip()
    if decision not in ("approve","reject") or (decision=="reject" and len(note)<5): raise HTTPException(422,"Choose approve or reject. A rejection needs a short reason.")
    with db.transaction() as conn:
        req=conn.one("SELECT * FROM community_requests WHERE id=?",(request_id,))
        if not req: raise HTTPException(404,"Community request not found.")
        if req["status"]!="pending": raise HTTPException(409,"This request has already been reviewed.")
        state="approved" if decision=="approve" else "rejected"
        conn.execute("UPDATE community_requests SET status=?,reviewed_by=?,review_note=?,updated_at=? WHERE id=?",(state,actor["id"],note,stamp(),request_id))
        community_id=None
        if decision=="approve":
            community_id=uid()
            conn.execute("INSERT INTO communities(id,name,topic,area,description,created_by,status,created_at) VALUES(?,?,?,?,?,?,'active',?)",(community_id,req["name"],req["topic"],req["area"],req["reason"],req["requested_by"],stamp()))
            conn.execute("INSERT INTO community_members(community_id,user_id,joined_at) VALUES(?,?,?)",(community_id,req["requested_by"],stamp()))
        _audit(conn,actor["id"],"community_request_reviewed","community_request",request_id,{"decision":decision})
    return {"id":request_id,"status":state,"community_id":community_id}


@app.post("/api/communities/{community_id}/join")
def join_community(community_id:str,actor=Depends(_write_actor)):
    _role(actor,"family","contributor")
    with db.transaction() as conn:
        row=conn.one("SELECT id FROM communities WHERE id=? AND status='active'",(community_id,))
        if not row: raise HTTPException(404,"Community is not available.")
        conn.execute("INSERT INTO community_members(community_id,user_id,joined_at) VALUES(?,?,?) ON CONFLICT(community_id,user_id) DO NOTHING",(community_id,actor["id"],stamp()))
        _audit(conn,actor["id"],"community_joined","community",community_id)
    return {"community_id":community_id,"joined":True}


@app.get("/api/communities/{community_id}/posts")
def community_posts(community_id:str,actor=Depends(_actor)):
    with db.transaction() as conn:
        member=conn.one("SELECT 1 AS yes FROM community_members WHERE community_id=? AND user_id=?",(community_id,actor["id"]))
        if not member: raise HTTPException(403,"Join this community before viewing its chat.")
        rows=conn.all("SELECT p.id,p.message,p.created_at,u.account_name,c.display_name AS helper_name,u.email FROM community_posts p JOIN users u ON u.id=p.user_id LEFT JOIN contributors c ON c.user_id=u.id WHERE p.community_id=? ORDER BY p.created_at DESC LIMIT 100",(community_id,))
    return [{"id":r["id"],"message":r["message"],"created_at":r["created_at"],"author":decrypt(r["account_name"]) if r["account_name"] else decrypt(r["helper_name"]) if r["helper_name"] else r["email"]} for r in rows]


@app.post("/api/communities/{community_id}/posts",status_code=201)
def create_community_post(community_id:str,data:CommunityPostInput,actor=Depends(_write_actor)):
    _role(actor,"family","contributor")
    if not data.message.strip(): raise HTTPException(422,"Write a message first.")
    ident=uid()
    with db.transaction() as conn:
        member=conn.one("SELECT 1 AS yes FROM community_members WHERE community_id=? AND user_id=?",(community_id,actor["id"]))
        if not member: raise HTTPException(403,"Join this community before sending a message.")
        conn.execute("INSERT INTO community_posts(id,community_id,user_id,message,created_at) VALUES(?,?,?,?,?)",(ident,community_id,actor["id"],data.message.strip(),stamp()))
        _audit(conn,actor["id"],"community_message_sent","community_post",ident)
    return {"id":ident,"status":"sent"}


@app.post("/api/admin/notifications/{notification_id}/retry")
def retry_notification(notification_id: str, actor=Depends(_write_actor)):
    _role(actor, "operator")
    with db.transaction() as conn:
        row = conn.one("SELECT * FROM notifications WHERE id=?", (notification_id,))
        if not row or row["status"] not in ("blocked", "failed"):
            raise HTTPException(409, "Only blocked or failed notifications can be manually retried.")
        conn.execute("UPDATE notifications SET status='queued',next_attempt_at=?,last_error='',updated_at=? WHERE id=?", (stamp(),stamp(),notification_id))
        try:
            reminder_id = json.loads(row["payload"]).get("reminder_id")
        except (TypeError, ValueError):
            reminder_id = None
        if reminder_id:
            conn.execute("UPDATE reminders SET status='queued' WHERE id=? AND status IN ('blocked','failed')", (reminder_id,))
        _audit(conn, actor["id"], "notification_retried", "notification", notification_id)
    return {"id":notification_id,"status":"queued"}


from fastapi.staticfiles import StaticFiles
app.mount("/", StaticFiles(directory=str(__import__('pathlib').Path(__file__).resolve().parents[1] / "frontend"), html=True), name="frontend")
