"""Environment-backed settings; credentials are never committed to source."""
import os

APP_ENV = os.getenv("APP_ENV", "development").lower()
DATABASE_URL = os.getenv("DATABASE_URL", "")
APP_SECRET = os.getenv("APP_SECRET", "")
SESSION_HOURS = int(os.getenv("SESSION_HOURS", "12"))
COOKIE_SECURE = APP_ENV == "production"
DEFAULT_HOURLY_PRICE = int(os.getenv("DEFAULT_HOURLY_PRICE_INR", "300"))
DEFAULT_CONTRIBUTOR_PAYOUT = int(os.getenv("DEFAULT_CONTRIBUTOR_PAYOUT_INR", "240"))
MAX_MONTHLY_CLIENT_SPEND = int(os.getenv("MAX_MONTHLY_CLIENT_SPEND_INR", "100000"))
OPERATOR_COST_PER_HOUR = int(os.getenv("OPERATOR_COST_PER_HOUR_INR", "240"))
MESSAGE_COST = int(os.getenv("MESSAGE_COST_INR", "2"))
ALERT_HR_LOW = float(os.getenv("ALERT_HR_LOW_BPM", "40"))
ALERT_HR_HIGH = float(os.getenv("ALERT_HR_HIGH_BPM", "140"))
ALERT_SPO2_LOW = float(os.getenv("ALERT_SPO2_LOW_PERCENT", "90"))
INTEGRATION_KEY = os.getenv("INTEGRATION_INGEST_KEY", "")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
WHATSAPP_APP_SECRET = os.getenv("WHATSAPP_APP_SECRET", "")
WHATSAPP_API_VERSION = os.getenv("WHATSAPP_API_VERSION", "v23.0")
WHATSAPP_TEMPLATE_BOOKING = os.getenv("WHATSAPP_TEMPLATE_BOOKING", "")
WHATSAPP_TEMPLATE_REMINDER = os.getenv("WHATSAPP_TEMPLATE_REMINDER", "")
WHATSAPP_TEMPLATE_ALERT = os.getenv("WHATSAPP_TEMPLATE_ALERT", "")
ASSEMBLYAI_API_KEY = os.getenv("ASSEMBLYAI_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_INTENT_MODEL = os.getenv("OPENAI_INTENT_MODEL", "gpt-4.1-mini")
FITBIT_CLIENT_ID = os.getenv("FITBIT_CLIENT_ID", "")
FITBIT_CLIENT_SECRET = os.getenv("FITBIT_CLIENT_SECRET", "")
FITBIT_REDIRECT_URI = os.getenv("FITBIT_REDIRECT_URI", "")
TOKEN_ENCRYPTION_KEY = os.getenv("TOKEN_ENCRYPTION_KEY", "")
DATA_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY", "")
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")
RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "")
ALLOW_LIVE_PAYMENTS = os.getenv("ALLOW_LIVE_PAYMENTS", "false").lower() == "true"
PARTNER_ADAPTER_URL = os.getenv("PARTNER_ADAPTER_URL", "")
HELPDESK_NAME = os.getenv("HELPDESK_NAME", "CareCircle helpdesk")
HELPDESK_PHONE = os.getenv("HELPDESK_PHONE", "")
HELPDESK_EMAIL = os.getenv("HELPDESK_EMAIL", "")
HELPDESK_HOURS = os.getenv("HELPDESK_HOURS", "Set service hours in deployment settings")
ADMIN_INVITE_CODE = os.getenv("ADMIN_INVITE_CODE", "")


def configured_provider(name: str) -> bool:
    if name == "whatsapp":
        return all((WHATSAPP_TOKEN, WHATSAPP_PHONE_NUMBER_ID, WHATSAPP_VERIFY_TOKEN, WHATSAPP_APP_SECRET,
                    WHATSAPP_TEMPLATE_BOOKING, WHATSAPP_TEMPLATE_REMINDER, WHATSAPP_TEMPLATE_ALERT))
    if name == "voice_ai":
        return bool(ASSEMBLYAI_API_KEY and OPENAI_API_KEY)
    if name == "fitbit":
        return all((FITBIT_CLIENT_ID, FITBIT_CLIENT_SECRET, FITBIT_REDIRECT_URI, TOKEN_ENCRYPTION_KEY))
    if name == "razorpay":
        return all((RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET))
    if name == "partner":
        return False  # No contractually approved partner adapter is implemented in this release.
    return False
