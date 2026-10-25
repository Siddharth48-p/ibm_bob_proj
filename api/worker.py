"""Independent process for due reminders, outbound notifications, and voice jobs."""
import asyncio
import json
from datetime import timedelta

from . import db, settings
from .adapters import IntegrationBlocked, extract_intent, send_whatsapp_template, transcribe_audio, whatsapp_download_audio
from .crypto import decrypt
from .main import _audit, _new_notification, _queue_alert_notification, now, stamp, uid


def _sync_reminder_status(conn, notification, status):
    """Keep the reminder record aligned with its delivery notification."""
    try:
        reminder_id = json.loads(notification["payload"]).get("reminder_id")
    except (TypeError, ValueError):
        reminder_id = None
    if not reminder_id:
        return
    mapped = {"sent": "sent", "blocked": "blocked", "failed": "failed", "retry": "queued"}.get(status)
    if mapped:
        conn.execute("UPDATE reminders SET status=? WHERE id=?", (mapped, reminder_id))


async def deliver_notifications():
    with db.transaction() as conn:
        due = conn.all("SELECT * FROM notifications WHERE status IN ('queued','retry') AND next_attempt_at<=? ORDER BY created_at LIMIT 30", (stamp(),))
    for item in due:
        with db.transaction() as conn:
            claim = conn.execute("UPDATE notifications SET status='sending',updated_at=? WHERE id=? AND status IN ('queued','retry')", (stamp(), item["id"]))
            if claim.rowcount != 1:
                continue
        try:
            if item["channel"] != "whatsapp" or not settings.configured_provider("whatsapp"):
                raise IntegrationBlocked("WhatsApp is blocked until credentials and approved templates are configured.")
            with db.transaction() as conn:
                profile = conn.one("SELECT whatsapp_ciphertext,notification_phone_ciphertext,notification_contact_consent FROM profiles WHERE id=?", (item["profile_id"],))
            if profile and profile["notification_contact_consent"] and profile["notification_phone_ciphertext"]:
                destination = decrypt(profile["notification_phone_ciphertext"])
            else:
                destination = decrypt(profile["whatsapp_ciphertext"]) if profile and profile["whatsapp_ciphertext"] else None
            if destination:
                destination = "".join(c for c in destination if c.isdigit())
            if not destination:
                raise IntegrationBlocked("No consented WhatsApp destination is registered for this profile.")
            template = settings.WHATSAPP_TEMPLATE_BOOKING if item["message_type"] == "booking_update" else settings.WHATSAPP_TEMPLATE_ALERT if item["message_type"] == "alert" else settings.WHATSAPP_TEMPLATE_REMINDER
            data = json.loads(item["payload"])
            parameters = data.get("parameters") or [str(data.get("title") or data.get("status") or "CareCircle update")]
            message_id = await send_whatsapp_template(destination, template, "en", parameters)
            with db.transaction() as conn:
                conn.execute("UPDATE notifications SET status='sent',provider_message_id=?,last_error='',attempts=attempts+1,updated_at=? WHERE id=?", (message_id, stamp(), item["id"]))
                _sync_reminder_status(conn, item, "sent")
        except IntegrationBlocked as exc:
            with db.transaction() as conn:
                conn.execute("UPDATE notifications SET status='blocked',last_error=?,attempts=attempts+1,updated_at=? WHERE id=?", (str(exc)[:400], stamp(), item["id"]))
                _sync_reminder_status(conn, item, "blocked")
        except Exception as exc:
            attempts = item["attempts"]+1
            status = "failed" if attempts >= 8 else "retry"
            retry = stamp(now()+timedelta(seconds=min(3600, 5*2**min(attempts,9))))
            with db.transaction() as conn:
                conn.execute("UPDATE notifications SET status=?,attempts=?,next_attempt_at=?,last_error=?,updated_at=? WHERE id=?", (status, attempts, retry, str(exc)[:400], stamp(), item["id"]))
                _sync_reminder_status(conn, item, status)


async def schedule_due_reminders():
    with db.transaction() as conn:
        reminders = conn.all("SELECT * FROM reminders WHERE status='scheduled' AND due_at<=? ORDER BY due_at LIMIT 30", (stamp(),))
        for reminder in reminders:
            claim = conn.execute("UPDATE reminders SET status='processing' WHERE id=? AND status='scheduled'", (reminder["id"],))
            if claim.rowcount != 1:
                continue
            _new_notification(conn, reminder["profile_id"], "reminder", {"reminder_id":reminder["id"],"title":reminder["title"]})
            conn.execute("UPDATE reminders SET status='queued' WHERE id=? AND status='processing'", (reminder["id"],))


async def process_voice_jobs():
    with db.transaction() as conn:
        jobs = conn.all("SELECT v.*,m.profile_id,m.provider_message_id FROM voice_jobs v JOIN messages m ON m.id=v.message_id WHERE v.status IN ('queued','retry') AND v.next_attempt_at<=? ORDER BY v.created_at LIMIT 5", (stamp(),))
    for job in jobs:
        with db.transaction() as conn:
            claim = conn.execute("UPDATE voice_jobs SET status='processing',updated_at=? WHERE id=? AND status IN ('queued','retry')", (stamp(), job["id"]))
            if claim.rowcount != 1:
                continue
        try:
            with db.transaction() as conn:
                consent = conn.one("SELECT voice_ai_consent FROM profiles WHERE id=?", (job["profile_id"],)) if job["profile_id"] else None
            if not consent or not consent["voice_ai_consent"]:
                raise IntegrationBlocked("Voice AI consent is absent; processing stopped before external transmission.")
            if not settings.configured_provider("voice_ai"):
                raise IntegrationBlocked("Consented voice processing remains blocked until AssemblyAI and OpenAI credentials are configured.")
            audio = await whatsapp_download_audio(job["media_id"])
            transcript = await transcribe_audio(audio)
            intent = await extract_intent(transcript)
            english_translation = str(intent.get("translated_english") or "")[:1800]
            review_text = transcript[:2000] + ("\n\nAI-drafted English translation (human confirmation required):\n" + english_translation if english_translation else "")
            with db.transaction() as conn:
                profile = conn.one("SELECT voice_ai_consent FROM profiles WHERE id=?", (job["profile_id"],)) if job["profile_id"] else None
                if not profile or not profile["voice_ai_consent"]:
                    raise IntegrationBlocked("Voice AI consent is absent; processing stopped.")
                conn.execute("UPDATE messages SET status='human_review',intent=?,transcript=? WHERE id=?", (intent.get("intent","unclear"), review_text[:4000], job["message_id"]))
                conn.execute("UPDATE voice_jobs SET status='completed',attempts=attempts+1,updated_at=? WHERE id=?", (stamp(), job["id"]))
                if intent.get("intent") == "urgent" or intent.get("needs_human"):
                    title = "Voice request needs human review"
                    conn.execute("INSERT INTO alerts(id,profile_id,category,title,source,status,created_at,updated_at) VALUES(?,?,'red',?,'whatsapp_voice_ai','open',?,?)", (uid(), job["profile_id"], title, stamp(), stamp()))
                    _queue_alert_notification(conn, job["profile_id"], title, "red")
                _audit(conn, None, "consented_voice_intent_extracted", "message", job["message_id"], {"intent":intent.get("intent"),"provider":"AssemblyAI+OpenAI","booking_created":False})
        except IntegrationBlocked as exc:
            with db.transaction() as conn:
                conn.execute("UPDATE voice_jobs SET status='blocked',last_error=?,attempts=attempts+1,updated_at=? WHERE id=?", (str(exc)[:300], stamp(), job["id"]))
                conn.execute("UPDATE messages SET status='human_review' WHERE id=?", (job["message_id"],))
        except Exception as exc:
            attempts = job["attempts"]+1
            with db.transaction() as conn:
                conn.execute("UPDATE voice_jobs SET status=?,attempts=?,next_attempt_at=?,last_error=?,updated_at=? WHERE id=?", ("failed" if attempts>=5 else "retry",attempts,stamp(now()+timedelta(seconds=min(1800,10*2**attempts))),str(exc)[:300],stamp(),job["id"]))


async def recover_stale_jobs():
    cutoff = stamp(now()-timedelta(minutes=15))
    with db.transaction() as conn:
        conn.execute("UPDATE notifications SET status='retry',next_attempt_at=?,updated_at=?,last_error='Recovered after worker interruption' WHERE status='sending' AND updated_at<?", (stamp(),stamp(),cutoff))
        conn.execute("UPDATE voice_jobs SET status='retry',next_attempt_at=?,updated_at=?,last_error='Recovered after worker interruption' WHERE status='processing' AND updated_at<?", (stamp(),stamp(),cutoff))


async def purge_expired_health_data():
    with db.transaction() as conn:
        profiles = conn.all("SELECT id,retention_days FROM profiles")
        for profile in profiles:
            cutoff = stamp(now()-timedelta(days=profile["retention_days"]))
            conn.execute("DELETE FROM voice_jobs WHERE message_id IN (SELECT id FROM messages WHERE profile_id=? AND received_at<?)", (profile["id"],cutoff))
            conn.execute("DELETE FROM messages WHERE profile_id=? AND received_at<?", (profile["id"],cutoff))
            conn.execute("DELETE FROM sensor_readings WHERE profile_id=? AND observed_at<?", (profile["id"],cutoff))


async def run_worker(poll_seconds=5):
    db.migrate()
    last_purge = now()-timedelta(days=1)
    while True:
        with db.transaction() as conn:
            conn.execute("INSERT INTO worker_heartbeat(name,last_seen_at) VALUES('carecircle-worker',?) ON CONFLICT(name) DO UPDATE SET last_seen_at=excluded.last_seen_at", (stamp(),))
        await recover_stale_jobs()
        await schedule_due_reminders()
        await deliver_notifications()
        await process_voice_jobs()
        if now()-last_purge >= timedelta(hours=24):
            await purge_expired_health_data()
            last_purge = now()
        await asyncio.sleep(poll_seconds)


def worker_is_healthy():
    db.migrate()
    with db.transaction() as conn:
        row = conn.one("SELECT last_seen_at FROM worker_heartbeat WHERE name='carecircle-worker'")
    return bool(row and now()-__import__('datetime').datetime.fromisoformat(row["last_seen_at"]) < timedelta(seconds=60))


if __name__ == "__main__":
    asyncio.run(run_worker())
