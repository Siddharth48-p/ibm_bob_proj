"""External service adapters. Calls only occur from configured, consented workflows."""
import asyncio
import json

import httpx

from . import settings


class IntegrationBlocked(RuntimeError):
    pass


async def send_whatsapp_template(destination: str, template_name: str, language: str, parameters: list[str]):
    if not settings.configured_provider("whatsapp") or not template_name:
        raise IntegrationBlocked("WhatsApp credentials or an approved template are missing.")
    components = []
    if parameters:
        components = [{"type": "body", "parameters": [{"type": "text", "text": str(p)[:250]} for p in parameters]}]
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(
            f"https://graph.facebook.com/{settings.WHATSAPP_API_VERSION}/{settings.WHATSAPP_PHONE_NUMBER_ID}/messages",
            headers={"Authorization": "Bearer " + settings.WHATSAPP_TOKEN},
            json={"messaging_product": "whatsapp", "to": destination, "type": "template",
                  "template": {"name": template_name, "language": {"code": language}, "components": components}})
    response.raise_for_status()
    data = response.json()
    return data.get("messages", [{}])[0].get("id")


async def whatsapp_download_audio(media_id: str) -> bytes:
    if not settings.configured_provider("whatsapp"):
        raise IntegrationBlocked("WhatsApp media credentials are missing.")
    headers = {"Authorization": "Bearer " + settings.WHATSAPP_TOKEN}
    async with httpx.AsyncClient(timeout=30) as client:
        metadata = await client.get(f"https://graph.facebook.com/{settings.WHATSAPP_API_VERSION}/{media_id}", headers=headers)
        metadata.raise_for_status()
        media_url = metadata.json().get("url")
        if not media_url:
            raise RuntimeError("WhatsApp returned no media URL.")
        audio = await client.get(media_url, headers=headers)
        audio.raise_for_status()
        if len(audio.content) > 25_000_000:
            raise RuntimeError("Audio exceeds the 25 MB processing limit.")
        return audio.content


async def transcribe_audio(audio: bytes) -> str:
    if not settings.ASSEMBLYAI_API_KEY:
        raise IntegrationBlocked("ASSEMBLYAI_API_KEY is not configured.")
    headers = {"authorization": settings.ASSEMBLYAI_API_KEY}
    async with httpx.AsyncClient(timeout=60) as client:
        upload = await client.post("https://api.assemblyai.com/v2/upload", headers=headers, content=audio)
        upload.raise_for_status()
        response = await client.post("https://api.assemblyai.com/v2/transcript", headers={**headers, "content-type": "application/json"}, json={"audio_url": upload.json()["upload_url"], "language_detection": True})
        response.raise_for_status()
        transcript_id = response.json()["id"]
        for _ in range(30):
            await asyncio.sleep(2)
            status = await client.get(f"https://api.assemblyai.com/v2/transcript/{transcript_id}", headers=headers)
            status.raise_for_status()
            result = status.json()
            if result["status"] == "completed":
                return result.get("text", "")
            if result["status"] == "error":
                raise RuntimeError(result.get("error", "Transcription failed."))
    raise TimeoutError("Speech-to-text timed out.")


async def extract_intent(transcript: str) -> dict:
    """Existing model integration. Deterministic red-flag routing runs first."""
    import re
    if re.search(r"\b(fall|fell|emergency|112|chest pain|hurt)\b|ಬಿದ್ದು|ತುರ್ತು|गिर|सीने में दर्द", transcript, re.I):
        return {"intent": "urgent", "needs_human": True, "create_booking": False}
    if not settings.OPENAI_API_KEY:
        raise IntegrationBlocked("OPENAI_API_KEY is required for structured multilingual intent extraction.")
    system = ("Extract a support-intent JSON object from the user's original-language transcript. "
              "Return only JSON with keys intent (booking, reminder, routine_question, scam_report, human, unclear), "
              "language, translated_english, category, date, time, duration_hours, needs_confirmation (boolean), "
              "needs_human (boolean). Never diagnose, change medicine, create a booking, or treat an uncertain emergency as routine.")
    async with httpx.AsyncClient(timeout=25) as client:
        schema = {"type":"object","properties":{
            "intent":{"type":"string","enum":["booking","reminder","routine_question","scam_report","human","unclear","urgent"]},
            "language":{"type":"string"},"translated_english":{"type":"string"},"category":{"type":"string"},
            "date":{"type":"string"},"time":{"type":"string"},"duration_hours":{"type":["integer","null"]},
            "needs_confirmation":{"type":"boolean"},"needs_human":{"type":"boolean"}},
            "required":["intent","language","translated_english","category","date","time","duration_hours","needs_confirmation","needs_human"],"additionalProperties":False}
        response = await client.post("https://api.openai.com/v1/chat/completions",
            headers={"Authorization": "Bearer " + settings.OPENAI_API_KEY},
            json={"model": settings.OPENAI_INTENT_MODEL, "temperature": 0,
                  "response_format":{"type":"json_schema","json_schema":{"name":"support_intent","strict":True,"schema":schema}},
                  "messages": [{"role":"system","content":system},{"role":"user","content":transcript[:4000]}]})
        response.raise_for_status()
        result = response.json()["choices"][0]["message"]["content"]
    value = json.loads(result)
    allowed = {"booking", "reminder", "routine_question", "scam_report", "human", "unclear", "urgent"}
    if value.get("intent") not in allowed:
        return {"intent":"unclear", "needs_human":True, "create_booking":False}
    # The AI output can only prepare a confirmation prompt; never execute actions.
    value["needs_confirmation"] = True
    value["create_booking"] = False
    return value
