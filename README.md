# CareCircle — production-oriented MVP

CareCircle is a modular-monolith elderly support service for controlled pilot preparation. The interface uses the requested colors: `#4CAF50`, `#FFC107`, `#FFFFFF`, `#607D8B`, and `#212121`. Unlike the earlier local demo, the current frontend reads and writes business records through FastAPI; the deployed source of truth is PostgreSQL.

## Run a local preview

For a quick Windows preview without Docker, run:

```powershell
.\scripts\run-local.ps1
```

Open `http://127.0.0.1:8765`. This starts the API, an independent local worker, and a development SQLite database in `data/local-preview.db`. On Windows, private profile fields use the signed-in Windows account's DPAPI protection when the optional `cryptography` package is unavailable. This fallback is only for local development. Use test accounts and non-sensitive demo data. Stopping the server with Ctrl+C also stops the worker.

The public site supports helper sign-in and self-registration. The main admin signs in with the single operator account provisioned directly in the database; public admin and client account creation are disabled. The admin interface contains a helper operations dashboard and helper management. Reminder delivery and provider connections remain blocked until their services are configured.

## Deploy with PostgreSQL

Docker Compose runs PostgreSQL, the API, and worker as separate services. Docker is required for this supported PostgreSQL deployment path. Local deployment verification is still required before use.

1. Copy `.env.example` to `.env`. Set `APP_ENV=production` for a deployed service and replace the database password, application secret, and Fernet data/token encryption keys with unique random values. Generate secrets after installing the requirements:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
   ```

   Use one random value for `APP_SECRET`; generate a different Fernet key for each of `DATA_ENCRYPTION_KEY` and `TOKEN_ENCRYPTION_KEY`. Use a separate strong `POSTGRES_PASSWORD`. Do not commit `.env`.

2. Start PostgreSQL, the API, and the independent worker:

   ```powershell
   docker compose up --build
   ```

   Open `http://localhost:8000`. Health is at `/api/health`; interactive API docs are available at `/docs` in development and disabled in production.

3. Create the first operator account using the one-time email/password in `.env`:

   ```powershell
   docker compose run --rm api python -m api.bootstrap_operator
   ```

   Remove `BOOTSTRAP_OPERATOR_PASSWORD` from `.env` immediately afterwards and restart the stack. Bootstrap refuses to create a second operator or reset the existing one.

4. Register client and helper accounts. Helpers submit onboarding, complete the knowledge check, and remain unavailable until an operator completes identity review and approves the account.

5. Run the API workflow and security checks:

   ```powershell
   python -m unittest discover -s tests -v
   ```

SQLite is allowed only for local development and tests; it is refused when `APP_ENV=production`. Docker and PostgreSQL were unavailable in this build environment, so PostgreSQL migrations and the Compose deployment have not been verified here.

## Implemented application workflows

- **Authentication and access:** helper-only public self-registration, one database-provisioned main admin, PBKDF2 password hashing, expiring opaque server-side sessions, HttpOnly/SameSite cookies, CSRF validation for mutations, database-backed login/register rate limits, and role checks at protected endpoints.
- **Consent and privacy:** account creation captures the elder's name, phone, language and service area, plus a named notification contact, relationship, phone and explicit contact-notification permission. Contact, name, approximate location, and provider-token fields are encrypted at rest. WhatsApp booking, reminder and alert notifications use that consented contact; WhatsApp sender lookup uses the elder's number. Health-data retention is configurable.
- **Client portal:** client care profile, explicit controls for booking, health-data, and AI voice consent; support visit requests; monthly booked-spend total with a configurable ₹1,00,000 cap; text and consented audio reports for human review; manual HR, SpO₂, blood pressure, temperature, movement, and fall records; reminders; cancellation; feedback; and Fitbit connection when configured.
- **Contributor portal:** onboarding, basic-task selection, training quiz, operator-controlled identity review, availability, eligible booking acceptance, separate expiring one-time OTPs, completion, payout record, and incident reporting.
- **Organization portal:** database-backed schedules, contributors, booking queues, alerts, incidents, provider status, worker status, analytics, audit records, acknowledgement, assignment, and closure.
- **Booking rules:** matching checks approved identity, training, qualification, availability, service area, language, and task eligibility before offering a booking. Contributors cannot accept another contributor’s offer. High-risk personal care and medical procedures are rejected.
- **Alerts:** authenticated normalized wearable ingestion with deduplication, consent checks, range/unit/time validation, configurable heart-rate/SpO₂ review thresholds, and a 30-day descriptive summary when enough readings exist. Device-native and client-reported fall events create red alerts. Client-entered blood pressure is recorded for human review; no BP clinical threshold or trained personalized ML model is claimed. These rules are not diagnoses or guaranteed emergency detection.
- **Background processing:** a separate worker schedules due reminders, sends approved WhatsApp templates when configured, retries provider errors, records blocked deliveries, recovers stale claims, processes consented voice jobs, and purges expired readings/transcripts.
- **Analytics:** completed service value, expected helper payout, indicative contribution before operating costs and payment settlement, fulfilment, unfilled work, alert closure, contributor cancellation recovery, and matching time are computed from records. These values do not claim cash collected or payouts settled. No savings, false-alert rate, or clinical accuracy is claimed without measurements.
- **Operations:** Docker Compose, PostgreSQL schema migration, health checks, database-backed audit log, request IDs, access logs without request bodies, security headers, a frontend-only static file root, and a checklist of tested and blocked scope.

## Integration setup and current blockers

Provider integrations are intentionally disabled unless required server-side credentials are present. `/api/system/status` reports each provider and the independent worker state.

### WhatsApp Business Platform — **BLOCKED pending account credentials and template approval**

1. Create/configure a Meta app and WhatsApp Business account, add the Cloud API product, and obtain a permanent/system-user access token and phone-number ID.
2. Configure the public HTTPS callback as `https://<your-host>/webhooks/whatsapp`, the `WHATSAPP_VERIFY_TOKEN`, and Meta App Secret. Subscribe to the WhatsApp message webhook field. Meta's GET verification challenge and POST `X-Hub-Signature-256` validation are implemented.
3. Create and get approval for localized booking, reminder, and alert templates. Set their exact names in `WHATSAPP_TEMPLATE_BOOKING`, `WHATSAPP_TEMPLATE_REMINDER`, and `WHATSAPP_TEMPLATE_ALERT`, with matching `WHATSAPP_API_VERSION`.
4. Collect the user's WhatsApp ID in a consented profile. Outgoing notices are queued and become `blocked` if credentials, recipient, or templates are missing. Operators can manually retry once the blocker is fixed.
5. Incoming messages are deduplicated and stored for follow-up. Voice messages are queued only for profiles with `voice_ai_consent`; the worker checks consent again before contacting providers.

No live WhatsApp webhook or message has been tested. Meta account review, public HTTPS hosting, permanent credentials, phone-number onboarding, and template approval are unavailable here.

### Speech-to-text and intent extraction — **BLOCKED until both providers are configured**

Set `ASSEMBLYAI_API_KEY` and `OPENAI_API_KEY`. The voice endpoint accepts audio only for a profile with explicit voice-processing consent, sends it to AssemblyAI for multilingual transcription and then OpenAI for structured intent extraction and an English translation draft. The original transcript and translation draft are shown to the client and operator for human confirmation. Deterministic urgent-language routing runs before the language model. The application does not create a booking from model output. Audio is not persisted by this service. A provider test and privacy review are still required before sending real audio.

### Fitbit Web API — **BLOCKED pending developer app approval and OAuth credentials**

Set `FITBIT_CLIENT_ID`, `FITBIT_CLIENT_SECRET`, `FITBIT_REDIRECT_URI`, and `TOKEN_ENCRYPTION_KEY`; register the exact callback URL with the Fitbit app. The OAuth flow is consent-gated and the sync endpoint stores heart-rate intraday readings. Fitbit requires an authorized user token; access to other users' intraday readings may require a Fitbit access request. Only heart rate is ingested by this adapter; no SpO₂, blood pressure, fall-detection, or clinical support is claimed. Fitbit's docs specify the `heartrate` scope and intraday endpoint; account/app approval remains outstanding: [Fitbit heart-rate intraday API](https://dev.fitbit.com/build/reference/web-api/intraday/get-heartrate-intraday-by-date-range/).

### Razorpay — **BLOCKED pending test keys and webhook configuration**

Set `RAZORPAY_KEY_ID` to a test key, `RAZORPAY_KEY_SECRET`, and `RAZORPAY_WEBHOOK_SECRET`; configure the webhook URL as `https://<your-host>/webhooks/razorpay` and subscribe to payment captured/failed and refund events. The API creates provider orders server-side, verifies the checkout signature, verifies webhook HMAC, stores event IDs idempotently, and tracks refund state. Test checkout could not be run because credentials and Docker are unavailable. Non-test keys are refused unless both production mode and `ALLOW_LIVE_PAYMENTS=true` are explicitly set after separate authorization/compliance review. See [Razorpay server integration](https://razorpay.com/docs/server-integration/python/test-app/) and [Razorpay security checklist](https://razorpay.com/security/checklist).

### Partner network — **BLOCKED**

No partner is represented as active. The platform runs an internal verified-network replacement search and records `unfilled` when no eligible replacement exists. A contract, partner API specification, participant verification evidence, and authorization are required before adding an external partner adapter.

## Data protection, safety, and deployment review

This code is a pilot-preparation baseline, not a declaration of legal or security compliance. Obtain qualified Indian legal, clinical, security, employment, insurance, and operations review before real user data or care is handled. Review applicability and commencement of the [Digital Personal Data Protection Act, 2023](https://www.meity.gov.in/static/uploads/2024/02/Digital-Personal-Data-Protection-Act-2023.pdf) and the [Digital Personal Data Protection Rules, 2025](https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf), as well as any applicable health-record, consumer, worker, emergency-response, and device/provider requirements. The Act and Rules have phased commencement dates; counsel should assess the current obligations for the intended launch date and service model.

Before a controlled pilot: terminate TLS at a trusted reverse proxy; set `APP_ENV=production`; use a secret manager rather than `.env`; restrict database/network access; rotate credentials; configure encrypted backups and restore drills; add central logs/alerts and a shared rate limiter if API replicas are added; run security and accessibility reviews; test backup/retention and consent withdrawal; complete a data-protection impact assessment; define human escalation coverage and incident response; confirm professional liability and worker safeguards. Do not rely on gig contributors for medical or emergency response. Call India's 112 service when immediate danger warrants it.

## Limitations

- Not yet ready for controlled real-user care. PostgreSQL deployment, Docker stack, migrations against PostgreSQL, and the local web page and API are available, but a full automated browser end-to-end run and PostgreSQL deployment check remain outstanding.
- Email verification, password reset, multi-factor authentication, account recovery, and shared/distributed rate limiting are not implemented.
- Contributor “training complete” is a short knowledge check, not practical competency certification. Uploaded identity documents are not collected or verified by software; operator approval is a human workflow.
- There is no partner adapter, real partner network, or partner booking acceptance contract.
- Payment integration requires real sandbox keys and end-to-end provider/webhook tests. Refund calls and webhook transitions need additional sandbox verification; live payments are disabled by default.
- Fitbit access and OAuth flows need account approval, device/user testing, token-refresh handling, and provider failure tests. No wearable alert rule is clinically validated.
- WhatsApp, AssemblyAI, and OpenAI requests have not been exercised against their live sandboxes. External processing occurs only after the profile consent flag, but contracts, retention, regional data transfers, and provider privacy terms need review.
- A red alert requires a human operator and is not an emergency service. There is no guaranteed 24/7 response coverage.
- The database records configured prices and actual payment states; operational overhead, travel time, operator time, satisfaction, false alerts, missed events, and cost savings are not yet instrumented comprehensively.
