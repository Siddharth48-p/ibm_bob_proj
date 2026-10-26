# CareCircle — Gig Worker Management Platform

CareCircle is a mobile-first organisation and gig-worker platform for coordinating low-risk elderly-care assistance. The existing FastAPI service, database, authentication, encryption, and migrations remain in place. Public access has two roles: **Organisation Admin** and **Gig Worker**. There is no customer login or customer app.

The interface continues to use the existing CareCircle palette: `#4CAF50`, `#FFC107`, `#FFFFFF`, `#607D8B`, and `#212121`.

The current service area is **Udupi district only**. Worker onboarding and gig creation use a district-fixed Udupi selector and supported localities: Udupi, Manipal, Malpe, Brahmavar, Kaup, Padubidri, Karkala, Hebri, Kundapura, Byndoor, Shirva, Kota, Parkala, Indrali, Alevoor, Santhekatte, Katapady, Perdoor, and Hiriadka. Eligible workers can see gigs across the district; the locality is shown in each offer.

## Run locally on Windows

For a local SQLite preview:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set a unique `APP_SECRET` of at least 32 characters in `.env`. For a local profile-protection key, set `DATA_ENCRYPTION_KEY` to a Fernet key generated with:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Then start the API and local worker:

```powershell
.\scripts\run-local.ps1
```

Open `http://127.0.0.1:8765`. The local preview uses `data/local-preview.db`; use synthetic test data. Stop both processes with Ctrl+C.

The first organisation admin is provisioned once, with environment credentials, never through public registration. Start the preview once and stop it with Ctrl+C so it creates its local secret and database. Then bootstrap the admin against that same SQLite database:

```powershell
$env:APP_ENV = "development"
$env:APP_SECRET = (Get-Content data/local-app-secret -Raw).Trim()
$env:DATABASE_URL = "sqlite:///data/local-preview.db"
$env:BOOTSTRAP_OPERATOR_EMAIL = "admin@example.invalid"
$env:BOOTSTRAP_OPERATOR_PASSWORD = "Use-a-unique-password-123!"
python -m api.bootstrap_operator
Remove-Item Env:BOOTSTRAP_OPERATOR_PASSWORD
```

Start `scripts/run-local.ps1` again and sign in with that admin account. Gig workers register from the sign-in screen and complete their profile in **Profile**.

## PostgreSQL deployment

Docker Compose runs PostgreSQL, the API, and a separate worker. Copy `.env.example` to `.env`, set `APP_ENV=production`, and configure unique `APP_SECRET`, `DATA_ENCRYPTION_KEY`, `TOKEN_ENCRYPTION_KEY`, and database credentials before running:

```powershell
docker compose up --build
```

Open `http://localhost:8000`. Provision the first admin once:

```powershell
docker compose run --rm api python -m api.bootstrap_operator
```

Remove the bootstrap password from the environment after use. Production refuses SQLite. The new migration is `009_gig_worker_platform.sql`; the PostgreSQL/Compose deployment has not been exercised in this workspace.

## Workflow implemented

- Worker registration, profile onboarding, encrypted contact/address/reference fields, and eligibility status.
- Aadhaar identity verification through an authorized provider reference that an admin checks through the provider’s authorized channel. Full Aadhaar numbers, unmasked images, and biometrics are not accepted or stored.
- An explicit **Development sandbox** option. Sandbox results are always labelled as such and are blocked from identity approval and gig eligibility.
- Separate identity verification, organisation approval, admin-controlled training status, account suspension/reactivation, and worker availability. Training changes record the admin and timestamp.
- Server-side gig eligibility: authorized identity verification, admin approval, training completed, and active account. The worker must be available and match the Udupi district, language, and selected gig type; gigs are visible across supported Udupi localities.
- Admin-created open gigs or offers for a selected eligible worker. Gig details include a summary, instructions, client contact/address, schedule, duration, offered payout, priority, and care notes. Client contact and detailed task data are hidden until the worker accepts.
- Mobile worker home with incoming offer popup, pass/accept actions, location/category/date/payout filters, active task details, navigation link, availability, and status reasons.
- Concurrency-safe gig acceptance, recorded pass decisions, sequential `On the Way → Reached → Helping → Done` updates, and an admin/client completion code before completion.
- Persistent organisation notifications and 15-second dashboard polling as the realtime fallback.
- Recorded earnings, pending and paid payout totals. An admin can mark a payout paid only with a settlement reference; this records confirmation and does not initiate a transfer.
- Database-based admin overview, worker management/search, task history, onboarding and gig metrics, and notification centre.
- Existing provider adapters and backend capabilities remain in the repository, but no customer-facing pages or customer authentication are available through the app.

## Identity provider setup and limits

No live Aadhaar provider is configured. Admins can mark a reference verified only when the worker selected **Authorized provider reference** and the admin has checked the result through an authorized provider channel. The sandbox cannot be marked verified and cannot enable gig acceptance. Do not enter Aadhaar numbers in the reference field. There is no automated Aadhaar-provider adapter in this version.

Payouts are records only. No worker payment integration or automatic transfer is enabled. The gig completion code is returned once to the admin at creation so the organisation can hand it to the client for completion confirmation.

The platform is a pilot-preparation baseline and is not ready for unsupervised care or real sensitive data without legal, privacy, security, workforce, and operational review. Existing WhatsApp, voice, wearable, and payment integrations still require the credentials, permissions, and provider tests described in `.env.example` and the earlier integration notes; these are not part of worker registration or task completion.

## Checks

```powershell
python -m unittest discover -s tests -v
node --check frontend/app.js
```

The tests exercise SQLite-backed API flows, worker/admin access boundaries, sandbox identity restrictions, admin-managed training, gig acceptance contention, task transitions, completion confirmation, notifications, and earnings. PostgreSQL migrations, Docker, provider sandboxes, and a full browser E2E run still need deployment verification.
