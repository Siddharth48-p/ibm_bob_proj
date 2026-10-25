# MVP implementation checklist

Status labels:

- **Implemented · locally tested** — code is present and exercised by the local SQLite-backed API test suite.
- **Implemented · not integration tested** — code is present, but its runtime dependency or provider sandbox was unavailable.
- **Blocked** — cannot be activated without an external account, credential, approval, deployment, or human operational process.
- **Not implemented** — explicitly outside this MVP build.

## Platform and operations

- [x] FastAPI modular monolith with PostgreSQL connection support and versioned migrations — **Implemented · locally tested** against SQLite development/isolated test fixtures; PostgreSQL is **not integration tested**.
- [x] Docker Compose definitions for PostgreSQL, API, and independent worker — **Implemented · not integration tested**; Docker was unavailable in the build environment.
- [x] API and worker health reporting, stale job recovery, retry/backoff, request IDs, security headers, and audit records — **Implemented · locally tested** where covered; container health and multi-process behavior are **not integration tested**.
- [x] Static website served from an isolated frontend-only directory — **Implemented · locally checked**; project files and configuration are outside the static file root.
- [x] One-time operator bootstrap from deployment secrets — **Implemented · locally tested by code review**, not run against a PostgreSQL deployment.
- [ ] Managed secrets, TLS termination, production hosting, encrypted backups, restore drill, central monitoring, and on-call response — **Blocked** pending deployment and operations setup.

## Accounts, consent, and access control

- [x] Family and contributor registration, login, server-side sessions, password hashing, CSRF protection, role checks, and login rate limits — **Implemented · locally tested**.
- [x] Operator account bootstrap and operator-only review routes — **Implemented · locally tested**.
- [x] Consent gates for care profiles, family booking access, wearable monitoring, and AI voice processing — **Implemented · locally tested**.
- [x] Encryption for profile names, contact details, approximate location, and provider tokens; keyed WhatsApp sender lookup — **Implemented · locally smoke-checked** with Windows user-scoped DPAPI in local preview and Fernet configuration in deployment. Test suite substitutes identity field crypto to isolate route behavior.
- [ ] Email verification, password reset, MFA, account recovery, and distributed rate limiting — **Not implemented**.
- [ ] Legal review, privacy impact assessment, provider data-transfer review, and retention policy approval — **Blocked** pending qualified review for the launch model.

## Family, booking, and contributor workflows

- [x] Care profile, hourly support booking, eligibility matching, booking history, cancellation and internal replacement search — **Implemented · locally tested**.
- [x] Contributor onboarding, training knowledge check, operator identity state, availability, and eligible booking acceptance — **Implemented · locally tested**.
- [x] Separate expiring check-in and check-out OTPs, completion, feedback, incidents, and payout state — **Implemented · locally tested**.
- [x] Human operator incident queue, response notes, alert acknowledgement/closure, and message review queue — **Implemented · locally tested**.
- [x] High-risk medical and personal-care task exclusions — **Implemented · locally tested** for covered validation rules.
- [ ] Real identity document capture/verification, practical competency certification, employment safeguards, insurance, and staffed escalation — **Blocked** pending human and operational processes.
- [ ] External partner-network booking and replacement — **Blocked**; no partner contract/API or verified network is configured. Internal search records `unfilled` when no eligible contributor is available.

## Messaging, voice, and reminders

- [x] Reminder scheduling, independent worker queue, provider delivery state, operator-visible blocked queue/manual retry, retry/block status, and retention purge — **Implemented · locally tested** with missing-provider behavior.
- [x] WhatsApp webhook verification, message deduplication, template sending adapter, and consent-aware voice queue — **Implemented · locally tested** for local logic.
- [ ] Live WhatsApp delivery — **Blocked** pending Meta account setup, public HTTPS callback, credentials, and approved templates.
- [x] Consent-gated AssemblyAI transcription and OpenAI intent extraction adapter with urgent-language review and no automatic booking — **Implemented · not integration tested**.
- [ ] Live transcription/intent provider verification — **Blocked** pending provider credentials, privacy review, and sandbox checks.

## Wearables and alerts

- [x] Fitbit OAuth connection and encrypted token storage — **Implemented · not integration tested**.
- [x] Authenticated normalized wearable ingestion, consent checks, event deduplication, value/unit/time validation, configurable review thresholds, and alert records — **Implemented · locally tested**.
- [ ] Live Fitbit user authorization and sync — **Blocked** pending registered app, credentials, user approval, and device/account testing.
- [ ] Clinical validation, guaranteed fall detection, and emergency response coverage — **Not implemented**. Alerts are review prompts, not diagnoses or emergency services.

## Payments and analytics

- [x] Server-side Razorpay order creation, checkout signature verification, webhook signature verification, event idempotency, and payment/refund state — **Implemented · locally tested** for blocked configuration and local logic; provider sandbox is **not integration tested**.
- [ ] Sandbox checkout, captured/failed/refund event verification, and payout settlement — **Blocked** pending Razorpay test credentials and configured webhook endpoint.
- [x] Database-backed booking, fulfilment, unfilled work, payment, alert, and quality counts — **Implemented · locally tested**.
- [ ] Measured satisfaction, operator time, false/missed alert rates, and cost-savings evidence — **Not implemented** until real, appropriately governed observations exist.

## Verification summary

- Local API and security tests are run with `python -m unittest discover -s tests -v`.
- Frontend syntax is checked with `node --check app.js`.
- Docker Compose, PostgreSQL migrations, live provider sandboxes, and a full browser end-to-end suite were not verified in this environment.
- This build is a pilot-preparation MVP, not ready for unsupervised or clinical care.
