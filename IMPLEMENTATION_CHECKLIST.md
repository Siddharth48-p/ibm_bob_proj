# CareCircle implementation checklist

Status reflects the gig-worker management platform in this iteration. SQLite-backed API tests are locally executed; PostgreSQL and external services still require separate verification.

## Roles and access

- [x] Two public roles: organisation admin and gig worker; no customer login/app.
- [x] Admin bootstrap from one-time environment credentials; no public admin registration.
- [x] Password hashing, server-side sessions, CSRF validation, and role checks.
- [x] Existing records and migrations retained; new features extend the schema.

## Worker onboarding and eligibility

- [x] Worker registration and encrypted profile fields for contact, home address, and provider reference.
- [x] Aadhaar provider-reference flow and explicit development sandbox label.
- [x] Sandbox identity cannot be represented as verified or used for gig eligibility.
- [x] Separate identity verification, admin approval, training status, account state, and availability.
- [x] Training is admin-controlled and records who changed it and when; no worker LMS or self-completion.
- [x] Backend eligibility check and worker-facing reasons.
- [ ] Automated Aadhaar verification provider integration — blocked until an authorized provider and credentials are configured.

## Gigs and task execution

- [x] Admin creates open gigs or targets one eligible worker.
- [x] Gig preview hides client contact, full address, and care details until acceptance.
- [x] Worker can preview, accept, pass, filter, and view accepted/history records.
- [x] Conditional assignment prevents two workers claiming the same gig.
- [x] Sequential task progress with timestamps, worker attribution, admin notifications, and activity history.
- [x] Completion requires a client/organisation code.
- [x] Admin can cancel gigs through the existing lifecycle route.
- [ ] Gig editing/closing UI and multi-helper assignment — not implemented; the current workflow intentionally enforces one worker per gig.
- [ ] WebSocket/SSE delivery — not implemented; the app polls for updates every 15 seconds.

## Admin operations and earnings

- [x] Worker search and review controls for identity, approval, training, and account state.
- [x] Persistent organisation notification centre for onboarding and gig events.
- [x] Database-driven worker and gig summary analytics, onboarding rates, acceptance time, and monthly gig trends.
- [x] Earnings, pending payout records, and admin-recorded paid state with settlement reference.
- [ ] Automated payout/transfer integration — not implemented.
- [ ] Full chart suite and production alert/overdue-task automation — not implemented.

## Verification

- [x] `python -m unittest discover -s tests -v` — passed locally against SQLite.
- [x] `node --check frontend/app.js` — passed.
- [ ] PostgreSQL migration and Docker Compose execution — not verified in this workspace.
- [ ] Live browser E2E run — not performed.
- [ ] External provider sandbox verification — blocked on credentials and approvals.
