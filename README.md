# FuzzCore Lab

React Native / Expo Android controller with a separate FastAPI and RQ lab-discovery backend. This is an academic implementation in progress, not a finished vulnerability scanner.

## Current scope

One pre-provisioned user, one fixed authorized lab, three bounded resources plus a fresh missing-path control and three virtual-host control/candidate requests. Six read-only synthetic API ownership checks add a known two-actor fixture proof. Six harmless parameter-marker checks add informational reflection/duplicate-value signals, never proof of injection. Modules can run separately or together with at most twenty-five checks including up to three versioned declarative custom GET/named disposable POST checks and three local DNS queries. DNS discoveries never trigger HTTP follow-up. This is not a general API security assessment. No arbitrary targets, exploits, remote code execution, external wordlists or auto-fixes. All six categories have bounded fixture implementations. Broader scenarios in the full design remain unfinished; the app describes its fixture limits.

## Run locally

Requires Docker Compose. Copy `.env.example` to `.env` and replace the placeholders with locally generated credentials. Never commit that file. The database URL password must be URL-encoded where necessary.

```
docker compose up --build -d
python infra/smoke.py
```

The control API is bound only to `127.0.0.1:8000`. DB, Redis, scanner and lab have no published ports. API has a separate ingress bridge; scanner only has internal control/lab networks. Do not expose this stack to the internet.

The Android phone needs a reachable trusted HTTPS API endpoint. The supplied Compose setup does not provision TLS, a public endpoint or phone connectivity. `localhost` on your phone means the phone. These remain explicit device/deployment gates.

## Develop and test

```
pip install -r services/api/requirements-dev.txt
PYTHONPATH=services/api pytest services/api/tests -q
cd apps/mobile
npm ci
node --experimental-strip-types --test tests/*.test.mjs
npx tsc --noEmit
npx expo export --platform web
```

Use Node 22 for the current pinned Expo toolchain. Preserve lockfiles. Check current official docs before changes, then prove compatibility with tests rather than upgrading blindly.

Read `CONTRIBUTING.md`. All contribution PRs target `dev`; `main` is preserved for release snapshots. Each behavior starts with a failing test, then a minimal implementation and a verified result. See `docs/day1-evidence.md` for actual test results and known gaps.

## API baseline

- `GET /health`: liveness.
- `GET /v1/capabilities`: actual supported modules and fixed profile.
- `GET /v1/targets`: fixed authorized lab.
- `POST /v1/scans`: target/profile, supported modules, explicit `authorization_confirmed: true`, and an `Idempotency-Key` header.
- `GET /v1/scans`, scan detail, findings and cancel routes.

All except liveness require the configured bearer token. The server rejects unsupported modules and concurrent active runs. The confirmation screen does not establish permission to test third-party targets.

## Persistence and recovery

Postgres stores scans, scope confirmation and a durable enqueue outbox. A partial unique index enforces one active run per owner. Conditional DB updates claim work atomically. Migrations preserve legacy history and do not invent past authorization.

Do not reset volumes to hide failures. See `docs/day1-evidence.md` for the explicit stopped-worker recovery procedure. Unsent queue intents can be retried; interrupted work is not automatically replayed. Back up the database before resolving migration conflicts.

## APK and verification

The Actions workflow builds a self-contained internal-test APK, not an AAB. The generated release build uses an Android Debug certificate, not production/Play Store signing. The APK needs a running backend.

The first APK was compiled and its package/signing metadata inspected. Native installation, SecureStore, lifecycle behavior and phone-to-backend HTTPS are separate, still-unverified gates. Web screenshots and passing TypeScript are not Android device tests.

## Security and remaining work

The scanner receives no DB, Redis or user-token credentials and accepts only four fixture paths. No redirects or response bodies are followed/read. Findings are informational discoveries, not confirmed vulnerabilities.

Remaining design work includes broader directory/API/parameter/custom fixture scenarios, richer filtering and remediation/retest workflow, broader recovery/security regressions, trusted device connection and final demo. All six bounded module categories and basic report/retest UI exist. No green badge establishes complete isolation or production readiness.

Stopping with `docker compose down -v` intentionally deletes demo history. It is a reset, not a safe recovery operation.

Authenticated JSON/printable HTML reports, immutable report snapshots, review states and same-scope linked retests are implemented. Native export uses a user-controlled share sheet. Device behavior remains unverified. See `docs/report-retest-evidence.md` for boundaries and tests.

Per-module progress records attempted requests separately from completed responses. Failed, cancelled and interrupted runs never mark later modules complete. Historic detailed progress is unavailable rather than fabricated. See [progress evidence](docs/module-progress-evidence.md).

Custom schema now supports exactly one named stateless POST scenario and two allowlisted response-header expectations. Existing GET case hashes are preserved. See [custom POST evidence](docs/custom-post-evidence.md).

Production directory discovery compares status/length/SHA256 with a randomized missing-path baseline, filters identical soft-404s and fails unavailable baselines. It still uses four checks. See [directory control evidence](docs/directory-control-evidence.md). Canary/upload cleanup remains separate.
