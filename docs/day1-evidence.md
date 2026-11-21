# Day 1 implementation evidence, 21 Nov 2026

## Scope

One user, a fixed isolated lab, four resource checks, and an Android React Native controller. Other discovery modules and reports are still planned. No unrestricted targets, exploits or remote command execution.

## Test-first changes

- Compose boundary: new regression failed because the API was only on an internal network. API now has its own ingress bridge; host binding stays 127.0.0.1:8000. Scanner, DB and Redis have no published ports. Real Docker smoke and the full baseline workflow passed in Actions run 44868493037.
- Authorization: tests failed for missing/false/non-boolean confirmation. API now requires explicit true and records the confirmation time and fixed scope version. Old migrated records keep unknown authorization as NULL, never fabricated approval.
- Capabilities: failing 404 test led to a truthful endpoint. Only directory discovery is supported; other modules are explicitly unavailable.
- One active run: database partial unique index covers queued/running/cancelling per owner. Tests include two application instances sharing a DB.
- Job claim: a forced two-worker race produced eight requests for a four-path run. Replaced read-then-write with an atomic conditional update; test now records exactly four.
- Enqueue recovery: failing tests showed queue outages made runs unrecoverable. Scan and enqueue intent now commit together; retry with the same idempotency key can dispatch the same scan. Stable RQ job IDs and an atomic worker claim prevent duplicate traffic. This is at-least-once dispatch, not a claim of exactly-once messaging.
- Schema: versioned forward migration ledger adopts the original tables, adds the active-run index/outbox, and stores scope confirmation. A legacy-database test preserves old history and unknown authorization. Conflicting legacy active runs cause a visible migration failure, not silent deletion.
- Interrupted work: an explicit operator recovery command requires the worker to be stopped, marks stale runs interrupted, and retries unsent queue intents. It does not automatically replay interrupted scans.
- Mobile: policy tests failed before the request builder existed. Start is disabled until authorization is confirmed; a successful submit resets confirmation. Web UI integration ran against a real loopback fixture, completed four checks/three discoveries and showed history. This test adapter is SQLite/threads, not Docker/RQ or native Android.

## Local results

30 Python tests; 2 Node mobile-policy tests; TypeScript check and web export pass. Visual web views inspected at 320, 390 and 1280 pixels. No page errors in the observed UI test. These results do not prove Android install, SecureStore behavior or phone-to-backend HTTPS.

## Recovery procedure

1. Stop the worker, leaving DB/Redis/API running: `docker compose stop worker`.
2. Run the recovery command from the stopped-worker image/config: `docker compose run --rm --no-deps worker python -m fuzzcore.recovery --worker-stopped`.
3. Read the summary, then start the worker: `docker compose start worker`.
4. Interrupted scans remain interrupted for explicit manual retry. Pending unsent queue intents are retried with their existing scan IDs. Do not run the command against an active worker.

Migration failures need inspection and a database backup. Do not delete the volume to make tests appear green. Demo reset with `docker compose down -v` intentionally deletes history and is not a recovery path.

## Current docs used

- https://docs.docker.com/reference/compose-file/networks/
- https://docs.docker.com/engine/network/port-publishing/
- https://docs.sqlalchemy.org/en/20/core/constraints.html
- https://docs.pydantic.dev/latest/concepts/validators/
- https://docs.pytest.org/en/stable/how-to/assert.html
- https://fastapi.tiangolo.com/tutorial/testing/
- https://python-rq.org/docs/jobs/
- https://docs.expo.dev/versions/latest/sdk/securestore/

Existing compatible dependency pins were retained. Current documentation does not imply that every newest dependency release should be adopted without a failing compatibility need and regression tests.
