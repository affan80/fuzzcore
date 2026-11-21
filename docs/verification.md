# Verification status

Last updated during Day 1 on 21 Nov 2026. See `day1-evidence.md` for test-first change details and recovery procedure.

## Proven in the published ingress baseline

Actions run https://github.com/affan80/fuzzcore/actions/runs/44868493037 has passed unit/mobile checks, the dev PR-target check and real Docker integration. The Docker smoke starts Postgres, Redis/RQ, API, worker, scanner and fixture; completes four fixed checks with three informational discoveries; and inspects scanner networks/credential absence. The APK job also passed, so this ingress baseline run is fully green. This does not verify the newer lifecycle slice until its separate run completes.

The first APK in run https://github.com/affan80/fuzzcore/actions/runs/44772454822 was retrieved and inspected: dev.fuzzcore.lab / FuzzCore Lab v1.0.0, 66,584,113 bytes, minSdk24 metadata, APK v2 Android Debug signing. ZIP digest matched the provider. This is not production signing or verified Android-version compatibility.

## New lifecycle slice, local only until its own CI completes

30 Python tests pass, including authorization, fixed scope, idempotency, one-active-run index, forced duplicate-worker claim race, queue retry, migrations and legacy history preservation. Two Node mobile policy tests pass. TypeScript and web export pass.

Web UI integration uses a real loopback HTTP lab plus a SQLite/threaded test adapter. It verifies explicit authorization before start, four checks/three discoveries, reset confirmation and history. Views were inspected at 320/390/1280 pixels with no observed page errors. This is not native Android or Docker/RQ evidence.

The lifecycle source's updated real-Docker smoke additionally checks scanner rejection of DB/Redis service connections. That assertion must pass in its fresh CI run before it is counted as verified.

## Still unverified or unfinished

- Physical Android install, SecureStore, background/reconnect behavior and trusted phone-to-backend HTTPS.
- Remaining module fixtures and implementations, report/retest flow and full app acceptance.
- All possible egress routes, compromise resistance and production deployment hardening.
- Recovery of every RQ failure mode. Current recovery handles unsent intents and explicit stale interrupted work; it is not a full distributed scheduler.
- Final dependency advisory review, production signing and clean-machine submission rehearsal.

A discovered path is not a vulnerability. An empty result set is not a security certificate. No Day 1 exit or full-app completion is claimed while device and scope gates remain open.
