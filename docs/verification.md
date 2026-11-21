# Verification status

Updated 21 Nov 2026. A compiled APK, working web preview and physical Android acceptance are separate gates.

## Verified foundation on dev

- PR11 postmerge run https://github.com/affan80/fuzzcore/actions/runs/44871310736 passed backend/mobile checks, real Docker/Postgres/Redis/RQ/scanner/fixture integration and APK compilation.
- PR12 exact-head run https://github.com/affan80/fuzzcore/actions/runs/44871499996 passed all four checks before merge into dev. It adds test-first legacy-queue consent protection; 32 backend tests passed locally. Migration v4 does not invent authorization or replay unknown-consent work.
- The lifecycle APK artifact https://github.com/affan80/fuzzcore/actions/runs/44869436224/artifacts/14693666971 was retrieved and its provider digest matched. Package dev.fuzzcore.lab, FuzzCore Lab 1.0.0, 66,584,893 bytes, minSdk24 metadata, APK v2 Android Debug signing. This is internal-test signing, not production or Play Store signing.

## Virtual-host slice, verified before merge

Seven new backend tests failed before implementation. The full backend suite now passes 41 tests, including additional scope-retry and shared-rate-limit regressions. Three Node mobile-policy tests, TypeScript and web export pass. The vhost adapter compares default and freshly randomized control-host signatures with a seeded fixture host. Identical responses and redirects are not discoveries. Destination stays pinned to the fixed fixture. Response evidence is status, length and SHA-256 only, with a 16 KiB body-processing cap. No raw body is persisted.

Module selection is persisted with the scan. Directory-only runs plan four requests; vhost-only three; combined runs seven under one deadline, cancellation checkpoints and request counter. The same idempotency key cannot silently change modules. Only directories and vhosts are advertised. Other surfaces remain unavailable.

PR13 exact-head CI https://github.com/affan80/fuzzcore/actions/runs/44872880662 passed all four jobs, including real Docker combined-seven-request smoke and APK compilation. PR13 is merged to dev. Local loopback fixture tests use SQLite and threads, not Docker/RQ or Android.

## API fixture slice, green CI

See `api-fixture-evidence.md`. Eleven failing regression cases preceded their fixes. The local full suite passes 53 backend tests and four mobile-policy tests, plus TypeScript and web export. A loopback UI run completes thirteen combined requests and shows scoped fixture ownership evidence with remediation. Only a known synthetic two-actor defect can receive fixture-confirmed severity. The secure counterpart produces no finding. Migration v6 preserves old severity/confidence defaults. Exact-head run https://github.com/affan80/fuzzcore/actions/runs/44873694975 passed all four jobs, including the real Docker thirteen-request fixture run and APK compile. PR14 merge is separate from this evidence.

## Parameter slice, local verification pending its own CI

See `parameter-fixture-evidence.md`. Five backend and one mobile-policy regression failed first. The full local suite passes 58 backend tests, five mobile-policy tests, TypeScript and web export. Positive/secure loopback fixture tests and web UI completed nineteen total requests. Reflection/duplicate-value outputs stay informational signals, not injection/bypass proof. Docker nineteen-request smoke and APK compile must pass in the fresh PR run before merge.

## Still unverified or unfinished

- Physical Android install, SecureStore, background/reconnect behavior and trusted phone-to-backend HTTPS. User computer OS and Android device details are still needed.
- Broader API inventory/transmission assessment, custom and DNS modules; traversal/upload fixture scenarios; report/remediation/retest flow and full-app acceptance.
- Module-specific progress UI beyond the current shared run counters.
- All possible egress routes, compromise resistance and production deployment hardening.
- Recovery of every RQ failure mode. Current recovery handles unsent intents and explicit stale interrupted work; it is not a full distributed scheduler.
- Final dependency advisory review, production signing and clean-machine submission rehearsal.

A discovered path or host is not a vulnerability. An empty result set is not a security certificate. No full-app or native-device completion is claimed.
