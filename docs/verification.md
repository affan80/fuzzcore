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

## Parameter slice, verified before merge

See `parameter-fixture-evidence.md`. Five backend and one mobile-policy regression failed first. The full local suite passes 58 backend tests, five mobile-policy tests, TypeScript and web export. Positive/secure loopback fixture tests and web UI completed nineteen total requests. Reflection/duplicate-value outputs stay informational signals, not injection/bypass proof. Exact-head CI https://github.com/affan80/fuzzcore/actions/runs/44876815211 passed all four jobs, including Docker nineteen-request smoke and APK compile, before PR15 merged.

## Custom cases, verified before merge

See `custom-fixture-evidence.md`. Fourteen backend cases and one mobile-policy case failed first. Full local suite: 74 backend tests, six mobile-policy tests, TypeScript and web export. Actual loopback UI completed twenty requests using one custom case. The maximum three-case plan is twenty-two requests. Schema rejection, mismatch behavior and immutable case versions are tested. Exact-head CI https://github.com/affan80/fuzzcore/actions/runs/44878113215 passed all four jobs including Docker22 checks and APK, before PR16 merged.

## Local DNS, verified before merge

See `dns-fixture-evidence.md`. Five backend regressions and one mobile-policy regression failed first. Full local suite:79 backend tests,7 mobile tests, TypeScript and web export. Real local UDP positive/wildcard fixtures pass. Actual loopback UI completes23 checks with one custom case. Maximum plan25 checks. Exact-head CI https://github.com/affan80/fuzzcore/actions/runs/44879542458 passed all four jobs including Docker25 checks/newDNS and APK before PR17 merged.

## Report/review/retest, green before merge

See `report-retest-evidence.md`. Seven failing backend regressions preceded implementation. Full local suite:87backend tests,7mobile tests, types/web export. Real loopback UI proved JSON+HTML downloads, matching totals/review state, immutable snapshot and same-scope linked retest/comparison. Report/mobile pixels inspected. Exact-head run https://github.com/affan80/fuzzcore/actions/runs/44880894769 passed all four checks including Docker exports/snapshots/retest and APK before PR18 merged; native file share is unverified. npm audit:3moderate Expo fingerprint/minimatch advisories, no high/critical; no blind major downgrade applied.

## Durable module progress, local verification pending CI

See `module-progress-evidence.md`. Nine backend regressions failed first, including final-response429; three new mobile formatting checks began red. Full local suite:96backend,10mobile, types/web export. Real loopback UI showed running/completed per-module counters, matching report export and cancellation with later modules not_run. Historic fine-grained results are explicitly unavailable, never inferred. Docker smoke checks the stored25-check plan; exact-head CI and native acceptance remain separate.

## Named disposable custom POST/header checks, local verification pending CI

See `custom-post-evidence.md`. Seven new backend checks failed before implementation, eighteen new cases pass. Full suite114backend/11mobile, types/web export. Old GET canonical JSON/hashes stay identical. Real loopback UI completed the named stateless POST plus header expectations under the unchanged23-check selected plan, exported matching evidence and reset consent on example change. Exact-head Docker/APK CI and native acceptance remain separate.

## Still unverified or unfinished

- Physical Android install, SecureStore, background/reconnect behavior and trusted phone-to-backend HTTPS. User computer OS and Android device details are still needed.
- Broader API inventory/transmission assessment, broader DNS inputs and saved custom-case listing; traversal/upload fixture scenarios; richer report/remediation/retest workflow and full-app acceptance.
- Physical Android verification of per-module progress after background/reconnect.
- All possible egress routes, compromise resistance and production deployment hardening.
- Recovery of every RQ failure mode. Current recovery handles unsent intents and explicit stale interrupted work; it is not a full distributed scheduler.
- Final dependency advisory review, production signing and clean-machine submission rehearsal.

A discovered path or host is not a vulnerability. An empty result set is not a security certificate. No full-app or native-device completion is claimed.
