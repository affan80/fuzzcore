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

## Durable module progress, green before merge

See `module-progress-evidence.md`. Nine backend regressions failed first, including final-response429; three new mobile formatting checks began red. Full local suite:96backend,10mobile, types/web export. Real loopback UI showed running/completed per-module counters, matching report export and cancellation with later modules not_run. Historic fine-grained results are explicitly unavailable, never inferred. Exact-head run https://github.com/affan80/fuzzcore/actions/runs/44881554293 passed all four jobs including Docker stored25-check progress and APK before PR19 merged; native acceptance remains separate.

## Named disposable custom POST/header checks, green before merge

See `custom-post-evidence.md`. Seven new backend checks failed before implementation, eighteen new cases pass. Full suite114backend/11mobile, types/web export. Old GET canonical JSON/hashes stay identical. Real loopback UI completed the named stateless POST plus header expectations under the unchanged23-check selected plan, exported matching evidence and reset consent on example change. Exact-head run https://github.com/affan80/fuzzcore/actions/runs/44882141935 passed all four checks including namedPOST/header Docker smoke and APK before PR20 merged; native acceptance remains separate.

## Directory controls, local verification pending CI

See `directory-control-evidence.md`. Ten new backend regressions failed before their fixes. Full local suite124backend/11mobile, types/web export. Positive and soft404 real local fixtures, unavailable/redirecting controls, production dispatch and actual web report evidence pass. The four-check directory budget and maximum25-check aggregate plan are unchanged. Fresh Docker/APK CI and native acceptance remain separate. Traversal/upload cleanup is not implemented by this slice.

## Opt-in synthetic file canary, local verification pending CI

See `file-canary-evidence.md`. Eight new backend regressions failed before fixes; fourteen new tests pass. Full suite138backend/12mobile, types/web export. Explicit immutable selection adds3symbolic read-only requests, with no host files read or included. Defaults stay4/25; opt-in directories7/full maximum28. Positive/secure real fixtures and actual26-check/10-result web journey pass. PR22 exact-head CI https://github.com/affan80/fuzzcore/actions/runs/44884208777 passed all four jobs, including Docker28-check/12-result smoke and APK. PR22 merged to dev at 4f019805c2f6103716fbf8a0cf34fc87d08410ec. Native acceptance remains separate. The later upload slice is described below.

## Still unverified or unfinished

- Physical Android install, SecureStore, background/reconnect behavior and trusted phone-to-backend HTTPS. User computer OS and Android device details are still needed.
- Broader API inventory/transmission assessment, broader DNS inputs and saved custom-case listing; richer report/remediation/retest workflow and full-app acceptance.
- Physical Android verification of per-module progress after background/reconnect.
- All possible egress routes, compromise resistance and production deployment hardening.
- Recovery of every RQ failure mode. Current recovery handles unsent intents and explicit stale interrupted work; it is not a full distributed scheduler.
- Final dependency advisory review, production signing and clean-machine submission rehearsal.

A discovered path or host is not a vulnerability. An empty result set is not a security certificate. No full-app or native-device completion is claimed.


### Benign temporary upload slice

Separate opt-in `upload-v1` adds a fixed in-memory harmless-text create/read/delete/absence check plus two explicit cleanup recovery reserves. Defaults remain 4 directory / 25 full-run attempts. Both canary+upload options reserve 13 directory / 34 maximum full-run attempts; normal maximum execution uses 32 and shows 2 unused reserves. No arbitrary content, filesystem writes, executable bytes or upload-vulnerability claim. Cleanup status/attempts are persisted and exported; unverified cleanup blocks new uploads, not read-only runs. Cancellation still performs reserved cleanup; expiry is a fallback, not proof. See [upload cleanup evidence](upload-cleanup-evidence.md) for test-first results, limits, source references and stop-worker recovery.


### Saved immutable case versions

Authenticated version library validates/saves/lists/retrieves one to three declarative cases per immutable version. Saving and loading never queue a scan. Loading copies into the editor and resets consent; later edits never alter past scans. Owner-scoped storage is capped at100 versions by database constraints; keyset pages hold50. Migration13 creates an empty library without inventing past saves. See [saved case evidence](saved-case-evidence.md). No scan budget expansion.


### Report filters and manual fixed review

Shared validated filters apply to findings, JSON/HTML exports and new immutable snapshots, with matching totals and visible unfiltered counts. Fixed remains an explicit manual review label: a note plus completed owner-scoped exact-scope linked retest where the fingerprint was not observed. Partial, still-observed or unresolved-cleanup evidence is rejected. Original evidence remains intact; no automatic fix or source deployment. See [filter/review evidence](report-filter-review-evidence.md).


### Explicit curated API inventory

Opt-in immutable `inventory-v1` adds4 read-only fixed lab requests after the existing6 API ownership checks: randomized missing control and named public/protected/hidden routes. Header/transport facts are informational, not production weakness claims. No arbitrary schema import or redirects. Defaults never expand. All current options reserve38/use36 maximum requests with2 unused cleanup reserves. See [API inventory evidence](api-inventory-evidence.md).

### DNS response boundaries

The unchanged three-query local DNS plan clears recursion-desired, rejects unexpected/truncated envelopes and suppresses A discoveries for aliased answers without following or storing foreign alias targets. Bounded flag metadata is informational, not a DNS vulnerability claim. Local205backend/19mobile, types/web export pass, including real UDP fixture and counted failure. Fresh Docker/APK gates and native acceptance remain separate. See [DNS response evidence](dns-response-evidence.md).

### Parameter recognition and differential signals

The unchanged six-marker plan now exposes fixed q recognition backed by distinct controls. Controlled test-only parser mismatch and named quoted-error counterparts remain informational, preserve actual status and never prove injection or authorization bypass. Defaults and budgets remain unchanged. Local219backend/19mobile, types/web export and real HTTP worker/export checks pass; fresh Docker/APK/native gates remain separate. See [parameter observation evidence](parameter-observation-evidence.md).
