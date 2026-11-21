# FuzzCore architecture and implementation boundary

## Product and full scope

React Native Android APK controls a separate server. The full design covers preparation, directories/files, virtual hosts, APIs, parameters, declarative custom cases, subdomains, reporting and remediation/retest. It is a bounded authorized-lab application, not a public scanning service. Explicit authorization confirmation does not prove third-party ownership.

The implementation supports four fixed resource paths , a three-request vhost comparison and six synthetic API ownership checks plus six harmless parameter-marker observations against one bundled lab. Future modules remain unavailable in `/v1/capabilities` until their positive and negative fixture tests pass. No fake results, automatic exploitation, RCE, credential attacks, arbitrary scripts or auto-deployed fixes.

## Flow

Phone → authenticated HTTPS API → Postgres scan/outbox → Redis/RQ stable job ID → trusted worker → restricted scanner gateway → fixed lab fixture → normalized records → API → phone/history/report.

API owns validation, identity, ownership, scope and budgets. Postgres is the source of durable run status. The phone may stop or background without owning the worker lifecycle. Active views poll every two seconds; terminal runs stop polling. Tokens use SecureStore on native and memory only in web preview.

## Networks and trust

- API: data plus a separate ingress bridge. Only host loopback `127.0.0.1:8000` is published.
- Worker supervisor: internal data/control networks, DB/Redis credentials.
- Scanner gateway: internal control/lab networks only, no DB/Redis/user-token credentials. Four fixed paths plus allowlisted default/control/seeded vhost cases, no redirects. Vhost bodies are hashed within a 16 KiB processing limit and discarded.
- DB/Redis: data only, no published ports.
- Web fixture: lab only. A non-recursive UDP DNS fixture is attached only to the lab network, with no published port. Three fixed suffix/control/candidate queries never use public resolvers or trigger HTTP follow-up.

All application containers run non-root with dropped capabilities. No Docker socket, host mounts or target-provided commands. The trusted worker bridges data and control, an explicit residual trust boundary. Passing network membership and local data-service rejection tests does not prove every possible egress route or sandbox escape is blocked.

## Current API

- GET /health
- GET /v1/capabilities
- GET /v1/targets
- POST /v1/scans
- GET /v1/scans
- GET /v1/scans/{id}
- POST /v1/scans/{id}/cancel
- GET /v1/scans/{id}/findings

All except liveness require bearer authentication. Scan creation accepts only `local-lab`, `lab-small`, directory/vhost/API/parameter/custom/DNS module selection and explicit boolean confirmation. Unknown fields and modules fail validation. API response identifiers are `id`, consistently used by the app.

## Persistence and lifecycle

Scans store owner, idempotency key, status, counters, timestamps, safe error, fixed target/scope version and authorization-confirmation time. Scans also store the selected module snapshot and corresponding total request budget. Findings store their module and bounded informational evidence, including vhost control signatures. An enqueue intent is saved in the same transaction as the scan.

Unique(owner, idempotency key) gives retry stability. A partial unique index on active states gives one active run per owner across API processes. Atomic queued→running update gives one worker claim even with duplicate deliveries. The outbox is at-least-once dispatch with stable RQ job IDs, not exactly-once messaging.

States currently used: queued, running, cancelling, cancelled, completed, failed, timed_out and interrupted. Queued cancellation is immediate; running cancellation stops new traffic at the next bounded checkpoint. Partial findings remain available. Broader per-module/partial status is planned with the additional modules.

Schema migration ledger versions adopt the legacy schema, add active-run/outbox persistence, and add scope confirmation without inventing past authorization. Version 4 interrupts unknown-consent queued legacy work; version 5 adds module selection and structured evidence; version 6 adds persisted severity/confidence. Upgrades are forward-only and preserve history. Legacy conflicting active runs fail visibly for operator review. A stopped-worker recovery command marks stale work interrupted and retries unsent queue intents. It never blindly resumes interrupted scans.

## Remaining full-design contracts

Modules will accept typed, server-validated inputs and share one global budget. Discovery uses default/missing/wildcard controls. API ownership checks use six known two-actor fixture scenarios with secure and deliberately vulnerable counterparts. Only their synthetic proof can be fixture-confirmed. Parameter reflection and duplicate-value observations remain informational signals, not proof of XSS/SQL injection or parser-bypass defects. Custom cases are bounded JSON GET expectations on three fixture paths, never code. Up to three normalized immutable cases/version are stored with each run. Version 7 adds case snapshot/version fields. DNS discoveries do not authorize new HTTP targets. Reporting is authenticated JSON and escaped printable HTML with restrictive CSP, immutable snapshots and review states. Linked retests require fresh consent and identical modules/cases; comparison never automatically declares fixed. Remediation is rule-linked advice, manual fixture changes and linked retest, not automatic deployment.

Per-module progress and immutable custom-case versions are implemented. Planned additions: richer report filtering and declared-fixed/retest workflow; capability flags and schema versions evolve with tests. Keep one user/worker/stack rather than adding SaaS/scaling infrastructure.

## Three-day sequence

1. Day 1: approved design, trustworthy Compose slice, persistence/recovery, explicit authorization, truthful capabilities, one complete module, APK and phone connectivity gate.
2. Day 2: remaining bounded modules and lab fixtures, module selection/progress, evidence and cancellation under shared limits.
3. Day 3: reports/remediation/retest, regression and clean startup, actual Android install/reconnect acceptance, final APK/source/demo and known limitations.

The Nov 23 target is tight after the design pause. A working APK build is not proof of Android device behavior or a complete app. Trusted phone-to-backend HTTPS, final device testing and other modules remain open. No paid hosting, public tunnel, iOS or Play Store release is assumed.

## Durable module progress

Migration10 adds per-module state/planned/attempted/completed checkpoints to each new scan. Request starts and returned responses are committed separately. Terminal runs preserve completed modules and mark never-started modules not_run. Legacy detailed progress is unavailable rather than inferred from aggregate counts. Scan detail, history and reports expose the same state. This does not change the request budget or fixture-only authority. See `module-progress-evidence.md`.

## Custom schema v2

GET remains default. POST is limited to one stateless disposable fixture with a bounded harmless marker, no query parameters or supplied request headers. Header expectations allow only content-type and x-fixture-mode, exact text matching. Old absent-field canonicalization preserves existing case versions. Capability metadata advertises these exact limits. See `custom-post-evidence.md`.

## Directory signatures

Production directory dispatch uses a randomized missing-path control first, then three fixed resources, with one request each. Status/length/SHA256 comparisons filter exact soft-404 signatures. Unavailable/redirecting controls fail partial rather than imply a clean assessment. The scanner caps body processing at16KiB and retains no raw body. The old status-only helper is not a production fallback. See `directory-control-evidence.md`.

## Explicit additional directory cases

Migration11 persists directory_cases as an immutable per-run selection. The default is empty. canary-v1 adds three fixed read-only symbolic fixture cases under the directories module, never host-file access. Its counters plan7 directory requests and a maximum28 full plan; default4/25 plans are preserved. Retry/retest checks require the same selection. Capabilities advertise request cost and off-by-default status. See `file-canary-evidence.md`.


### Benign temporary upload slice

Separate opt-in `upload-v1` adds a fixed in-memory harmless-text create/read/delete/absence check plus two explicit cleanup recovery reserves. Defaults remain 4 directory / 25 full-run attempts. Both canary+upload options reserve 13 directory / 34 maximum full-run attempts; normal maximum execution uses 32 and shows 2 unused reserves. No arbitrary content, filesystem writes, executable bytes or upload-vulnerability claim. Cleanup status/attempts are persisted and exported; unverified cleanup blocks new uploads, not read-only runs. Cancellation still performs reserved cleanup; expiry is a fallback, not proof. See [upload cleanup evidence](upload-cleanup-evidence.md) for test-first results, limits, source references and stop-worker recovery.


### Saved immutable case versions

Authenticated version library validates/saves/lists/retrieves one to three declarative cases per immutable version. Saving and loading never queue a scan. Loading copies into the editor and resets consent; later edits never alter past scans. Owner-scoped storage is capped at100 versions by database constraints; keyset pages hold50. Migration13 creates an empty library without inventing past saves. See [saved case evidence](saved-case-evidence.md). No scan budget expansion.


### Report filters and manual fixed review

Shared validated filters apply to findings, JSON/HTML exports and new immutable snapshots, with matching totals and visible unfiltered counts. Fixed remains an explicit manual review label: a note plus completed owner-scoped exact-scope linked retest where the fingerprint was not observed. Partial, still-observed or unresolved-cleanup evidence is rejected. Original evidence remains intact; no automatic fix or source deployment. See [filter/review evidence](report-filter-review-evidence.md).


### Explicit curated API inventory

Opt-in immutable `inventory-v1` adds4 read-only fixed lab requests after the existing6 API ownership checks: randomized missing control and named public/protected/hidden routes. Header/transport facts are informational, not production weakness claims. No arbitrary schema import or redirects. Defaults never expand. All current options reserve38/use36 maximum requests with2 unused cleanup reserves. See [API inventory evidence](api-inventory-evidence.md).

### DNS response boundaries

DNS questions explicitly clear recursion-desired. Mismatched/truncated envelopes fail closed; IN/A records require the exact requested name and an answer without aliases. No alias target is retained or followed. Stored flag booleans describe only the isolated fixture; they do not assess real recursion exposure, DNSSEC or takeover risk. The three-query budget and fixed destination stay unchanged.
