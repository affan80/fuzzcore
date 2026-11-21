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

Modules will accept typed, server-validated inputs and share one global budget. Discovery uses default/missing/wildcard controls. API ownership checks use six known two-actor fixture scenarios with secure and deliberately vulnerable counterparts. Only their synthetic proof can be fixture-confirmed. Parameter reflection and duplicate-value observations remain informational signals, not proof of XSS/SQL injection or parser-bypass defects. Custom cases are bounded JSON GET expectations on three fixture paths, never code. Up to three normalized immutable cases/version are stored with each run. Version 7 adds case snapshot/version fields. DNS discoveries do not authorize new HTTP targets. Reporting is authenticated JSON and escaped printable HTML. Remediation is rule-linked advice, manual fixture changes and linked retest, not automatic deployment.

Planned additions: per-module records/progress, custom-case versions, report snapshots, finding review and retest links; capability flags and schema versions evolve with tests. Keep one user/worker/stack rather than adding SaaS/scaling infrastructure.

## Three-day sequence

1. Day 1: approved design, trustworthy Compose slice, persistence/recovery, explicit authorization, truthful capabilities, one complete module, APK and phone connectivity gate.
2. Day 2: remaining bounded modules and lab fixtures, module selection/progress, evidence and cancellation under shared limits.
3. Day 3: reports/remediation/retest, regression and clean startup, actual Android install/reconnect acceptance, final APK/source/demo and known limitations.

The Nov 23 target is tight after the design pause. A working APK build is not proof of Android device behavior or a complete app. Trusted phone-to-backend HTTPS, final device testing and other modules remain open. No paid hosting, public tunnel, iOS or Play Store release is assumed.
