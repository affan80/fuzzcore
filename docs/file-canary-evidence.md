# Opt-in synthetic file canary

This is a controlled symbolic lab scenario, not arbitrary file inclusion or host-file testing. The fixture maps three fixed names to in-memory responses. It never opens, resolves or includes any file. There are no user-provided paths, remote includes, shell payloads or execution.

`directory_cases: ["canary-v1"]` adds exactly three GET requests: a public positive control, an always-denied out-of-scope control and the known synthetic canary. The scanner accepts only those case IDs and keeps its destination pinned to the same lab. Responses have the same 16 KiB cap, no redirects and no raw-body retention. The proof requires exact known marker matches, the public control and the denied control. The secure fixture counterpart returns no canary finding.

Only this seeded simulation receives medium / fixture-confirmed classification, with a rule ID, case version, control signatures and a specific allowlist/containment recommendation. It does not prove that an external system is vulnerable. The UI says no host files were read or included. A missing or mismatched control cannot confirm the issue. No fix is applied automatically.

## Immutable opt-in scope

The default is off in the app and absent in old requests. Enabling it resets consent. Migration11 adds an empty selection for old rows, never extra work. Default directory runs remain four requests and the old full plan remains 25. Explicit canary selection makes directory runs seven requests and the maximum full plan 28. Attempted requests are still counted individually under the same rate, deadline, concurrency and cancellation limits.

Selection is persisted, checked on idempotent retry and required unchanged for a linked retest. Unsupported, duplicate or non-directory selections are rejected before queueing; the worker also rejects an unknown persisted selection before traffic. Reports, snapshots and history carry the selection. An old queued scan cannot silently expand after an upgrade.

## Test-first evidence

Seven initial backend cases failed before implementation, and a further worker-scope regression failed before its fix. Fourteen new cases now pass, including migration/no-expansion, default/opt-in maximum budgets, schema rejection, pinned requests, body bounds, control comparisons, positive/secure real HTTP fixtures, cancellation and retest scope. Full local suite:138 backend tests. One new mobile guard test failed before implementation; all 12 mobile tests, TypeScript and web export pass.

Actual local HTTP/UDP UI selected the case, verified off-by-default and consent reset, completed all six modules with 26 checks and 10 results, exported matching scope/proof, saved an immutable snapshot, reviewed a result and ran a same-scope linked retest. Another run cancelled without completing later modules. Narrow and desktop overflow checks passed; canary/remediation pixels were inspected. This is SQLite/threads and web evidence, not physical Android or Docker/RQ.

Docker smoke now requests the maximum 28-check opt-in plan and expects 12 results, with the new signature-only control proof. The earlier default four-request smoke is unchanged; a separate API regression verifies the old default maximum stays25. Fresh exact-head Docker/APK CI is required before merge. Native installation, SecureStore, background/reconnect, file sharing and trusted HTTPS remain separate.

Current remediation reference checked: https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html . Benign upload/cleanup is not implemented by this slice and requires its own explicit immutable case selection and request accounting.
