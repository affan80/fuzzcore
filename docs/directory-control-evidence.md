# Directory response controls

Production directory discovery now uses status, processed length and SHA256 signatures rather than status-only checks. The scanner requests a freshly randomized missing path first, then the three fixed approved resources. It still makes exactly four target requests. HTTP destination remains the pinned fixture; no request-provided URL is accepted. Random controls use a fixed path prefix and generated hex suffix.

Each response is processed with a 16 KiB cap, identity encoding, no redirects and no raw body retention. A 2xx resource is a discovery only if its status/length/hash signature differs from the missing-path control. Identical soft-404 responses are filtered. This is exact response-signature comparison, not a universal soft-404 detector: noisy or dynamic pages need additional controls and review.

A missing control never confirms a candidate. Redirecting or failing controls fail the run and keep its report partial, rather than producing a misleading clean result. Candidate redirects are not discoveries. Known controls and candidates are recorded as signature evidence with a rule ID and a specific exposure/authentication recommendation. Resource existence is not a vulnerability.

The production worker uses the signature gateway explicitly; it cannot silently fall back to the legacy status-only helper. That old helper remains for compatibility with foundation tests and the old read-only gateway path, not the production scan dispatch. Controls run first so a cancelled or failed baseline does not publish unvalidated resource observations. Request progress still means returned responses, separately from assessment state.

## Test-first evidence

Six initial backend regressions failed before the module existed. Two additional baseline-failure tests failed before their fix; the production-dispatch/order regression failed before moving the random control first. A final rate-limit regression failed before moving the shared stop check ahead of baseline analysis. Ten added tests now pass. Full local suite:124 backend tests,11 mobile tests, TypeScript and web export pass.

Tests cover signature/wildcard filtering, redirects, unavailable controls, body bounds, path rejection, randomized pinned requests, redaction, production gateway dispatch, and real positive/soft-404 local fixtures. A real HTTP/UDP web UI run completed all six modules with23 checks and 9 results, downloaded matching baseline evidence, saved a snapshot, reviewed a result, ran a linked retest and cancelled a later run. The mobile discovery/remediation pixels were inspected. No page errors. This is SQLite/threads and local web evidence, not Docker/RQ or physical Android.

The Docker smoke now asserts directory-control rule IDs and baseline status before continuing its unchanged maximum 25-check run. Exact-head Docker/APK CI is still required before merge. Native acceptance remains separate.

Current implementation reference checked: https://www.python-httpx.org/quickstart/ for streaming responses. Traversal canaries and benign upload/cleanup scenarios are not part of this slice. They require their own explicit cases, budget and cleanup accounting. No host file access, upload execution or arbitrary target scanning is added.
