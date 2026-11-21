# Reports, review and linked retest

Reports are authenticated and owner-scoped. JSON and escaped printable HTML include immutable run scope/case version, counts, statuses, severity/confidence, evidence, review state, limitations and rule-linked remediation. Incomplete/cancelled runs remain partial. Empty results never state that a target is secure.

## API

- GET `/v1/scans/{id}/report.json`
- GET `/v1/scans/{id}/report.html`
- POST `/v1/scans/{id}/report-snapshots`, then GET `/v1/report-snapshots/{snapshot_id}`
- PATCH `/v1/scans/{id}/findings/{finding_id}/review` with state `open`, `acknowledged` or `retest_requested`, plus an optional note of at most 500 characters.
- POST `/v1/scans` may carry `retest_of` only with fresh explicit authorization, the original module selection and exact custom-case snapshot. The original must be terminal and owned by the user.
- GET `/v1/scans/{id}/retest-comparison` compares normalized module/path/rule fingerprints of a terminal linked retest.

Live reports reflect current review state. Saved snapshots keep the exact serialized report from creation, even after review changes. No endpoint edits or deletes a snapshot. Migration8 adds review fields and snapshots; migration9 adds retest links. Previous history is preserved.

## Honest review and comparison

There is no automatic fixed state. Review actions do not deploy a fix or alter old evidence. Retest returns still-observed, newly-observed and not-observed fingerprints with a partial flag. Not-observed does not prove remediation, especially for partial/error runs. A person must review matching scope and evidence. Fixture changes remain manual.

Every report string is rendered as escaped text. HTML has a restrictive content-security policy, no scripts/forms/external resources, no target-derived links and no raw HTML insertion. User/fixture text cannot become HTML markup. JSON keeps original text as data. Tokens and infrastructure secrets are not included.

## Mobile export

The app downloads authenticated JSON/HTML. Web exports use local blob downloads. Native exports write a private cache file and open the platform share sheet using current Expo filesystem/sharing APIs; the temporary file is deleted after sharing completes. No bearer token is placed in a URL. Native behavior remains unverified until actual Android installation.

The report tab also saves a snapshot, updates review state and starts a same-scope retest after fresh consent. History and the original run remain available. Sharing to another person is a deliberate user action in the platform sheet, not an automatic background disclosure.

## Test-first evidence

Five report regressions and two retest regressions failed before implementation. Full local suite:87 backend tests,7 mobile-policy tests, TypeScript and web export pass. Actual loopback UI tests download and parse JSON/HTML, verify totals/review, save a snapshot, perform a fresh-consent linked retest and view comparison. The printable HTML and mobile controls were rendered and visually inspected. These tests use local HTTP/UDP with SQLite/threads, not Docker/RQ/native Android.

The Docker smoke adds authenticated export, snapshot immutability after review, and a linked directory-only retest after the maximum25-check fixture run. Fresh Docker/APK CI is required before merge.

## Dependency check

Adding Expo filesystem/sharing used Expo's compatible-version resolver and updated the lockfile/plugin. npm audit reports3 moderate advisories through Expo fingerprint/minimatch, no high/critical. The automatic suggestion is an Expo major-version downgrade, so no blind fix was applied. Source: https://github.com/advisories/GHSA-g3hv-75wg-m249 . A compatible tested resolution remains open.

## Sources

- https://docs.python.org/3/library/html.html
- https://fastapi.tiangolo.com/advanced/custom-response/
- https://docs.expo.dev/versions/latest/sdk/filesystem/
- https://docs.expo.dev/versions/latest/sdk/sharing/

Still unfinished: report filtering and richer remediation workflow, declared fixed/retest acceptance state, module-specific progress, broader directory/API/parameter fixture scenarios, physical Android acceptance and trusted phone HTTPS. This slice is not full-app completion.
