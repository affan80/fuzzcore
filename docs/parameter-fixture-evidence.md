# Parameter fixture observations

The parameter module sends six bounded GET requests to one fixed lab endpoint. It uses no script, SQL, command, credential or destructive payloads.

## Cases and classification

The six cases are no query value, two separate harmless marker values, both values with the same parameter name, a marker containing quote characters, and a marker containing a space, plus and ampersand through the HTTP client's parameter encoder.

A reflection signal requires the correct response to every marker, including quoted/encoded variants, and no marker in the baseline. A duplicate-parameter signal requires each single-marker response to match and the duplicate response to retain both known values. These are informational signals, not confirmed XSS, SQL injection, authorization bypass, parser mismatch or code execution. JSON reflection by itself is normal behavior.

The secure fixture counterpart rejects duplicate values and does not echo markers. It produces no signals. Static marker responses, HTML login pages and redirects also produce no signals. The scanner never follows redirects.

## Boundaries

Only six named cases are accepted by the scanner gateway. The destination remains the bundled lab service. Response processing has a 16 KiB limit; raw bodies and arbitrary JSON fields are discarded. Persisted evidence consists of control statuses, hashes, lengths and comparisons against the application's own known markers. No target-supplied evidence text is retained.

Four modules together plan nineteen total requests under the existing shared counter, deadline, rate limit and cancellation checkpoints. A parameter-only run plans six requests. No new database fields or migration are needed. Per-scan explicit authorization and idempotency scope protection remain in place. Module-specific progress is still unfinished.

## Test-first evidence

Five new backend regressions and one mobile-policy regression failed before implementation. The local full suite passes 58 backend tests and five mobile-policy tests, plus TypeScript and web export. Real loopback tests cover positive and secure counterparts; a web UI integration completed nineteen requests and displayed seven findings/signals across the four current surfaces. UI pixels were inspected at mobile widths. These tests use SQLite/threads, not Docker/RQ/native Android.

Fresh Docker integration adds the nineteen-request combined run. Its new CI and APK compile must pass before merge. Actual Android installation, SecureStore/reconnect and phone HTTPS remain unverified.

## Remediation guidance

Treat all client input as untrusted. Apply context-appropriate output encoding where values enter HTML or other executable contexts. Use typed validation and parameterized database queries. Where one parameter value is expected, reject duplicates and ensure every layer validates and uses the same parsed value. These are advice, not automatically deployed fixes.

## Current sources

- https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/03-HTTP_Parameter_Pollution/
- https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/01-Reflected_Cross_Site_Scripting/
- https://docs.python.org/3/library/urllib.parse.html
- https://www.python-httpx.org/quickstart/
