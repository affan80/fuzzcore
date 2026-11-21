# Declarative custom fixture cases

Custom cases are JSON data, never executable code or templates. A custom scan requires one to three cases, and cases cannot accompany a scan without the custom module selected.

## Supported schema

```json
[{"path":"/health","method":"GET","params":{},"expect_status":200,"contains":"fixture"}]
```

- `path`: exactly `/health`, `/api/status` or `/custom-fixture`.
- `method`: GET only. Disposable POST scenarios remain unimplemented.
- `params`: empty or one `q` marker of at most 64 letters, digits, spaces, underscores or hyphens.
- `expect_status`: 200 or 404.
- `contains`: optional literal text of at most 64 characters. No regular expressions, shell, evaluation, interpolation or file reads.
- Unknown fields fail validation. Absolute URLs, traversal, arbitrary headers, scripts in parameters, unsupported methods and oversized inputs are rejected before queueing and again at the scanner boundary.

The existing target ID is still fixed and authorization is explicit. A case cannot alter the origin, port, DNS destination or scanner network. All response processing is bounded to 16 KiB, raw response bodies are discarded, redirects are not followed and proxy inheritance is disabled.

## Immutable versions and results

Validated cases are serialized canonically and hashed with SHA-256. The exact normalized JSON and version are stored on the scan. A retry with the same idempotency key cannot change cases or selected modules. Migration v7 adds these fields with empty/null defaults for older history.

Each case costs one request. Up to three cases share the scan's existing deadline, cancellation checkpoints, rate limit and request counter, with at most twenty-two requests across all five current modules. Mismatch is an informational review signal, not a vulnerability. A matching expectation is an observed result, not a security certificate. Findings include status/length/hash, comparison booleans and the immutable case version, not response content.

## Test-first evidence

Fourteen backend cases and one mobile-policy case failed before implementation. Local full suite: 74 backend tests, six mobile-policy tests, TypeScript and web export pass. Real loopback tests cover passing and mismatching expectations, immutable scope and strict schema rejection. An actual loopback UI run completed twenty requests with eight results across the current modules and verified consent reset/history. Pixels were inspected. These tests use SQLite/threads, not Docker/RQ/native Android.

The new Docker smoke runs the maximum twenty-two-request plan with two passing expectations and one intentional mismatch. Fresh Docker/APK CI must pass before merge. Physical Android installation, secure storage, reconnect and trusted phone HTTPS remain separate gates.

## Current sources

- https://docs.pydantic.dev/latest/concepts/fields/
- https://docs.pydantic.dev/latest/concepts/validators/
- https://www.python-httpx.org/quickstart/

Still unfinished: approved disposable POST checks, header expectations, saved reusable case library, per-module progress, reports and linked retest. No arbitrary custom execution is supported.
