# API fixture ownership checks

This module tests a synthetic two-actor fixture. It does not test real user credentials, discover arbitrary API routes, or generalize its result to a third-party application.

## Six read-only cases

1. Missing fixture route returns 404.
2. Anonymous read of Alice's known object returns 401.
3. Alice reads her own object, with the expected fixture marker and owner/object identity.
4. Alice is denied access to Bob's secure object, with 403.
5. Bob reads his own deliberately vulnerable fixture object.
6. Alice reads that same Bob-owned vulnerable object.

A high-severity, fixture-confirmed result is emitted only when every control has its expected outcome, both Bob-object responses identify the known Bob-owned object, and both carry the synthetic fixture marker. A login page, redirect, missing marker, owner mismatch or failed control does not establish the rule. The secure counterpart fixture produces no finding.

The actor header is a deliberate fixture switch, not production authentication. No real bearer token is sent from the control API to the scanner or fixture. The scanner accepts only the six named cases, builds fixed GET requests to the existing lab destination, follows no redirects, and disables environment proxies.

## Evidence and limits

Bodies are processed within a 16 KiB cap and discarded. Only allowlisted fixture owner/object labels, status, length and SHA-256 survive normalization. Unexpected JSON, HTML and extra fields are not stored as raw evidence. All probes share the scan's request counter, 300-second deadline and cancellation checkpoints. Failed network attempts count toward the total. No automatic replay of terminal work is introduced.

Request plans are four for directories, three for virtual hosts, six for API, or thirteen for all three. Capabilities and mobile selection expose only implemented modules. Per-scan explicit authorization remains required, and an existing idempotency key cannot silently change its module snapshot.

## Test-first evidence

Ten API regressions failed before implementation, then passed. A later failing regression proved failed network attempts were not counted; the counter now increments before the request. The full local backend suite passes 53 tests. Four mobile-policy tests, TypeScript and web export pass. A real loopback UI run completed thirteen requests with three resource discoveries, one host discovery and one scoped fixture ownership finding. These are SQLite/threads tests, not Docker/RQ or Android acceptance.

Migration v6 adds persisted severity/confidence with informational/observed defaults for old findings. Existing history is preserved. The Docker smoke adds an all-three-module fixture run and checks the ownership rule's severity/confidence. Its fresh CI result is required before claiming container integration for this slice.

## Remediation

Enforce authenticated object ownership server-side for every object access. Return a denied response for cross-owner reads. The secure fixture counterpart demonstrates the expected behavior. This module supplies advice and tests, not automatic edits or deployment to a real service.

## Current sources used

- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- https://fastapi.tiangolo.com/tutorial/security/
- https://www.python-httpx.org/quickstart/

Still unfinished: arbitrary-scope authorization, broader API endpoint inventories, transmission policy assessment beyond the fixed local lab, parameter/injection signals, reports and linked retest. No complete API security assessment is claimed.
