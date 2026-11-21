# Bounded DNS response checks

The same three fixed lab DNS questions now explicitly clear recursion-desired. The bundled UDP server never forwards queries. The scanner rejects mismatched question/response envelopes and truncated replies without TCP fallback, retries, extra names or HTTP follow-up. Only IN/A answers for the exact requested name can become records. Any CNAME in the answer suppresses A-record discovery; its target is not retained or followed.

Each successful response adds five bounded metadata fields: authoritative, recursion_available, truncated, alias_observed and isolated_fixture_only scope. These are observations, not vulnerabilities. The bundled fixture currently reports authoritative=false and recursion_available=false; no unsupported inference about real DNS service safety is made. Invalid responses fail the run with the attempt counted, never a fabricated empty successful response.

## Test-first and integration evidence

Five new regressions failed before implementation: recursion flag/metadata, truncated/wrong-question/wrong-class envelopes, and CNAME plus injected A. Eight new checks pass, including real local UDP metadata, recursion-available observation without follow-up, and safe failed-run counting. Full local suite205backend/19mobile; TypeScript and web export pass. No mobile UI layout changes. Docker smoke requires exact stored seeded DNS metadata in addition to the unchanged maximum38reserved/36used all-options plan. Fresh exact-head Docker/APK CI remains required before merge. Native device acceptance remains separate.

## Sources checked

- https://dnspython.readthedocs.io/en/stable/message-class.html
- https://dnspython.readthedocs.io/en/stable/message-flags.html

No DNSSEC validation, recursion exposure test, takeover detection, arbitrary suffix import, recursive/public DNS query, alias resolution or external target has been added. Existing stored scans keep their original evidence.
