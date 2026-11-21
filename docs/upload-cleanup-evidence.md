# Fixed benign upload and truthful cleanup

## Scope and request accounting

`upload-v1` is a separate immutable opt-in under directories, off by default. Changing either optional directory case resets mobile consent without erasing the other selection. No arbitrary files, extensions, URLs, executable bytes, host paths or commands are accepted.

The fixture accepts only the exact hard-coded harmless marker under a scan-derived 32-hex object identifier. It keeps only bounded in-memory state (maximum 64 objects), never opens or writes a filesystem, and refuses replacement of an existing identifier. Per-object 300-second expiry and read-time expiry checks are fallbacks. Timer callbacks cannot delete a newer value for the same identifier. Expiry is not proof of cleanup.

The explicit case reserves six attempts: POST create, GET known-marker read, DELETE, GET absence verification, plus two cleanup recovery reserves. A normal case uses four. Defaults remain 4 directory / 25 maximum full-run attempts. Canary-only remains 7 directory / 28 full-run attempts. Both options reserve 13 directory / 34 full-run attempts; normal maximum full-run execution uses 32 and displays 2 unused cleanup reserves, never 34 returned responses. Requests remain serialized and rate-limited. No redirects are followed; bodies are capped at 16KiB and only signatures/booleans retained.

## Cancellation, failures and recovery

Before POST, the database commits `cleanup_status=pending`. The identifier is deterministic from the immutable scan ID, so a lost create response does not lose the cleanup destination. No unrelated destination can be supplied.

Routine requests honor cancellation and the 300-second scan deadline. Once a create may have happened, the reserved DELETE/absence verification pair still runs, with attempts persisted before each request. HTTP 404 on the final verification is required for `verified_absent`. Unknown responses or other statuses remain `unverified`; they never turn into a completed clean run. The report remains partial on cancellation, timeout or failure, even after successful cleanup. A roundtrip observation is informational, not evidence of an insecure-upload vulnerability.

The normal cleanup pair does not silently retry. With the worker stopped, operator recovery may use the remaining reserved DELETE/GET pair, never POST or repeat the ordinary probes:

```
docker compose stop worker
docker compose run --rm worker python -m fuzzcore.recovery --worker-stopped --cleanup-uploads
docker compose up -d worker
```

Recovery preserves the terminal failure/interruption and its error. No more than four cleanup attempts or 34 overall attempts are allowed. If the budget is exhausted, the explicit unresolved state remains for operator review. New upload runs are blocked while this owner has unresolved cleanup, but read-only runs remain available. The fixture TTL limits residue if both worker and recovery are unavailable, without claiming externally verified deletion. Recovery requires the scanner and lab to be running. Scanner still has no DB/Redis/token credentials and cannot access the data network.

## Test-first and integration evidence

- Initial 10 backend tests failed on absent upload behavior; 10 passed after implementation. Two further safety regressions failed before adding production gateway wiring and unresolved-cleanup gating.
- Sixteen upload tests cover immutable budgets, maximum plan, exact-scope retest, ordinary defaults, expiry, wrong input, gateway ID/action validation, body limits, real HTTP roundtrip, lost create response, cancellation, timeout, unknown delete, failed verification, bounded stop-worker cleanup recovery, no repost, migration, and network-separated production wiring.
- Full suite: 154 backend tests, 14 mobile tests. Two new mobile regressions failed first. TypeScript and Expo web export pass.
- Actual local HTTP/UDP UI, with all six modules and one custom case: 30 of 32 reserved requests, 11 observations, cleanup verified absent with 2 cleanup attempts. Same-scope retest kept 11 observations. Cancellation during the upload stage ended cancelled/partial with 7 counted requests and verified cleanup. No page errors, no horizontal overflow at 320/390/1280px. Scope, counters and informational evidence pixels inspected.
- Docker smoke now checks both options at maximum custom scope: 32 of 34 requests, 13 observations, verified cleanup, honest unused reserves, matching exports/snapshot. This is pending exact-head CI until recorded separately; local loopback is not a Docker or native-device result.

## Current official references

- https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html : allowlisted content, generated identifiers, size limits, non-execution, storage separation and least privilege. The fixture is deliberately narrower than a production file-upload service and does not claim complete upload security.
- https://docs.python.org/3/library/threading.html : Timer cancellation only works before execution, so callback identity/expiry checks are required. Timer scheduling is not an exact deletion guarantee.
- https://www.python-httpx.org/advanced/timeouts/ : bounded client timeouts. Unknown network outcomes require cleanup tracking, not a success assumption.

Native device installation, SecureStore, native sharing, background transitions, trusted HTTPS and dependency acceptance remain separate gates. No paid deployment, production signing, host-file access or execution is included.
