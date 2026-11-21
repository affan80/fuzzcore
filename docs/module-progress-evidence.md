# Durable per-module progress

Each new scan persists a progress object for exactly its selected modules. Every module has state, planned, attempted and completed counters. Attempted is incremented and committed before a request. Completed is incremented with the stored response/results after a probe returns. A failed in-flight request can therefore have attempted greater than completed. Completed responses are not successful security tests or proof of safety.

States are queued, running, completed, failed, cancelled, timed_out, interrupted and not_run. Cancellation, timeout and failure preserve earlier completed modules and mark later unstarted modules not_run. A final 429 response marks its module failed even when all planned responses returned. Operator-only stale-worker recovery marks an active module interrupted. No job is automatically replayed. Queued cancellation sends no requests.

Migration10 adds the non-null JSON text with an empty default. It never infers fine-grained history from old aggregate counters. Historic records return progress_available=false and an empty object; the app says detailed progress is unavailable. A legacy unattempted queued job starts tracking only after an atomic claim. Existing authorization checks still decide whether it can be dispatched.

The API scan detail, history and reports expose the same durable object. Saved report snapshots remain immutable. Mobile shows separate response-completed and request-attempted counts for each module and labels the limitation. Existing active-screen polling remains bounded, pauses in background and stops on terminal state. No ETA is invented.

## Test-first evidence

Eight new backend cases failed before implementation; an additional final-response rate-limit regression failed before its fix. Three mobile formatting checks failed initially because the new module did not exist. Full local suite:96 backend tests,10 mobile tests, TypeScript and web export pass.

Real local HTTP/UDP fixture UI testing completed all six modules with23 checks and9 results, watched running/completed counters, verified exported report progress, saved snapshots and ran a linked retest. Another run cancelled after one directory request and showed later modules not_run. Screenshots at390px and1280px were inspected; the existing320/390/1280 layout overflow checks pass. This is SQLite/threads and web UI evidence, not Docker/RQ or physical Android.

The Docker smoke asserts all six stored module counters match the full25-check plan. Exact-head CI, including real Docker/Postgres/Redis/RQ and APK compilation, is required before merge. Native installation/background/SecureStore/HTTPS acceptance remains separate.

Source checked: https://docs.sqlalchemy.org/en/20/orm/session_basics.html . Separate short-lived sessions and commits own the durable request/response checkpoints; a Session is never shared between concurrent worker/API threads.
