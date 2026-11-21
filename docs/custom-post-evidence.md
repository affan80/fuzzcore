# Named disposable custom POST and header checks

The declarative schema now supports GET on the three existing paths, plus POST only on `/custom-disposable`. That named fixture accepts exactly one `body.marker` containing1-64 harmless ASCII letters, digits, spaces, underscores or hyphens. POST cannot carry query parameters. GET cannot carry a body. No request headers, arbitrary methods, absolute URLs, code, files, templates, credentials or external wordlists are accepted.

The disposable fixture is stateless. It validates a small JSON body and returns a fixed acknowledgement. It writes no file or database record and retains no marker, so it creates nothing needing cleanup. It is not an upload scenario, exploit or third-party POST capability. The existing isolation, per-scan consent, single-flight lock, response-size cap, timeouts, no-redirect policy and shared25-check budget still apply.

`expect_headers` may contain only `content-type` and `x-fixture-mode`, with short printable literal values. Matching is exact, not a regular expression. Missing/mismatched headers, wrong status/text or redirects do not pass. Evidence records expected values and match booleans, not arbitrary received headers, cookies or raw bodies. Results stay informational pass/mismatch observations, never vulnerability proof.

Canonicalization omits absent new fields. Every old GET canonical JSON snapshot and SHA256 version therefore stays identical. New POST/header cases get their own immutable hash. Retests still require the identical case snapshot and fresh consent. Capabilities advertise declarative-v2 and its exact method/path/header/body limits.

The mobile editor describes the constraints and includes a disposable POST example. Loading that example resets consent. It remains disabled during an active run or pending idempotent start. Choosing the example does not start a request.

## Test-first evidence

Six new backend checks failed before implementation and a seventh capability regression failed before its addition. Eighteen new backend checks now cover compatibility, safe POST, headers, redirects, schema rejection and a real local fixture. Full local suite:114backend tests,11mobile tests, TypeScript and web export pass. The new mobile example regression failed before implementation.

A real local HTTP/UDP UI run selected the POST example, verified consent reset, completed all six modules with23 checks/9results, downloaded JSON/HTML with matching POST/header evidence, saved an immutable snapshot, reviewed evidence, ran a linked same-scope retest and cancelled another run. No page errors. Editor and resulting progress/report pixels were inspected. These are local SQLite/threaded and web checks, not native-device or Docker evidence.

The Docker smoke now includes the named POST/header case in the existing maximum25-check plan without increasing its request budget. Exact-head CI including Docker/Postgres/Redis/RQ and APK compilation is required before merge. Physical Android/SecureStore/sharing/background/HTTPS acceptance remains separate.

Current official source checked for JSON request bodies and streaming responses: https://www.python-httpx.org/quickstart/ . Broader custom-case storage/listing, directory upload cleanup and broader module scenarios remain unfinished.
