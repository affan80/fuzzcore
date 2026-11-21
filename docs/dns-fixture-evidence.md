# Local DNS fixture discovery

Three DNS A queries go to a bundled non-recursive UDP fixture: the fixed suffix baseline, a newly randomized missing label, and the seeded `app.lab.invalid` name. The fixture never forwards queries upstream. Production resolves only the fixed Docker service name `dns-lab`, then sends its bounded queries to that address/port. Candidate names never go to a public resolver.

The result is an informational discovery. A seeded record is accepted only with the expected synthetic name/address and successful negative controls. Matching wildcard responses are filtered. Resolving a name does not authorize an HTTP scan, prove ownership, show a takeover, or show a vulnerability. The module has no HTTP follow-up or registration behavior.

## Isolation and limits

The DNS container is attached only to the internal lab network, runs non-root with dropped capabilities, has a read-only root, and publishes no ports. It has no DB, Redis, API token or host mount. Its UDP parser accepts at most 512-byte single A/IN questions for the fixture suffix. The scanner stays on control/lab networks with no data credentials.

Each query has a two-second timeout, no recursive resolver use, no retries or TCP fallback. The three checks share the run's deadline, cancellation checkpoints, rate and request counter. Maximum plan for all six current modules with three custom cases is twenty-five checks. DNS failure becomes a safe failed run or produces no discovery, never fabricated evidence. Findings keep names, normalized A records and control outcomes.

## Test-first evidence

Five backend regressions and one mobile-policy regression failed before implementation. The local full suite passes 79 backend tests and seven mobile-policy tests, plus TypeScript and web export. Real local UDP tests cover seeded and wildcard fixtures. An actual loopback UI run completed twenty-three checks with one custom case, nine results and no observed page errors; pixels were inspected. This uses local UDP/HTTP plus SQLite/threads, not Docker/RQ/native Android.

The new Docker smoke adds a maximum twenty-five-check plan and verifies the one expected DNS discovery, alongside prior network/data-credential checks. Its fresh CI and APK compile must pass before merge. No native-device/HTTPS success is claimed.

## Dependency choice

The current PyPI dnspython 2.9.2 release requires Python 3.11 or newer. This project pins Python 3.10. dnspython 2.8.0 is the latest installable compatible release and is pinned explicitly; no silent runtime upgrade was made.

## Sources checked

- https://dnspython.readthedocs.io/en/stable/query.html
- https://dnspython.readthedocs.io/en/stable/message-make.html
- https://pypi.org/pypi/dnspython/json
- https://pypi.org/pypi/dnspython/2.8.0/json

Still unfinished: candidate import/custom suffixes, CNAME/IPv6 observations, per-module progress, broader report/retest acceptance. Only the bounded local fixture is supported.
