# Monday demo script (fallback-first)

Status 22 Nov 2026. This script is driven by verified CI evidence. It claims no physical-device success. Nothing is hosted: no server, tunnel or cloud service is used or expected. The optional phone segment is limited to what works without a backend.

## Ground rules for the presenter

- Say "lab" and "fixture". FuzzCore here is a bounded, authorized-lab academic build. It cannot scan user-supplied targets.
- Say "discoveries" and "signals". Never say "vulnerability found" for a finding. Fixture proofs are labelled as fixture proofs.
- Do not say the app is device-accepted. Say the APK builds, is signed for internal testing and needs a running backend.
- An empty result is not a security certificate.

## Segment 1: the problem and the design (2 min)

- Problem: a web application fuzzer with a mobile controller and a server-side engine.
- Architecture: React Native Android app controls scans. A separate backend (API, queue, worker, scanner) runs them against a fixed lab service on an internal Docker network. Show the architecture image from the design File.
- Guardrails: no target URL input anywhere, redirects and proxies off, internal-only DNS fixture, benign in-memory upload bytes, GET-only synthetic canary, per-scan explicit authorization confirmation. Evidence: docs/verification.md and the safety pass recorded in the design File.

## Segment 2: what each module does (3 min)

Walk the six surfaces using docs/verification.md and the evidence files in docs/:
1. Directories with randomized baseline controls (soft-404 handling).
2. Virtual hosts (control-host comparison, fixed destination).
3. API ownership checks plus curated inventory (two synthetic actors, vulnerable and secure counterparts).
4. Parameters (fixed marker requests, informational signals only).
5. Custom cases (one to three declarative GET or named POST cases, immutable saved versions).
6. DNS (three queries to the local fixture, wildcard control).
Opt-ins: synthetic file canary and benign upload with verified cleanup.

## Segment 3: proof it works, from CI (3 min)

Show on GitHub, not on a phone:
- Final dev CI run, all jobs green, including real Docker integration smoke and APK build: https://github.com/affan80/fuzzcore/actions/runs/44952735148
- Test counts: 219 backend and 19 mobile tests, TypeScript and web export. Each slice was test-first (failing regression recorded in its evidence file).
- Docker smoke (infra/smoke.py) in the CI log: runs the bounded lab scan plan and creates demo scan, report and saved-version data (see docs/readiness.md).
- Pull request history: focused PRs into dev, each gated on exact-head CI (PR numbers run to 31).
- Dependency gate: advisory cleared with a minimatch override, audit at 0, rejected the breaking Expo downgrade (PR30).

## Segment 4: reports and review (2 min)

- Printable HTML and JSON report with filters, immutable snapshots, visible scope, counters and cleanup status.
- Review flow: a finding is marked fixed only after an explicit note and a completed linked retest where its fingerprint is gone. Comparison alone never marks fixed.
- Use the report exports described in docs/report-retest-evidence.md and docs/report-filter-review-evidence.md. If screenshots are shown, use ones captured from the web preview and say so.

## Segment 5 (optional): the APK on a phone, no backend

Nothing is hosted, so there is no live scan from the phone. Do not imply one. Only if the presenter has already installed the APK and checked it on their own phone, show the installed app on screen and say it needs a backend to scan. A live scan needs a backend on a machine the presenter owns, which is not part of this plan. Otherwise skip this segment and say device acceptance is the next step.
- The APK is debug-signed and internal-test only.
- Do not start or promise a scan. Show results from the CI evidence and the report examples instead.
- No tokens, backend addresses or ports appear on screen.

## Segment 6: honest limits and next steps (1 min)

- Open gates: physical Android acceptance, a backend the phone can reach (none is planned or hosted), clean-machine rehearsal, production signing.
- Out of scope by design: arbitrary targets, exploit automation, public DNS follow-up, automatic fixes.
- Next: device acceptance on a real phone with a backend on a machine the owner provides.

## Questions to expect

- Can it scan any website? No. It only talks to its bundled lab service by design.
- Is it production ready? No. It is an internal-test academic build.
- Why no real exploits? The brief is discovery and reporting in an authorized lab. Findings are signals for a human to review.
