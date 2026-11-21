# Internal-test readiness,21Nov2026

This is a bounded authorized-lab academic application with a React Native Android controller and separate backend. It is not a public/general-purpose vulnerability scanner or production release. A built APK requires the backend. Do not install it expecting standalone scanning.

## Proven layers

- Local219backend/19mobile regression tests, TypeScript and web export pass on the parameter-observation source. Test-first details live in each slice evidence file.
- Real local HTTP/UDP journeys cover scope/consent, reports, immutable custom versions, filters/manual linked retest, upload cancellation/cleanup and bounded DNS/parameter observations. Local journeys use SQLite/threads, not Docker/RQ.
- Focused merged PRs separately passed real Docker/Postgres/Redis/RQ/scanner/lab integration and APK compilation. Exact run links are in verification.md. PR28 exact-head Docker/APK gate passed before merge; device acceptance remains separate.
- Browser pixels were inspected for narrow consent/progress/findings/saved versions/review/filter views. No physical Android success follows from web pixels.

## Rehearsal on a clean machine, not yet signed off

1. Use Docker Engine/Desktop with Compose support, Python3.10 for host tests and Node22 for the pinned Expo toolchain. Clone the repository and check out the reviewed dev commit. Do not substitute main, which is preserved for release snapshots.
2. Copy .env.example to .env. Generate unique local DB and bearer secrets privately; never paste them into chat or commit them. URL-encode the password in DATABASE_URL. The CI helper infra/ci_env.py generates ephemeral credentials for CI, not a production secret-management system.
3. Run docker compose config --quiet, then docker compose up --build -d. Run python infra/smoke.py from the repository root. This is an active bounded lab test, not a read-only diagnostic. It intentionally creates demo scan/report/version data.
4. Inspect docker compose ps and bounded logs on failure. Keep volumes for diagnosis. docker compose down stops services; adding -v deliberately deletes demo history and is not recovery.
5. Stop the worker before operator recovery. Follow day1-evidence.md and upload-cleanup-evidence.md. Cleanup recovery requires scanner/lab availability, never reposts a marker and preserves partial/failed history. TTL expiry alone is not verified deletion.
6. Do not publish the supplied loopback API or data ports. A separate trusted HTTPS endpoint and phone routing plan must be agreed and tested before device acceptance. No paid host or tunnel is provisioned.

Fresh CI starts clean containers, but that does not establish successful setup on the user's own computer. Record the OS, runtime versions, reviewed SHA, commands, outcomes and any errors during handoff.

## Physical Android acceptance, all pending

- Confirm device/Android version and computer OS. Install the current internal-test APK with the user's permission. It is Android Debug signed, not production/Play Store signed.
- Verify reachable trusted HTTPS backend, token entry, failed connection recovery and readable auth errors. Phone localhost is the phone, not the computer.
- Confirm SecureStore persistence across cold launch; disconnect clears token/view. Web preview deliberately uses memory-only tokens.
- Select modules and opt-ins, edit/load a custom case, verify consent resets and explicit per-scan confirmation. Verify immutable retry/retest scopes.
- Run and cancel safely. Background/foreground and disconnect/reconnect must recover actual server state without duplicate scan traffic or invented counters. Do not assume a foreground web test covers Android process death.
- Open history/findings, filters, JSON/HTML exports and native share sheet; inspect saved file contents and cancellation behavior on device.
- Save/load two case versions, snapshot a filtered report and perform linked retest/manual review. Non-observation alone must not automatically mark fixed.
- Verify upload cleanup status on cancellation; unresolved cleanup must stay explicit and block only new uploads.
- Record screenshots/results per step. A failed or skipped step remains open. Never call this checklist completed from an APK compile.

## Residual risks and exclusions

One pre-provisioned bearer user, no production identity/rotation service, no complete distributed recovery scheduler, no immutable review event ledger and no guarantee against every egress/sandbox-escape route. Production TLS, backups/retention, access monitoring, rate-abuse controls and signing are separate work. Three moderate Expo-chain advisories remain on the last audit; no high/critical. Proposed automated fix was an incompatible Expo52downgrade and was not applied. A no-high/critical audit is not a security certificate.

No arbitrary hosts/URLs, credentials, imported wordlists/OpenAPI, real exploit/injection/RCE automation, public DNS follow-up, automatic fixes, paid deployment or Play Store release. Synthetic positive proofs must remain labelled as fixture proofs. Empty findings never establish target security.
