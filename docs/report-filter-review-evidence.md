# Filtered exports and explicit manual fixed review

## Consistent filters

Findings, JSON reports, escaped printable HTML and immutable report snapshots share validated severity/module/confidence/review-state filters. Report totals always count the filtered findings; unfiltered count and the exact active filter map are retained in JSON/HTML/snapshots. Empty or partial results never imply security. Filters cannot change scope, counters, raw evidence or the full stored results. Invalid filter values fail422. Owner checks still apply before matching.

The React Native report view cycles each named filter with an explicit all state and offers clear filters. The same selected filter map is used by both export buttons and new snapshots. Stored snapshots stay unchanged after review changes.

## Manual fixed review

Comparison still never auto-fixes anything. A developer first changes the isolated fixture manually, then submits a fresh-authorized, identical-scope linked retest. The original finding may be marked fixed only by an explicit manual review PATCH with a non-empty note and supporting retest ID. The backend requires the same owner, a completed linked run, matching target/scope/module/custom/directory snapshots, no unresolved cleanup and no matching module/path/rule fingerprint in the retest.

Still-observed, partial, cancelled, unrelated, foreign, changed-snapshot and unverified-cleanup retests are rejected. Review preserves the original severity/confidence/evidence. Fixed is a manual workflow label, not proof of a source-code edit, a deployed fix or target security. Reopening clears the supporting review link. Migration14 adds optional review time/retest fields without inventing historic evidence. This slice records the current review, not an immutable review event ledger.

The UI requires the operator's manual note and ID, then a separate button on the chosen finding. It displays the saved review note, time and retest. No source editing, deployment or fix is performed by the app.

## Evidence

Eight initial backend regressions failed before implementation. Ten new report/filter tests now cover matching totals across formats and snapshots, invalid filters, empty/full views, fixed requirements, still-observed/partial/unrelated/foreign runs, changed snapshots, unresolved cleanup, owner isolation and migration. Full local suite183 backend /18 mobile. Two new mobile checks first failed on absent helper. TypeScript and web export pass.

Actual HTTP UI found the deliberately seeded API issue, exported a high-only report, saved a snapshot, then the test operator manually switched the local fixture to secure ownership checks. A completed same-scope retest did not observe the fingerprint; the original remained open until the explicit note/ID/finding button. Fixed review preserved high/fixture-confirmed original evidence and exported the supporting retest ID. First UI pass caught missing linked ID in printable HTML; rendering and regression coverage were fixed before a successful rerun. No page errors or horizontal overflow at320/390/1280px. Narrow manual-review and filtered-report pixels inspected.

Docker smoke verifies filtered13-total/1-high-API exports and owner-scoped matching results, with the existing real end-to-end path. Exact-head Docker/APK CI and physical Android remain separate gates until recorded. Current escaped HTML/response guidance already used by the report layer applies; no new external tooling was installed.
