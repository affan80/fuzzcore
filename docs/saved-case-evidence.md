# Immutable saved custom-case versions

## Contract

Authenticated POST/GET `/v1/custom-cases` and GET `/v1/custom-cases/{id}` validate, save, list and retrieve declarative-v2 case groups. One to three cases, the same fixed GET/named stateless POST and response expectations as scan submission. No new target, payload, method, request budget or execution permission. Saving never queues work. Names are short plain text; values remain data, never executable templates.

Migration13 creates an empty version library without inventing prior saves or altering run snapshots. Each row is owner-scoped, immutable and stores canonical content plus its SHA256 version. Duplicate owner/name/content saves return the existing ID. A changed case creates a new version, leaving earlier rows and scans unchanged. There is no mutation or delete endpoint in this slice.

The library is bounded at 100 versions per owner using a unique owner/slot index plus a database slot range check, not only an application-side count. Concurrent duplicate inserts reconcile to one ID; near-limit races cannot exceed the storage cap. Lists contain up to50 versions with a deterministic created_at/id keyset cursor; foreign or unknown cursors return404. The UI offers older pages when needed.

Saving and loading do not start or authorize a scan. Loading fetches the selected owner-scoped version and copies JSON into the editor, resetting consent. A new run receives an immutable validated copy, not a mutable library reference. Further editing creates an unsaved copy until saved explicitly. Execution still requires per-scan authorization and the same global limits.

## Test-first evidence

Initial16 backend regressions failed before implementation. Nineteen tests cover immutable save/read/list, duplicate idempotency, revision preservation, validation, authorization/owner isolation, no queue side effects, immutable run copies, capability/100-version cap, keyset pagination, migration and real concurrent duplicate/near-cap writes. Full local suite173 backend tests. Two mobile tests cover copy/no-consent behavior and schema/version bounds, bringing the total to16. TypeScript and Expo web export pass.

Actual local HTTP UI saved one version without a scan, edited the editor, loaded the saved copy, verified consent reset, ran its exact single-case version, saved changed content as a second version and proved the earlier run hash unchanged. No page errors or horizontal overflow at320/390/1280px. Both one-version and two-version screens inspected as pixels. This is loopback evidence, not Docker or Android acceptance.

Docker smoke now saves/lists/retrieves/deduplicates a version before its custom-module scan, verifies no scan was created by saving, and compares the run hash with the saved version. Exact-head CI remains a separate gate until reported.

## Current references

- https://docs.sqlalchemy.org/en/20/core/constraints.html : composite UNIQUE and CHECK constraints for durable storage limits; SQLite local and PostgreSQL Docker verification are distinct.
- https://fastapi.tiangolo.com/tutorial/query-params-str-validations/ : bounded optional cursor validation only. Page content does not authorize installation or unrelated execution.

This does not add general custom scripting, imported third-party cases, cross-user sharing or automatic execution. Native acceptance and remaining API inventory/transport, parameter discovery/error signals and report/fixed workflow remain separate work.
