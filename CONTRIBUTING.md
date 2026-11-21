# Contributing to FuzzCore

## Branch and pull request flow

- `dev` is the integration and default branch. Start every feature, fix, test or documentation branch from the latest `dev`.
- Use short branch names such as `feat/scan-history`, `fix/cancel-state`, `test/lab-boundary` or `docs/setup`.
- Open contribution pull requests with **base: dev**. Check the base explicitly before submission. Do not open contribution PRs against `main` and do not push routine work directly to `dev` or `main`.
- `main` is reserved for maintainer-controlled release snapshots after verification of `dev`. Release promotion is separate from the contribution PR flow.
- Link the relevant issue and keep each PR focused. Use draft PRs while checks or implementation are incomplete.

## Local setup and checks

The source uses the normal `apps/`, `services/`, `infra/` and `docs/` tree. Do not commit dependency folders, build outputs or encoded copies of the source.

Before requesting review:

1. Run backend tests: `PYTHONPATH=services/api pytest services/api/tests -q` after installing the pinned requirements in a virtual environment.
2. Run mobile checks from `apps/mobile`: `npm ci`, `node --experimental-strip-types --test tests/*.test.mjs`, `npx tsc --noEmit`, and `npx expo export --platform web`.
3. For container changes, run the isolated fixture smoke test and document the actual environment/results. For native changes, compile and install the APK on Android and report what you tested.
4. Write a failing regression test for changed behavior, make it pass, then review the diff. Do not claim tests, device checks or builds ran when they did not.

## PR checklist

- [ ] Base branch is `dev`.
- [ ] Linked issue, purpose and changes are clear.
- [ ] Scope is small and the diff contains no unrelated generated files.
- [ ] Relevant checks passed; missing checks and known limitations are listed.
- [ ] UI changes include screenshots labelled web preview or native device accurately.
- [ ] No credentials, `.env`, database files, APK signing keys, dependencies or private target data are included.
- [ ] Security-sensitive changes preserve the target boundary, budgets, cancellation and ownership checks.

## Security and test ethics

Use only the bundled isolated lab or explicitly authorized targets within written scope. Do not add arbitrary command execution, destructive probes, credential attacks or external scanning to CI. Findings must distinguish discoveries, unconfirmed signals and verified vulnerabilities. Keep evidence minimal and redact secrets.

Do not disclose live credentials or private target details in public issues. Report security concerns privately to the repository owner through an established private channel; do not assume a private vulnerability-reporting feature is enabled.

## Review and merge

Resolve review comments, rerun affected checks and keep evidence with the PR. Maintainers decide when a PR is ready to merge into `dev`. Branch protection and required checks, if configured in repository settings, are separate from this guide. Default-branch selection alone does not prevent someone from manually targeting `main`.
