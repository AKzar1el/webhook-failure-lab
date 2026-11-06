# Webhook Failure Lab ? development rules

- Product: local-first webhook failure simulation and observable side-effect verification, not a general production webhook forwarder.
- Run `npm run verify` (12 baseline tests and four end-to-end smoke scenarios at v0.1.0); add regression coverage for changes.
- Never access non-loopback destinations, real customer payloads, paid APIs or production credentials.
- Follow `docs/REVENUE_SHOT.md`; one bounded source improvement per wake, resume meaningful unfinished work, preserve writers' changes.
- Branch naming: `revshot/<task>`; after local tests and reviewed changed files, submit only CI-green, non-draft PRs with an exact `MERGER_HANDOFF: AKzar1el/webhook-failure-lab@<SHA>` marker in the PR body.
- The guarded merger owns integration; never bypass review/CI or mutate workflow/package/release config without separate manual approval.
- Keep `secrets.txt`, `.env*`, `.revenue-shot/` and private journals out of Git. Use the Windows credential store rather than copying secrets.
