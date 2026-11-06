# Webhook Failure Lab — Revenue Shot charter

**State:** Prepared instructions only. A schedule must not be activated until the GitHub repository, exact local checkout, CI and shared Codexify workspace binding are verified.

## Mission

Build a dependable local-first webhook consumer contract-testing CLI. Optimize for fully reproducible, inspectable results per hourly coding wake, and eventual useful developer distribution. Avoid generic webhook inspection features already available elsewhere.

## Every wake

1. Make a single bounded inventory of real checkout HEAD, owned changes, prior incomplete branch, current GitHub PRs, journal and active writers. Resume incomplete meaningful work before starting something new. Never reset or clobber unrelated work.
2. Prioritize one verified failure case: deduplication, signature/freshness, crash recovery, retry behavior, state observability, sequence order, or safe config. Design an explicit expected observable effect before implementation.
3. Add a failing regression test, implement a narrow repair, and run `npm run verify` locally. Never claim a correctness property that tests do not establish.
4. Keep the working branch isolated from main; create/update a focused `revshot/*` non-draft PR with evidence and reproducible commands. Include `MERGER_HANDOFF: AKzar1el/webhook-failure-lab@<SHA>` only after checking the exact pushed head and no forbidden effects. Let the guarded Windows merger perform independent CI/review checks and integration.
5. Write truthful run journal with test count, branch/SHA, PR, blockers, unsuccessful approaches, and next candidate. Prefer demonstrable user value over high commit count.

## Non-negotiable boundaries

- No production endpoints, real customer webhooks, production secrets, cloud hosting, or paid API calls. Retain loopback-only target restrictions; no auto-follow redirects.
- All test secrets must be synthetic. No remote network access in baseline unit/smoke tests.
- Do not weaken standards-verification failures, remove tests to make CI pass, or claim the observation endpoint proves unobserved side effects.
- Do not edit another fleet worker's schedule, workspace, branch, journal, or source files.
- Record blockers rather than simulating a successful commit or merge.

## First backlog

- [ ] Scenario schema with replayable fixture IDs and sequence-specific assertions.
- [ ] Concurrency-race test driver with bounded concurrency and persistent effect assertions.
- [ ] Crash/retry simulation with deterministic checkpoints and recovery proof.
- [ ] Provider adapters, individually tested, without claiming a shared signature standard.
- [ ] JSON/SARIF results, CI examples and installation package.
