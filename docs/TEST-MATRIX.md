# Webhook Failure Lab test matrix

This is the supported contract for the current local-first test harness.
The CLI targets **loopback HTTP only**; it cannot send traffic to public
webhooks. Use synthetic signing secrets and event payloads.

## Baseline scenarios (implemented)

| Scenario | Expected receiver behavior | Current evidence |
| --- | --- | --- |
| First valid signed delivery | Accept once; observer count becomes one | Local smoke |
| Same event ID delivered twice | Acknowledge without repeated business side effect | Local smoke |
| Modified body after signing | Reject; observer state unchanged | Local smoke |
| Stale signed timestamp | Reject; observer state unchanged | Local smoke |
| Concurrent copies of one freshly signed event (opt-in) | All acknowledged; observer count rises exactly once | Local integration test, plus deliberately non-atomic negative receiver fixture |
| First delivery rejected with injected HTTP 503, then same signed event retried (opt-in) | First attempt leaves observer unchanged; retry succeeds and increments it once | Local integration test, plus fixture that marks rejected events as processed |

Run `npm run verify` to execute unit tests, the concurrency regression tests,
and the four default localhost smoke scenarios. Set
`"concurrentDuplicateDeliveries": 4` (integer 2-8) in local configuration
to enable the fifth check against your own receiver. The baseline also has
negative tests for deliberate duplicate processing and receivers accepting
invalid signatures. Add `"retryAfterTransientFailure": true` to test a single
retry after a development-only injected failure. The local receiver adapter
must return 503 **before processing** when the first request contains
`x-wfl-test-fault: reject-before-process-once`; the lab then resends the same
signed event without that header. Receivers without this explicit test adapter
fail the first-status assertion. Do not enable the adapter on public services.

The observer is a **caller-provided processed-event count**, not a direct
proof of bank charges, emails sent, or database writes. It can be wrong
or incomplete. Passing is therefore a scoped assertion, not an
exactly-once delivery guarantee.

## Bounded next scenarios (not implemented yet)

- Lost acknowledgement after processing, then duplicate delivery, scoped to
  an independently observable committed effect.
- Two dependent event types delivered out of order, with explicit state
  transition assertions.
- Receiver restart between processing and acknowledgement, with
  durable idempotency state supplied by a local fixture.
- Secret rotation and dual-key acceptance, including negative coverage.
- Idempotency retention boundary expiry, scoped to a documented time window.

Each new scenario must include a fixture proving the test detects a
deliberately broken receiver, not merely that the happy path passes.

## Guardrails

- No remote URLs, provider credentials, real customer payloads, paid APIs,
  or cloud service dependencies.
- Avoid claims of cryptographic or exactly-once guarantees beyond the
  tested implementation.
- Keep raw webhook signing keys and local `.revenue-shot/` state outside Git.
- For CI integration, make negative scenarios fail the process with a
  nonzero exit code and preserve machine-readable evidence.
