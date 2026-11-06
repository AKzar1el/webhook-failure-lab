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

Run `npm run verify` to execute unit tests, the concurrency regression tests,
and the four default localhost smoke scenarios. Set
`"concurrentDuplicateDeliveries": 4` (integer 2-8) in local configuration
to enable the fifth check against your own receiver. The baseline also has
negative tests for deliberate duplicate processing and receivers accepting
invalid signatures.

The observer is a **caller-provided processed-event count**, not a direct
proof of bank charges, emails sent, or database writes. It can be wrong
or incomplete. Passing is therefore a scoped assertion, not an
exactly-once delivery guarantee.

## Bounded next scenarios (not implemented yet)

- Failed first attempt followed by retry, where the failure is injected
  through a deterministic fake receiver.
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
