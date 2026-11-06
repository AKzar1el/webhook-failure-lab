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
| Committed event loses HTTP acknowledgement, then same signed event redelivered (opt-in) | First attempt raises transport error but increases observer count once; retry is accepted with no second effect | Local integration test, plus fixture that loses the idempotency record after commit |
| Dependent resource activation delivered before resource creation (opt-in) | Premature activation receives 409, leaves resource missing and count unchanged; creation advances to created; identical signed activation retry advances to activated, one effect per accepted transition | Local integration tests with premature-apply and rejected-event-deduplication negative fixtures |
| Secret rotation: previous signing key still valid, retired key revoked (opt-in) | Fresh previous-key event accepted once; different retired-key event rejected with no effect | Local integration tests with previous-key rejection, retired-key acceptance and reject-but-commit negative fixtures |
| Real local receiver restart after committing a signed event (programmatic opt-in) | First delivery commits once; an independently restarted child process retains the observer count and deduplication record; identical signed retry does not commit twice | Local child-process integration fixture with atomic disk-state replacement, lost-dedupe negative fixture, no-op restart negative fixture |
| Abrupt local receiver exit after persisting a signed event (programmatic opt-in) | First delivery commits then terminates without HTTP acknowledgement; recovered receiver preserves count and dedupe record; identical retry has no second observed effect | Real child exit code 47, fresh process, and deliberately broken durable count/dedupe fixtures |
| Declared deduplication retention boundary and stale signed replay (programmatic opt-in) | Exact duplicate one second before retention expiry must not reprocess; unchanged signature at +301 seconds must be rejected without effect | Synthetic clock, premature-eviction and stale-replay acceptance broken receivers, no-op-clock negative fixture |
| Same authenticated delivery ID reused with different signed payload (opt-in) | First signed event commits once; identical signed retry is idempotent; different validly signed body with same ID returns 409 without another effect | Local fixture catches silently acknowledged conflicts and reject-but-commit broken receivers |

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
Add `"lostAckAfterCommit": true` for a separate scenario using
`x-wfl-test-fault: commit-then-drop-ack-once`. The local-only adapter must
commit an event and its deduplication record before closing the socket without
an HTTP response. The runner then retries the same signed event without the
header; a second effect fails the check. An ignored fault header fails too.
The reported transport error is not proof of a real process crash or of
durable state across restarts. Never enable this adapter in production.
Add `"outOfOrderStateTransitions": true` for a separate dependent-event
contract. The local receiver must recognize the synthetic types
`test.resource.created` and `test.resource.activated` with a shared
`data.id`. It must return **409** without an effect for activation before
creation, then accept creation, then accept a retry of the **same signed**
activation. For this opt-in check, `GET /state?resourceId=<id>` must return
the usual non-negative integer `processedCount` and a `resourceState` of
`missing`, `created` or `activated`. The runner asserts both effects and
states after each step. An absent adapter or missing state observation fails
the check; it never claims generic receivers support these synthetic events.
Two local broken fixtures show why a 409 must neither apply the premature
transition nor mark the rejected message ID as already processed.
Add `"secretRotation": true` for a separate signing-key acceptance contract.
Set `WFL_SECRET`, `WFL_PREVIOUS_SECRET` and `WFL_RETIRED_SECRET` to three
distinct **synthetic** `whsec_` keys; do not place raw keys in configuration or
version control. The local receiver must accept the current/previous keys and
reject the retired key. The runner signs two independent events with previous
and retired keys respectively, asserting the 2xx/4xx outcomes and both observer
counts. It does not simulate a timed grace window or prove key persistence
across process restarts. The CLI validates all key formats and uniqueness
before any requests when this option is enabled.

Use `restartAfterCommit: true` only with the **programmatic** `runLab(config,
{ secret, restartReceiver })` API. `restartReceiver` is an explicit caller-owned
local process controller: it must terminate and await the original test receiver,
launch a fresh receiver process backed by its own persisted idempotency state,
then return the replacement's `{ endpoint, observer }` URLs. Both returned URLs
must be plain-HTTP loopback. The runner sends a fresh signed event before
restart, observes the committed count and `receiverInstanceId`, invokes the
controller once, observes the replacement, and replays the **identical** signed
event. Both HTTP responses must succeed; count must increase once total, survive
restart unchanged, and remain unchanged after replay. Two different, nonempty
observer-reported `receiverInstanceId` strings are required to detect a no-op
controller. The fixture additionally checks that the OS child PID changed.
The CLI has **no process-controller option**, so specifying this flag in
`lab.json` without calling the programmatic API fails closed before requests.
Tests spawn a synthetic child process and use a disposable local JSON state
file written before acknowledgement; no real service is restarted. The negative
fixture preserves the counter but forgets the dedupe set, exposing a second
observed effect after restart. A passing test does not verify arbitrary
database durability, actual crash-on-write behavior, or externally observable
exactly-once side effects. The observer and instance identifier are supplied by
the receiver and can be inaccurate.

Use `crashAfterPersist: true` only with the **programmatic** `runLab(config,
{ secret, recoverReceiver })` API. The test-only receiver must recognize the
header `x-wfl-test-fault: persist-then-crash-before-ack` on a fresh signed
event, persist the effect counter and deduplication key, then terminate its
process without returning an HTTP response. The caller-owned `recoverReceiver`
must witness termination, start a distinct local process backed by the state,
and return replacement `{ endpoint, observer }` loopback URLs. The runner
expects a transport error, a changed nonempty `receiverInstanceId`, the
committed count after recovery, and no additional effect when replaying the
identical signed event. The CLI cannot control processes; absent callbacks,
invalid flags, and nonloopback recovery URLs fail closed. Crash and graceful
restart checks require separate runs.

The synthetic integration fixture exits an actual Node child with code 47
after an awaited atomic JSON-file rename. Broken receivers persist the count
but lose the dedupe key, or persist the dedupe key but lose the count;
another negative fixture ignores the fault header. This is **post-rename
process-exit recovery**, not power-loss durability, an fsync guarantee, a crash
during a multi-write transaction, or proof of external exactly-once effects.
Both controller and observer remain caller-supplied evidence.

Use `retentionWindowSeconds: 60` (integer 2-240) **only** with
`runLab(config, { secret, advanceReceiverTime })`. A caller-owned callback
advances the clock of a synthetic local test receiver by the requested
seconds; the harness does not change the machine clock or wait in real time.
The scenario accepts a fresh signed event, replays it at `window - 1` seconds
(same signature; accepted with no additional effect), then replays the unchanged
signed event at +301 seconds (4xx rejection and no effect). The mock receiver
uses a 60-second synthetic dedupe retention, with negative variants that expire
the key too early or treat stale previously accepted messages as valid after
eviction. The callback is required before network requests, and a no-op clock
controller fails the stale-replay assertion. The JSON CLI lacks this controller
and fails closed if configured with this option. Run separately from restart
and crash tests. The check forbids reprocessing **within** the declared
retention window; it does not prescribe behavior for newly signed events
after that window. Retention longer than the declared minimum is allowed. This is not a proof
of provider timestamp behavior or external exactly-once side effects.

The observer is a **caller-provided processed-event count**, not a direct
proof of bank charges, emails sent, or database writes. It can be wrong
or incomplete. Passing is therefore a scoped assertion, not an
exactly-once delivery guarantee.

Enable `"conflictingEventIdPayload": true` in local CLI configuration to
exercise an explicit **strict event-ID immutability** contract. The runner
sends a new signed event, a byte-identical signed retry (both expected 200),
then a different body signed afresh with the same `webhook-id` (expected
**409 Conflict**). All three observer counts must show exactly one new
effect. Both signatures are valid; a 401 is not an acceptable stand-in for
detecting the collision. Built-in deliberately broken receivers either
silently acknowledge the changed body or reject it after committing another
effect. This stricter rule is opt-in because it is a receiver/application
contract, **not** a universal provider guarantee that event IDs never carry
revised payloads. Keep the test adapter local-only.

## Bounded next scenarios (not implemented yet)

- Torn multi-write database transaction and power-loss/fsync durability
  (not established by post-rename process exit).
- Real-time retention expiry under scheduling and delayed delivery (synthetic
  receiver-clock control only is tested).

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
