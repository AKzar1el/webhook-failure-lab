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
| Older distinct signed resource-version update delivered after a newer version (opt-in) | Signed versions 1 and 3 are accepted; delayed signed version 2 receives 409 with no additional effect and observed version remains 3 | Synthetic adapter and local negative receivers that apply stale versions or reject only after committing |
| Concurrent copies of one freshly signed event (opt-in) | All acknowledged; observer count rises exactly once | Local integration test, plus deliberately non-atomic negative receiver fixture |
| Concurrent independently signed events with distinct IDs (opt-in) | All acknowledged; observer count increases once per unique event | Local integration tests with deliberately broken global-coalescing and busy-rejection fixtures |
| First delivery rejected with injected HTTP 503, then same signed event retried (opt-in) | First attempt leaves observer unchanged; retry succeeds and increments it once | Local integration test, plus fixture that marks rejected events as processed |
| Committed event returns HTTP 503, then identical signed delivery retried (opt-in) | First attempt returns 503 *after* one observed effect; retry succeeds with no additional effect | Local integration tests with missing dedupe key, precommit failure, and ignored fault negative fixtures |
| Committed event loses HTTP acknowledgement, then same signed event redelivered (opt-in) | First attempt raises transport error but increases observer count once; retry is accepted with no second effect | Local integration test, plus fixture that loses the idempotency record after commit |
| Dependent resource activation delivered before resource creation (opt-in) | Premature activation receives 409, leaves resource missing and count unchanged; creation advances to created; identical signed activation retry advances to activated, one effect per accepted transition | Local integration tests with premature-apply and rejected-event-deduplication negative fixtures |
| Secret rotation: previous signing key still valid, retired key revoked (opt-in) | Fresh previous-key event accepted once; different retired-key event rejected with no effect | Local integration tests with previous-key rejection, retired-key acceptance and reject-but-commit negative fixtures |
| Real local receiver restart after committing a signed event (programmatic opt-in) | First delivery commits once; an independently restarted child process retains the observer count and deduplication record; identical signed retry does not commit twice | Local child-process integration fixture with atomic disk-state replacement, lost-dedupe negative fixture, no-op restart negative fixture |
| Abrupt local receiver exit after persisting a signed event (programmatic opt-in) | First delivery commits then terminates without HTTP acknowledgement; recovered receiver preserves count and dedupe record; identical retry has no second observed effect | Real child exit code 47, fresh process, and deliberately broken durable count/dedupe fixtures |
| Declared deduplication retention boundary and stale signed replay (programmatic opt-in) | Exact duplicate one second before retention expiry must not reprocess; unchanged signature at +301 seconds must be rejected without effect | Synthetic clock, premature-eviction and stale-replay acceptance broken receivers, no-op-clock negative fixture |
| Same authenticated delivery ID reused with different signed payload (opt-in) | First signed event commits once; identical signed retry is idempotent; different validly signed body with same ID returns 409 without another effect | Local fixture catches silently acknowledged conflicts and reject-but-commit broken receivers |
| Concurrent distinct signed payloads sharing one event ID (opt-in) | Exactly one request accepted and the other returns HTTP 409 (either order); observer count increases once | Local racy check-before-commit, silent-acknowledge and reject-after-commit negative fixtures |
| Same ID and body re-signed at a different fresh timestamp (opt-in) | Both validly signed deliveries are acknowledged; first commits once, second makes no new observed effect | Local fixture catches signature-keyed deduplication and rejection of valid re-signatures; CLI config and composition regressions |
| Correctly signed event dated one hour in the future (opt-in) | Reject 4xx without committing any new observed effect | Local negative fixtures detect accepted future timestamps and rejected events that still commit; no system clock change |
| Previously processed event ID replayed with a tampered HMAC (opt-in) | Valid initial delivery accepted once; same ID, timestamp and body with a modified signature rejected 4xx, without a second observed effect | Local negative fixtures detect dedupe-before-authentication acknowledgement and reject-after-commit mistakes |
| Previously processed event ID re-signed with a stale timestamp (opt-in) | Fresh signed event accepted once; same cached ID and raw body re-signed one hour in the past must be rejected 4xx without another effect | Local negative fixtures detect dedupe-before-freshness acknowledgement and reject-after-commit mistakes |
| Previously processed event ID replayed with changed body but original HMAC (opt-in) | Original delivery accepted; altered body with reused authenticated ID and now-invalid HMAC rejected without collision 409 or another effect | Local negative fixtures detect collision-before-auth status and reject-after-commit mistakes, even if configured rejection statuses include 409 |
| Cached ID replayed with a retired signing key (opt-in) | Fresh delivery with accepted previous key commits once; same ID/body/timestamp authenticated under revoked key rejected without another effect | Local negative fixtures detect cached-ID acknowledgement before key validation and reject-after-commit, with strict three-key preflight |
| Multiple v1 signatures in a single header (opt-in) | Valid second or first token is accepted once; separate event with two invalid tokens rejected without effect | Local negative fixtures catch first-only verification, acceptance of an invalid list and rejection after extra effect |

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
Add `"retryAfterCommittedError": true` for a separate **post-commit HTTP 503**
contract. The receiver's development-only adapter must recognize
`x-wfl-test-fault: commit-then-respond-503-once` on the first fresh signed
`wfl_committed503_` event. It must commit the effect and dedupe key, then return
HTTP 503. The harness observes the increment before retrying the identical
signed event without the fault header; that retry must succeed without another
effect. Broken fixtures fail when the receiver loses dedupe state, rejects
before committing, or ignores the explicit fault. This is neither the
pre-commit 503 check nor the transport-drop check. No automated backoff or
external business-effect guarantee is asserted; never expose the adapter.
Add `"concurrentDistinctDeliveries": 4` (integer 2-8) for a separate
**distinct-event concurrency** check. The harness concurrently sends N
independently signed, fresh events with different webhook IDs and payload IDs;
every request must return `successStatus`, and the observer must increase by N
effects. This complements the *same-ID* race test, which expects only one effect
from N deliveries. The local negative fixtures model a global in-flight lock
that either silently acknowledges and loses N-1 distinct events or returns 503
for them; both must fail. The test uses bounded in-process fan-out and does not
assert throughput, fairness, real provider behavior, or external exactly-once
effects. The option is independent and can be combined with other checks.
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

Enable `"rejectRetiredKeyDuplicate": true` to check that a previously
accepted delivery ID does not bypass signing-key retirement. Supply distinct
synthetic `WFL_SECRET`, `WFL_PREVIOUS_SECRET` and `WFL_RETIRED_SECRET` keys.
The first event is authenticated by the still-valid previous key, accepted
once; its **same ID, raw body and timestamp** are then signed with the revoked
key. The second request must return a configured 4xx rejection and must not
increment `processedCount`. The runner validates all three secrets and the
boolean opt-in before any HTTP request. A cache-first acknowledgement and
rejection-after-commit are exercised by deliberately broken local fixtures.
The baseline's four scenarios are unchanged; this check composes with
`secretRotation`, and does not establish real provider retirement timing,
secret storage correctness, or unobserved external effects.

Enable `"multiSignatureHeader": true` to test a space-separated Standard
Webhooks signature header. A fresh event signed with the configured synthetic
current key is sent with an invalid v1 token first and a valid v1 token second;
an identical duplicate is sent with the valid token first. Both must be
acknowledged, with only one new observed effect. A separate event carrying
two invalid tokens must return a configured 4xx rejection without an effect.
The runner validates the boolean before sending any requests, never includes
signatures in reports, and does not require previous or retired keys. Broken
local fixtures catch first-token-only verification, invalid-list acceptance,
and rejection after committing. This does not prove a real provider's key
rotation behavior, external business effects or a receiver's key management.

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

Enable `"rejectUnauthenticatedCollision": true` to test the boundary between
authentication and strict event-ID immutability. The harness first sends a
valid signed event, then changes the raw body under the same ID while reusing
the original HMAC. Since the changed bytes are not authenticated, the receiver
must reject with a configured 4xx status **other than 409 Conflict** and must
not commit another observed effect. The exclusion of 409 applies even if
`rejectionStatuses` explicitly includes it: collision classification must
not precede HMAC verification. Two deliberately unsafe fixtures catch
collision-before-auth and rejection-after-commit behavior. This opt-in check
works with the existing signed collision and tampered duplicate tests; it
does not prove external side effects or prevent every information leak.

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

Enable `"concurrentConflictingEventIdPayload": true` to test the related
**atomic** collision contract. Two different bodies, each signed correctly
with the same fresh `webhook-id`, are sent together. One must return
`successStatus` and the other **409**, in either order; the observer must
increase by one effect. A local negative receiver deliberately lets both
requests read an empty deduplication record before both commit, proving the
probe detects a check-then-write race. Other fixtures acknowledge the
conflict without 409 or reject only after committing. This two-request
probe does not exhaustively explore all schedules, prove atomicity of
external effects, or apply to providers without an immutable-ID contract.
Omitting the option preserves the four baseline checks. It composes with
the existing concurrency checks.

Enable `"resignedDuplicateDelivery": true` in local CLI configuration to
exercise a separate **same-event-ID re-signing** contract. The runner sends
one fresh signed event, then an identical body and ID authenticated with a
different timestamp (one second apart) and corresponding valid signature.
Both responses must equal `successStatus`; the observer count may increase
only for the initial delivery. Local broken receivers instead key the dedupe
record on the signature (committing twice) or reject the new valid signature
for an already accepted ID. These negative fixtures fail the scenario. This
does not test provider-specific retry policy or require a service to support
re-signed duplicate IDs universally; enable it only for a local receiver
whose application contract accepts that behavior. The observer remains
caller-controlled, not proof of external exactly-once business effects.

Enable `"rejectFutureSignedTimestamp": true` in local CLI configuration to
exercise a symmetric signed-timestamp freshness contract. The runner sends
an event whose HMAC correctly authenticates its ID, raw body and timestamp,
but whose `webhook-timestamp` is **3600 seconds ahead** of the runner clock.
The receiver must return one of `rejectionStatuses` (default 400/401/403),
without changing the `processedCount` observer. It is opt-in to avoid
claiming every provider requires identical clock-skew behavior. The built-in
mock catches receivers that validate past expiry but accept far-future
signatures, or reject future signatures after recording an effect. The
scenario uses no wall-clock waits or system-clock changes; the runner and
receiver should have reasonably synchronized clocks and a 300-second
Standard Webhooks freshness policy. Passing cannot prove unobserved effects.

Enable `"rejectTamperedDuplicateSignature": true` in local CLI configuration
to verify that **authentication precedes deduplication**. The runner first
sends one fresh valid signed event, then replays its exact event ID, timestamp
and raw body with a single HMAC digest character changed. The receiver must
accept the first request, reject the second with a configured 4xx status, and
record only one new observed effect. This tests a different failure path from
the baseline's tampered body on a previously unseen ID: a cached event ID must
not bypass verification. Two deliberately broken local receivers either
acknowledge the unauthenticated duplicate or commit an additional effect before
returning 401. The check is opt-in, uses only synthetic keys and loopback HTTP,
and does not establish unseen external business-effect correctness.

Enable `"rejectStaleDuplicateSignature": true` in local CLI configuration
to verify that **freshness precedes cached-ID deduplication**. The runner first
delivers a fresh, valid signed event and then sends the **same ID and raw
body**, authenticated with an independent valid HMAC whose timestamp is
3600 seconds in the past. The cached-ID replay must return a configured
4xx rejection without another observed effect. This is distinct from the
baseline stale-timestamp check on an **unseen** ID, the invalid-HMAC duplicate
check, and the synthetic-clock retention test. Two deliberately broken
receivers either acknowledge the stale cached ID or return 401 after an extra
effect. No clock changes, delayed requests or production keys are involved.
This opt-in rule assumes a Standard Webhooks receiver enforcing a 300-second
timestamp tolerance; passing establishes only the caller-reported count, not
the absence of external effects.

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

## Versioned update-order contract (opt-in)

Enable `"versionedOutOfOrderUpdates": true` for a **monotonic resource-version**
contract. A local-only adapter must recognize three separately signed
`test.resource.versioned` events with the same `data.id` and integer
versions 1, 3, then 2. Accept 1 and 3 with `successStatus`, then reject
delayed 2 with HTTP **409**, leaving both `processedCount` and the reported
`resourceVersion` unchanged at 3. The observer must include a non-negative
integer `resourceVersion` in `GET /state?resourceId=<id>`; missing
instrumentation fails the scenario. A correct receiver may skip intermediate
version numbers and must not treat the late event as an already-seen ID. Two
negative fixtures apply the stale version outright or reject it only after
recording another effect. Boolean options are validated before any request.
This is independent of creation/activation order and does not guarantee
external exactly-once effects or provider version semantics.
