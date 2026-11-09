# Webhook Failure Lab test matrix

This is the supported contract for the current local-first test harness.
The CLI targets **loopback HTTP only**; it cannot send traffic to public
webhooks. Use synthetic signing secrets and event payloads.

The CLI defaults to JSON, with opt-in `--format sarif` for SARIF 2.1.0.
Opt-in `--format junit` emits a JUnit-style XML test suite with one testcase
per completed scenario; contract violations are failures, while invalid
configuration or transport errors become a single execution-error testcase
without any receiver-contract verdict. Both CI formats export only allowlisted
observations, never payloads, keys, untrusted observer strings or target URLs.
The deliberately broken duplicate-data-key receiver is also a real negative
fixture for a failed XML testcase. Exit codes remain 0/1/2 in every format.
Only failed receiver contracts create SARIF error findings; all executed
scenarios appear as stable rules, and exit status remains 0 (pass), 1
(receiver failure), or 2 (input/transport error). The signed duplicate-data-key
broken receiver is an explicit negative fixture for a machine-readable error.
In SARIF mode an incomplete run (for example, a deliberately broken localhost
observer returning 503) emits a failed invocation with a sanitized
`toolExecutionNotifications` entry and no contract findings, retaining exit 2.
This reports an execution failure, **not** a receiver contract verdict; the
default JSON mode retains its stderr-only execution errors.
SARIF excludes payloads, secrets, URLs, and arbitrary observer strings; it
does not invent a receiver source-code location. Counts remain receiver-reported.

## Baseline scenarios (implemented)

| Scenario | Expected receiver behavior | Current evidence |
| --- | --- | --- |
| Validly signed JSON with missing required synthetic event field, then corrected same-ID signed retry (opt-in) | Reject schema-invalid envelope with 422 before an effect or dedupe write; accept corrected event once and dedupe exact replay | Deliberately broken local receivers accept invalid envelopes, poison dedupe on rejection, or reject after recording an effect |
| Correctly signed JSON with two top-level data properties, including a Unicode-escaped second key `d\u0061ta`, then a corrected same-ID signed retry (opt-in) | Reject both ambiguous duplicate-key envelopes with 422 before any effect or ID reservation; accept the corrected single-key event once and dedupe replay | Local negative fixtures accept literal or escaped duplicate logical keys, cache a rejected ID or commit before rejection; a narrow synthetic fixture, not a universal duplicate-property detector |
| Valid signed JSON sent as text/plain, then same-ID correction to application/json (opt-in) | Reject first attempt with 415 without effect or ID reservation; accept corrected original-HMAC delivery once; identical replay dedupes | Local broken receivers catch accepting wrong media type, poisoning dedupe on rejection, and 415 after an unwanted effect |
| Correctly signed JSON declaring unsupported Content-Encoding: gzip, then same-ID removal of that header (opt-in) | Reject the first uncompressed JSON body falsely declared gzip with 415 before effect or ID reservation; accept unchanged signed bytes once without the encoding header and dedupe exact replay | Local negative receivers ignore the unsupported encoding, cache rejected IDs or return 415 after committing; opt-in declared local encoding policy only |
| Valid signed JSON with application/json; charset=utf-8, followed by same-ID plain application/json (opt-in) | Accept both valid JSON media types with one observed effect despite an unsigned header change | Local broken receivers reject the legitimate charset parameter with 415 or dedupe by Content-Type and commit twice |
| Signed pretty JSON and semantically identical compact JSON reusing the first HMAC (opt-in) | Accept the exact signed pretty bytes once; reject altered raw bytes without effect; accept an exact replay without another effect | Local broken receivers reserialize before verification, acknowledge cached ID before verifying altered bytes, or reject only after another effect |
| Same signed event ID in two independent synthetic tenants, then wrong-key replay (opt-in) | Tenant A and B each commit once under their own signing key; a cached tenant-A ID signed by B's key is rejected without effect or 409 collision classification; exact retries dedupe within each tenant | Local negative fixtures catch globally keyed dedupe, premature collision classification, cross-tenant key acceptance, and reject-after-commit |
| Correctly signed JSON exceeding a declared 1,024-byte local size cap, then corrected same-ID signed retry (opt-in) | Return 413 without effect or ID reservation; accept a corrected smaller independently signed body once, and dedupe exact replay | Broken localhost fixtures accept oversized input, poison deduplication on rejection, or return 413 after an observed commit |
| Two independently signed IDs differing only in ASCII case, then exact retries (opt-in) | Both new IDs accepted and committed once each; exact retries acknowledged without additional observed effects | Local negative fixtures lowercase the dedupe key or reject the case variant as a collision |
| Two signed webhook IDs named `__proto__` and `constructor`, then exact retries (opt-in) | When the receiver declares arbitrary opaque ID support, accept and report each new authenticated ID once; exact retries must remain idempotent | Three broken loopback receivers use an inherited-property dictionary, a prototype setter that loses the dedupe key, or blanket 409 rejection; this is not an assertion that every provider permits these IDs |
| Two distinct signed delivery IDs for one resource ID, then exact signed retries (opt-in) | Independently accept a synthetic resource creation and update, both referring to one `data.id`; count each event once and dedupe by signed delivery ID, not by the resource ID | Broken localhost receivers silently coalesce by resource ID, return 409 for a distinct event, or reprocess exact event-ID replays |
| Two independently signed delivery IDs carrying byte-identical JSON bodies, then exact retries (opt-in) | Count each previously unseen authenticated ID once even when body bytes match; accept exact replays without a second observed effect | Local broken receivers dedupe by body hash, classify identical-body distinct IDs as 409 collisions, or reprocess signed retries; assumes synthetic per-delivery counting contract |
| Malformed JSON with valid HMAC, then corrected same-ID signed retry (opt-in) | First delivery rejected as invalid JSON without effect or dedupe record; corrected independently signed JSON with same ID accepted and applied exactly once | Local negative receivers accept the malformed body, poison the dedupe cache on reject, or commit before returning 400 |
| Invalid HMAC on fresh event ID, followed by valid retry and identical replay (opt-in) | First signed-header tampering rejected without effect or reserved ID; identical event with correct signature commits once, and exact valid replay dedupes | Local negative fixtures catch cached IDs reserved on authentication failure, reject-after-commit effects, and accepting the invalid signature |
| Missing HMAC header on a fresh event ID, followed by validly signed retry and replay (opt-in) | Reject unsigned first attempt 4xx without effect or ID reservation; accept corrected signature once and dedupe exact replay | Local negative fixtures accept absent signature, poison rejected dedupe, or commit before rejecting |
| Unsupported `v2,` signature prefix with authentic v1 digest, followed by correct v1 signed retry and replay (opt-in) | Strict v1-only receivers reject unsupported version 4xx before effect or ID reservation, then accept and dedupe the same ID once with proper v1 signature | Broken local fixtures ignore the version prefix, poison a rejected-ID cache or reject after committing; this is not a universal assertion about future signature algorithms |
| Missing signed timestamp header on a fresh event ID, followed by corrected retry and replay (opt-in) | Reject first attempt 4xx without effect or ID reservation; accept same ID/body/HMAC with added timestamp once and dedupe exact replay | Local negative fixtures accept absent timestamp, poison rejected dedupe or commit before 401 |
| Missing signed event-ID header, followed by corrected same-ID retry and replay (opt-in) | Reject first attempt 4xx without effect or reserving body ID; accept restored signed ID header once and dedupe replay | Broken local receivers substitute JSON data.id for absent wire header, cache rejected body ID, or commit before returning 401 |
| Two physical webhook-id HTTP fields with different IDs and HMAC for the first, followed by corrected same-ID retry (opt-in) | Reject ambiguous wire headers 4xx before effect or dedupe reservation; accept a single signed event-ID header once and dedupe exact replay | Direct loopback Node HTTP sender preserves distinct fields; first-wins, rejected-ID-cache and reject-after-commit negative receivers are detected |
| Two physical webhook-timestamp fields, fresh signed and stale in both wire orders, then corrected same-ID retry (opt-in) | Reject both ambiguous signed timestamp envelopes 4xx before effect or dedupe reservation; accept the sole fresh timestamp once and dedupe exact replay | Direct loopback Node HTTP sender preserves both fields; negative receivers trust the first/last timestamp, cache rejected IDs or commit before rejection |
| Two physical webhook-signature fields, one valid HMAC and one corrupted HMAC in both wire orders, then corrected same-ID retry (opt-in) | Reject ambiguous physical signature fields 4xx before effect or ID reservation; accept the sole valid signature once and dedupe exact replay | Direct loopback Node HTTP sender preserves both fields; separate multi-signature-in-one-field test remains valid; broken receivers trust first/last, cache rejected IDs or commit before rejection |
| Two physical Content-Type fields with conflicting application/json and text/plain in both wire orders, then corrected same-ID retry (opt-in) | Reject both ambiguous media-type envelopes with a configured 4xx before effect or dedupe reservation; accept the sole application/json field once and dedupe replay | Direct Node loopback HTTP preserves raw physical fields; negative receivers trust first or last, poison the rejected ID or commit an effect before rejection; this is a declared local strict-header policy |
| Two physical Content-Encoding fields with conflicting identity and gzip in both wire orders, then corrected same-ID retry (opt-in) | Reject each ambiguous encoding envelope with a configured 4xx before effect or dedupe reservation; accept the same signed bytes without encoding headers once and dedupe exact replay | Direct Node loopback HTTP preserves physical fields; four deliberately broken receivers trust first/last, poison rejected IDs or commit before rejection; strict encoding policy is local-only |
| Valid signed JSON with a three-byte UTF-8 character split across two HTTP chunked-transfer writes, then identical fixed-length replay (opt-in) | Decode/verify the complete raw bytes, accept the initial chunked delivery, and deduplicate the same signed event ID independently of transfer framing | Direct Node loopback HTTP sender forces split over the multibyte sequence; broken fixtures decode individual chunks, reject chunked transfer or key deduplication by framing |
| Correctly HMAC-signed JSON containing invalid raw UTF-8 bytes, then corrected same-ID signed retry (opt-in) | Reject invalid encoding with a configured 4xx before any effect or dedupe reservation; accept corrected bytes once and dedupe replay | Broken local receivers silently replace invalid octets, cache rejected ID, or commit before rejection; HMAC is computed over exact bytes |
| First valid signed delivery | Accept once; observer count becomes one | Local smoke |
| Same event ID delivered twice | Acknowledge without repeated business side effect | Local smoke |
| Modified body after signing | Reject; observer state unchanged | Local smoke |
| Stale signed timestamp | Reject; observer state unchanged | Local smoke |
| Older distinct signed resource-version update delivered after a newer version (opt-in) | Signed versions 1 and 3 are accepted; delayed signed version 2 receives 409 with no additional effect and observed version remains 3 | Synthetic adapter and local negative receivers that apply stale versions or reject only after committing |
| Concurrent copies of one freshly signed event (opt-in) | All acknowledged; observer count rises exactly once | Local integration test, plus deliberately non-atomic negative receiver fixture |
| Concurrent independently signed events with distinct IDs (opt-in) | All acknowledged; observer count increases once per unique event | Local integration tests with deliberately broken global-coalescing and busy-rejection fixtures |
| First delivery rejected with injected HTTP 503, then same signed event retried (opt-in) | First attempt leaves observer unchanged; retry succeeds and increments it once | Local integration test, plus fixture that marks rejected events as processed |
| First signed event receives HTTP 429 with Retry-After: 0, followed by identical signed retry and replay (opt-in) | Synthetic local adapter rejects without side effect or ID reservation; the immediate retry commits once and replay dedupes | Four deliberately broken loopback fixtures detect poisoned dedupe, a pre-429 effect, missing retry guidance, and ignored fault injection |
| Committed event returns HTTP 503, then identical signed delivery retried (opt-in) | First attempt returns 503 *after* one observed effect; retry succeeds with no additional effect | Local integration tests with missing dedupe key, precommit failure, and ignored fault negative fixtures |
| Committed event loses HTTP acknowledgement, then same signed event redelivered (opt-in) | First attempt raises transport error but increases observer count once; retry is accepted with no second effect | Local integration test, plus fixture that loses the idempotency record after commit |
| Client times out waiting for a committed signed event (opt-in) | Receiver commits once but holds HTTP acknowledgement past the client's `timeoutMs`; the harness observes a client timeout, then identical signed retry succeeds without a second effect | Synthetic localhost held-response fixture, with broken lost-dedupe and ignored-fault negative receivers |
| Client times out before a declared synthetic precommit cancellation (opt-in) | First signed delivery holds response until client deadline without reserving ID or committing; identical signed retry commits once and exact replay dedupes | Local fault `hold-before-commit-until-timeout`; negative fixtures poison the dedupe cache, commit during the fault, or ignore the timeout control |
| Dependent resource activation delivered before resource creation (opt-in) | Premature activation receives 409, leaves resource missing and count unchanged; creation advances to created; identical signed activation retry advances to activated, one effect per accepted transition | Local integration tests with premature-apply and rejected-event-deduplication negative fixtures |
| Delayed replay of resource creation after activation (opt-in) | Signed creation and activation each commit once; identical signed creation replay is acknowledged without another effect or regressing activated state | Local integration tests with rewind, reject-duplicate and hidden-effect negative fixtures |
| Secret rotation: previous signing key still valid, retired key revoked (opt-in) | Fresh previous-key event accepted once; different retired-key event rejected with no effect | Local integration tests with previous-key rejection, retired-key acceptance and reject-but-commit negative fixtures |
| Real local receiver restart after committing a signed event (programmatic opt-in) | First delivery commits once; an independently restarted child process retains the observer count and deduplication record; identical signed retry does not commit twice | Local child-process integration fixture with atomic disk-state replacement, lost-dedupe negative fixture, no-op restart negative fixture |
| Abrupt local receiver exit after persisting a signed event (programmatic opt-in) | First delivery commits then terminates without HTTP acknowledgement; recovered receiver preserves count and dedupe record; identical retry has no second observed effect | Real child exit code 47, fresh process, and deliberately broken durable count/dedupe fixtures |
| Concurrent signed retries after a postcommit receiver crash (programmatic opt-in) | After real exit 47 and a new process starts, 2-8 identical signed retries all succeed and the already committed effect count stays unchanged, including a final replay | Real recovered localhost child, deliberately forgotten durable dedupe on recovery, and deterministic check-before-write race |
| Abrupt local receiver exit before committing a signed event (programmatic opt-in) | First delivery terminates without HTTP acknowledgement or any durable effect/ID reservation; recovered receiver accepts the same signed retry once, and exact replay dedupes | Real child exit code 48, new process instance, broken precrash dedupe-only or effect-only persistence fixtures and ignored fault fixture |
| Concurrent signed retries immediately after a precommit receiver crash (programmatic opt-in) | After real exit 48 and a clean restart, 2-8 identical concurrently delivered signed retries all succeed; observer count rises once in total, followed by an idempotent replay | Real recovered localhost child plus a deterministic broken check-before-write deduplication race and precrash ID-poisoning fixture |
| Declared deduplication retention boundary and stale signed replay (programmatic opt-in) | Exact duplicate one second before retention expiry must not reprocess; unchanged signature at +301 seconds must be rejected without effect | Synthetic clock, premature-eviction and stale-replay acceptance broken receivers, no-op-clock negative fixture |
| Same authenticated delivery ID reused with different signed payload (opt-in) | First signed event commits once; identical signed retry is idempotent; different validly signed body with same ID returns 409 without another effect | Local fixture catches silently acknowledged conflicts and reject-but-commit broken receivers |
| Concurrent distinct signed payloads sharing one event ID (opt-in) | Exactly one request accepted and the other returns HTTP 409 (either order); observer count increases once | Local racy check-before-commit, silent-acknowledge and reject-after-commit negative fixtures |
| Same ID and body re-signed at a different fresh timestamp (opt-in) | Both validly signed deliveries are acknowledged; first commits once, second makes no new observed effect | Local fixture catches signature-keyed deduplication and rejection of valid re-signatures; CLI config and composition regressions |
| Correctly signed event dated one hour in the future (opt-in) | Reject 4xx without committing any new observed effect | Local negative fixtures detect accepted future timestamps and rejected events that still commit; no system clock change |
| Modified textual timestamp header with HMAC for canonical integer (opt-in) | Reject leading-zero and decimal `.0` timestamp strings without observed effects; the original signature only covers canonical timestamp bytes | Local broken receiver fixtures detect numeric normalization before HMAC verification and rejected deliveries that still commit |
| Previously processed event ID replayed with a tampered HMAC (opt-in) | Valid initial delivery accepted once; same ID, timestamp and body with a modified signature rejected 4xx, without a second observed effect | Local negative fixtures detect dedupe-before-authentication acknowledgement and reject-after-commit mistakes |
| Previously processed event ID re-signed with a stale timestamp (opt-in) | Fresh signed event accepted once; same cached ID and raw body re-signed one hour in the past must be rejected 4xx without another effect | Local negative fixtures detect dedupe-before-freshness acknowledgement and reject-after-commit mistakes |
| Previously processed event ID re-signed with a future timestamp (opt-in) | Fresh signed event accepted once; same cached ID and raw body re-signed one hour in the future must be rejected 4xx without another effect | Local negative fixtures detect cached-ID acknowledgement before future freshness and reject-after-commit effects |
| Previously processed event ID replayed with changed body but original HMAC (opt-in) | Original delivery accepted; altered body with reused authenticated ID and now-invalid HMAC rejected without collision 409 or another effect | Local negative fixtures detect collision-before-auth status and reject-after-commit mistakes, even if configured rejection statuses include 409 |
| Cached ID replayed with a retired signing key (opt-in) | Fresh delivery with accepted previous key commits once; same ID/body/timestamp authenticated under revoked key rejected without another effect | Local negative fixtures detect cached-ID acknowledgement before key validation and reject-after-commit, with strict three-key preflight |
| Multiple v1 signatures in a single header (opt-in) | Valid second or first token is accepted once; separate event with two invalid tokens rejected without effect | Local negative fixtures catch first-only verification, acceptance of an invalid list and rejection after extra effect |
| Concurrent signed HTTP 202 acknowledgements with delayed local processing (opt-in) | Two identical signed deliveries receive 202, one observed effect after a bounded settlement window, then a 202 replay without an extra effect | Deliberately broken in-memory queue fixtures drop work after acknowledging, double-commit a queued event, or enqueue the concurrent duplicate; does not establish durable queuing or later external side effects |

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
Add `"timeoutAfterCommit": true` for a distinct client-deadline scenario using
`x-wfl-test-fault: commit-then-hold-ack-until-timeout`. The test-only local
receiver must commit the effect and its idempotency key before holding the
connection open longer than `timeoutMs`. The client must observe its own
timeout (not an early transport drop or HTTP response), verify the committed
count, then retry the exact same signed event without the fault header. A
lost dedupe record or ignored header fails the scenario. It is not a provider
timeout simulation or a durable/external exactly-once guarantee, and the
unsigned fault adapter must never be exposed in production.
Add `"timeoutBeforeCommit": true` for the complementary, explicitly
synthetic cancellation-before-commit contract. The local receiver must hold
the first response to `x-wfl-test-fault: hold-before-commit-until-timeout`
past the client's deadline, neither commit an effect nor reserve the signed
ID, and then accept an identical retry exactly once; an identical replay
must remain idempotent. The harness verifies a client timeout, unchanged
pre-retry count and post-retry count +1. Local negative fixtures poison the
ID, commit prematurely or ignore the fault. Real network timeouts do **not**
imply absence of commit, and the observer is not a guarantee about external
side effects; this fault header must not be used in production.
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
Add `"delayedCreationReplayAfterActivation": true` for a separate
**already-processed older-event replay** contract. The receiver uses the same
local synthetic `test.resource.created` and `test.resource.activated` adapter
and `GET /state?resourceId=<id>` observer. The harness sends creation, then
activation, then an **identical signed retry of creation**. All three responses
must equal `successStatus`; observed states must be `created`, `activated`,
`activated`, while the observer count increments only for the first two.
Broken fixtures catch rewinding the resource to `created`, rejecting an
already-acknowledged creation with 409, and an extra hidden observed effect
despite preserving the final state. This tests in-process idempotency while
the dedupe record is available, not a particular provider's redelivery
schedule, cross-restart persistence or external exactly-once effects. The
option composes with `outOfOrderStateTransitions` using separate IDs.
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

The test fixture waits up to 10 seconds for a child readiness IPC message to
avoid false failures under concurrent Node test-runner load (previously 4
seconds). A synthetic child delayed by 4.25 seconds must still start and pass
the default four loopback scenarios; a deliberately broken child that never
sends readiness must time out with a short test-only deadline. This changes
the local test fixture, not the public runner timeout or receiver contract.

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

Enable `"tenantScopedEventIds": true` to verify **per-tenant authentication
and idempotency** for the same opaque webhook ID. Supply two distinct synthetic
`whsec_` signing keys in `WFL_SECRET` and `WFL_TENANT_B_SECRET` (or use
`runLab(config, { secret, tenantBSecret })`). The receiver's **local-only**
`x-wfl-test-tenant` adapter selects the signing key for synthetic tenant
`a` or `b` and namespaces dedupe by tenant. The runner sends one
authenticated event per tenant with the **same ID** but distinct bodies, then
attempts a tenant-A event signed by B's key (configured 4xx other than 409
required even for a cached ID), followed by exact signed retries for A and B.
Expected observed increments are `[+1,+2,+2,+2,+2]` relative to the baseline. Five negative
fixtures expose global dedupe, false collisions, premature collision
classification, wrong-tenant-key acceptance and reject-after-commit. Invalid
keys, equal keys, and malformed flags fail
before requests. This header is a synthetic test selector, not an authorized
production tenant identity; observed counts cannot establish real tenant
isolation, external business effects, or provider-level key scoping.

Enable `"caseSensitiveEventIds": true` to test an explicit case-sensitive,
opaque event-ID contract. Two independent event IDs differ only in their final
ASCII `a` or `A`, and both are HMAC-authenticated over the exact ID and
their own raw JSON bodies. Both must return `successStatus` and increase the
observer count once. Exact signed retries of both IDs must be acknowledged
without another effect. Negative local receivers that lowercase deduplication
keys either silently drop the second event or return 409 for it; both fail.
This rule is opt-in because provider-specific ID semantics can differ. It
asserts only the synthetic receiver's exposed processed count, never
unobserved business effects.

Enable `"distinctEventsSameResource": true` to test a different event identity
contract: two independently signed webhook IDs contain synthetic resource
`created` and `updated` events with the **same** business `data.id`. Both
fresh events must be acknowledged and produce one observed effect each; each
exact signed retry must succeed with no additional effect. Expected observer
increments are `[+1,+2,+2,+2]` relative to the baseline. Three deliberately
broken localhost receivers silently dedupe by business resource ID, reject
the second event as a 409 collision, or replay both events as new effects.
This opt-in contract applies only where both synthetic event types are
actionable, not to arbitrary repeated resource notifications. It does not
verify domain state correctness or unobserved external business effects.

Enable `"rejectMalformedSignedPayload": true` to verify that authenticated
bytes still undergo JSON syntax validation **before** any idempotency write.
The runner sends intentionally incomplete JSON under a fresh `wfl_malformed_`
ID, with a valid HMAC over those exact bytes, and expects a configured 4xx
response and no observed effect. It then sends a valid JSON event with the
**same ID and a new, valid HMAC**; that corrected delivery must succeed and
increase `processedCount` by one. The corrected retry is intentionally a
different authenticated payload, unlike the collision check against an ID
that has already been **accepted**. Three negative fixtures expose accepting
malformed data, caching a rejected event ID, and rejecting after an observed
commit. A receiver without JSON validation fails closed; the check makes no
assertion about a real provider's ability to correct and resend malformed
events, or effects hidden from the provided observer. No extra protocol or
external network dependency is needed.

Enable `"rejectInvalidSignedEventSchema": true` for a separate opt-in
**synthetic envelope validation** contract. A fresh event has valid JSON and
correct HMAC authentication, but lacks the required `data.id` field for the
local `test.created` adapter. The receiver must return HTTP **422** without
recording an effect or caching the webhook ID. The runner independently signs
a corrected event with the **same webhook ID**, a matching `data.id`, and
valid JSON; it must commit once and then acknowledge an identical signed
replay without a second observed effect. Negative fixtures accept invalid
envelopes, poison the ID cache on rejection, or record an effect before 422.
Missing local schema validation fails the scenario. This tests an explicitly
declared local schema only: it does not imply that Standard Webhooks prescribes
`data.id`, any universal JSON schema or provider retry behavior. The count
is receiver-reported and cannot establish external exactly-once effects.

Enable `"rejectOversizedSignedPayload": true` for a separate **local-only**
payload-size policy check. The runner signs a valid JSON body exceeding 2 KiB
under a fresh `wfl_oversize_` ID. A receiver enforcing a declared
**1,024-byte UTF-8 body cap** must return **413**, without an observed effect
or reserving that ID. An independently signed corrected JSON body using the
same ID must then succeed exactly once; its exact replay must be acknowledged
without another observed effect. Deliberately broken receivers accept the
oversized payload, poison the deduplication cache upon rejection, or return
413 only after an observed commit. Missing local enforcement fails closed.
This opt-in policy is **not** a provider or Standard Webhooks size standard:
the test covers only the declared local adapter and exposed processed count.

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

Enable `"rejectNoncanonicalTimestamp": true` to test exact signature coverage
of the textual `webhook-timestamp` header. The runner signs two independent
synthetic event IDs using the current integer timestamp but transmits a
leading-zero header for one and a decimal `.0` header for the other. A receiver
must reject both 4xx without any observed effect even though a permissive
numeric parser would yield the original number. The local Standard Webhooks
verifier rejects noncanonical decimal strings; the broken fixtures detect
numeric coercion before HMAC verification and rejection after an unintended
commit. The option is boolean and composes with future-timestamp and
multi-signature tests. No external endpoints, provider claims, or proof of
unobserved business effects are involved.

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

Enable `"rejectFutureDuplicateSignature": true` for the complementary
**future-skewed cached-ID** check. First, a freshly signed event is accepted
once. The runner then independently signs the identical ID and raw body
using a timestamp 3600 seconds in the future; despite the cached ID, that
delivery must return a configured 4xx without another observed effect.
Deliberately broken local receivers acknowledge the cached ID before
checking future freshness or commit an extra effect before returning 401.
The option composes with the unseen-ID future test and stale duplicate test.
It does not change the system clock, assume real provider redelivery policy,
or prove unobserved external business-side-effect correctness.

### Signed webhook ID header integrity (opt-in)

Enable `"rejectTamperedEventId": true`. The harness authenticates a new
event under its original ID, then changes only the transmitted ID header
while preserving the HMAC, timestamp and JSON payload. The second delivery
must be rejected and must not increase the observer's `processedCount`.
Synthetic broken receivers detect body-ID substitution during signature
verification and reject-after-commit behavior. The observer cannot prove
unobserved external effects.

### Valid JSON with a charset parameter (opt-in)

Enable `"acceptJsonCharsetContentType": true` to send one fresh, signed JSON
event using `Content-Type: application/json; charset=utf-8`, then retry the
identical signed ID/body/timestamp using `Content-Type: application/json`.
Both must return `successStatus`; `processedCount` must rise exactly once.
The Content-Type header is not included in this Standard Webhooks HMAC and
must not independently define the event's deduplication identity. Negative
local fixtures reject the valid parameter with 415 or reprocess a duplicate
because the media type changed. This check is independent of and composes
with the text/plain rejection check; neither asserts universal provider media
types or hidden business effects. Boolean config is validated before HTTP.

### Exact raw JSON signature bytes (opt-in)

Enable `"rawJsonSignatureBytes": true` to verify that HMAC authentication
uses the actual request bytes rather than parsed or reserialized JSON. The lab
signs a fresh pretty-printed JSON event including a final newline, then sends
the same signed ID and HMAC with compact, semantically equivalent JSON. The
receiver must accept the first delivery, reject the second with a configured
4xx without committing an effect, and accept an exact original replay without
another effect. The expected observer counts are `[+1,+1,+1]` relative to the
prior count. Three local broken receivers expose canonicalized signature
verification, cached-ID acknowledgement before authentication and
reject-after-commit. This does not claim a provider will send pretty JSON,
cover every encoding or certify unobserved external business effects.

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
