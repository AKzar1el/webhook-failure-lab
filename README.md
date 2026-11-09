# Webhook Failure Lab

**Local-first webhook consumer fault-verification harness** for developers and autonomous coding workers. Uses Standard Webhooks HMAC v1 fixtures and a local observer to check whether a receiver mistakenly processes duplicated, tampered, or stale deliveries. **No paid API, browser, external network, or dependencies are required for self-test.**

## Fast verification

Requires Node.js >=22.12.0.

```sh
npm test
npm run smoke
npm run verify
```

`npm run smoke` starts a throwaway localhost mock receiver on an OS-assigned port. It produces four individual scenario results and exits without contacting any remote service.

## Integrate a local receiver

1. Run the application under test **locally** with the Standard Webhooks `whsec_` test secret from `WFL_SECRET`. Use a random synthetic key distinct from production credentials.
2. Add a read-only development-only `GET /state` endpoint reporting a `processedCount` non-negative integer. It should measure a meaningful **committed effect**, not mere request receipt. Never expose it publicly.
3. Create `lab.json`:

```json
{
  "endpoint": "http://127.0.0.1:3000/webhook",
  "observer": "http://127.0.0.1:3000/state",
  "successStatus": 200,
  "rejectionStatuses": [400, 401, 403],
  "timeoutMs": 3000
}
```

4. Run `WFL_SECRET=whsec_<base64-of-32-random-bytes> node bin/wfl.mjs run lab.json` (on Windows PowerShell set `$env:WFL_SECRET` first). `WFL_SECRET` is never displayed or included in reports.

The four initial scenarios are: valid event (count +1), **duplicate same event ID** (no extra effect), **body tampering after signing** (reject + no effect), and **signed but expired timestamp** (reject + no effect). The CLI exits 0 only if all checks pass, 1 for assertion failures, 2 for bad input/transport errors. Output is machine-readable JSON.

### CI-readable SARIF findings (opt-in output format)

Use `node bin/wfl.mjs run lab.json --format sarif` to emit SARIF 2.1.0
instead of the default JSON (or specify `--format json`). Each executed
synthetic scenario becomes a stable `WFL_*` rule; failed receiver contracts
become error findings with allowlisted HTTP statuses and observed counts.
The process exit codes remain **0** for all checks passing, **1** for any
failed receiver contract and **2** for invalid input or execution errors.
For example, a mock receiver that accepts signed ambiguous JSON generates a
`WFL_DUPLICATE_JSON_DATA_KEY_RETRY` finding, verified by a negative fixture.

With `--format sarif`, an invalid configuration, failed local observer, or
transport error also produces parseable SARIF on stdout with a failed
`executionSuccessful` invocation and a sanitized tool-execution notification.
It deliberately contains **no contract findings** because the run did not
finish; exit status remains 2. The default JSON mode retains its existing
stderr-only error behavior. Check the local configuration and observer if an
execution notification appears; it is not evidence of a failed business effect.

The SARIF does not include signing keys, raw payloads, target addresses, or
arbitrary observer strings. It intentionally does **not** fabricate repository
source-file locations for a separate webhook receiver; consumers requiring
source-anchored code-scanning alerts must supply their own location mapping.
The findings concern the **receiver-reported** count, not an independently
verified exactly-once business effect. This is a local CI artifact format, not
a deployment, workflow integration or remote upload.

### CI test-report XML (opt-in output format)

Use `node bin/wfl.mjs run lab.json --format junit` for a local JUnit-style XML
report that CI test-report viewers can ingest, with one testcase per executed
synthetic scenario. Failed receiver contracts become `<failure>` testcases
with only allowlisted HTTP statuses, counts and synthetic resource states.
A deliberately broken localhost receiver accepting signed duplicate JSON keys
produces a failed `duplicate_json_data_key_retry` testcase.

Incomplete runs instead emit one `execution` testcase with `<error>`, no
receiver-failure claim, and exit code 2. Exit codes 0/1/2 and the default JSON
mode remain unchanged. XML never contains signing keys, payloads, local URLs,
or arbitrary observer-provided strings; the exported count is still solely
receiver-reported. The CLI does not write files or upload reports; redirect
stdout to a local artifact file if your CI expects a path.

### Optional HTTP keep-alive connection isolation and cross-connection replay

Add `"keepAliveConnectionIsolation": true` to verify that a receiver handles
**two independently signed events on the same HTTP/1.1 keep-alive connection**
without merging or rejecting the second event. The harness replays the first
event on that same socket, then replays the second event using a **new TCP
connection**. All four deliveries must return `successStatus`; the local
`processedCount` observer should increment for only the two unique IDs.
The report includes `sameSocketReused` and `freshSocketUsed` booleans so a
pass cannot be inferred when connection pooling behaves differently.

Four deliberately broken loopback receivers demonstrate per-connection
event coalescing, false 409 rejection, deduplication scoped only to a socket,
and duplicate processing on a reused connection. This tests the receiver's
request isolation and reported counts, **not** durable idempotency across
process restarts or unseen external side effects. The raw Node HTTP sender
validates the loopback-only target, does not follow redirects, and uses
synthetic HMAC signing keys. Keep-alive support is an opt-in receiver contract.

### Optional mixed-case webhook header replay

Add `"mixedCaseWebhookHeaders": true` to send one valid signed JSON event
with mixed-case physical `webhook-id`, `webhook-timestamp`, and
`webhook-signature` field names, then replay its identical signed bytes
using lowercase names. Both deliveries must succeed with one reported
effect. Negative local fixtures expose header-name case-sensitive parsers,
dedupe keys improperly tied to the original field-name spelling, and
incorrect 409 responses for a valid replay.

HTTP field names are case-insensitive; the values and HMAC remain unchanged.
This opt-in check uses a raw loopback-only Node HTTP sender without redirects.
It does not assert provider-specific casing or external exactly-once effects.

### Optional chunked UTF-8 signed delivery and replay

Add `"chunkedSignedUtf8Replay": true` to validate a receiver's **HTTP
chunked-transfer parsing and raw-byte signature verification**. A synthetic
signed JSON event contains a real three-byte UTF-8 character deliberately
split across two HTTP request-body writes. The local receiver must assemble
the full body before UTF-8 decoding and HMAC verification, accept it once,
and acknowledge the **same signed bytes and event ID** sent again with
ordinary fixed-length framing without a second reported effect.

Three local negative receivers demonstrate invalid per-chunk text decoding,
rejection of an otherwise valid chunked request, and deduplication mistakenly
keyed by HTTP transfer framing. The sender uses only validated HTTP loopback
destinations, does not follow redirects, and does not expose payloads or keys
in results. Enable only for a development receiver that declares support for
chunked request bodies. This probes receiver-reported processing count, not
external exactly-once side effects; it does not stress-test arbitrary stream
sizes or network segmentation patterns.

### Optional aborted partial-body upload and signed retry

Add `"partialBodyUploadAbort": true` to send a synthetic signed JSON event
with its full `Content-Length` declared but only a prefix of the body written.
The local HTTP client then closes the socket without finishing the upload. The
receiver must not commit an effect or reserve the unverified event ID. A
subsequent **complete, identical signed request** must commit once; its exact
replay must be idempotent. The probe reports a transport error and the observer
counts after abort, retry, and replay.

Two intentionally broken localhost receivers demonstrate a cached ID from an
incomplete upload and an effect committed during that upload. This check uses
only raw HTTP to a validated loopback URL, never follows redirects, and adds no
fault header or production dependency. A bounded 100 ms observation delay
allows the local receiver to notice socket closure; it is **not** proof that
every asynchronous effect has settled, that the receiver actually consumed
every sent prefix byte, or that external business effects are exactly-once.
Enable this check only for a development receiver that exposes the count
observer and permits the synthetic retry contract.

### Optional signed malformed-body retry check

Add `"rejectMalformedSignedPayload": true` to `lab.json` to detect a
**validly signed but syntactically invalid JSON** event that poisons a receiver's
idempotency cache. The lab sends malformed JSON with a fresh event ID and a
correct HMAC; the receiver must return a configured 4xx rejection **without
committing an effect or recording the ID as processed**. It then sends a
corrected valid JSON body using the **same ID**, newly signed over its actual
bytes and the same fresh timestamp. The retry must return `successStatus`
and commit exactly one observed effect.

Three deliberately broken local receivers demonstrate accepting malformed
JSON, rejecting it after committing, and returning 400 while incorrectly
reserving its ID (thereby silently dropping the corrected retry). A missing
JSON-validation adapter also fails the test. The check is opt-in because not
every provider supports same-ID corrected retries; it exercises a declared
local receiver contract and does not prove anything about real provider
retry policies or unobserved external side effects. The existing four default
checks and loopback-only restrictions are unchanged.

### Optional duplicate JSON data-key rejection and retry

Add `"rejectDuplicateJsonDataKey": true` to check a **strict local JSON
envelope policy**. The lab sends correctly HMAC-signed, syntactically valid
JSON containing two top-level `"data"` keys with different notes, then an
independently signed variant with its second key encoded `"d\u0061ta"`.
JSON parsers decode that Unicode escape into the same logical name and often
retain only the last value. A strict receiver must return **422 for both**
before recording any observed effect or reserving the ID. The lab then sends a
corrected, independently signed single-key body with that same ID, followed
by an identical retry; both must succeed, with one total observed effect.

Deliberately broken localhost fixtures accept either ambiguous delivery,
poison the rejected ID, or return 422 after committing. This is an opt-in
synthetic policy, **not** a rule imposed by Standard Webhooks, a generic
JSON duplicate-property detector, or a provider redelivery guarantee.
The mock recognizes these narrowly constructed fixtures; a tested receiver
must implement its own robust JSON validation. The count is caller-reported
and cannot prove hidden business effects.

### Optional nested duplicate resource-ID rejection and retry

Add `"rejectDuplicateNestedResourceId": true` for a strict local JSON
policy that rejects ambiguous **nested `data.id` fields**. The lab
signs two otherwise valid JSON envelopes with the same delivery ID: one has
conflicting literal `"id"` keys inside `data`; the other
escapes the second key as `"i\u0064"`. Both must receive HTTP **422**
without reserving the signed delivery ID or recording an effect. A separately
signed, corrected single-ID body must then process once; its exact replay
must not increment the observed count.

Broken loopback receivers deliberately accept either duplicate-key shape,
poison the dedupe cache on rejection, or commit before returning 422. This is
an **opt-in synthetic receiver contract**, not a requirement of Standard
Webhooks, a generic JSON duplicate-key scanner, or evidence about a provider's
retry policy. The mock only recognizes the two constructed shapes; a real
receiver needs an actual duplicate-aware parser. Counts remain receiver-reported.

### Optional wrong media-type retry check

Add `"rejectWrongContentTypeRetry": true` to require **HTTP 415** for a
validly signed JSON body delivered with `Content-Type: text/plain`. The
receiver must neither commit an effect nor reserve that signed event ID.
The lab resends the **same ID, body, timestamp and HMAC** with
`Content-Type: application/json`, then retries it identically. Both
corrected deliveries must be acknowledged, with **one** new observed effect
overall. This catches handlers that parse any content type, poison dedupe
state on a 415 rejection, or report 415 after an unwanted effect. A missing
media-type adapter fails closed. Unlike the malformed-JSON check, the raw
body is valid JSON throughout; only the unsigned content type changes.
Enable this opt-in contract only for a local receiver that explicitly
requires JSON media type; some webhook providers legitimately use other
content types. No provider behavior or unobserved business effects are proven.

### Optional HTTP method rejection and signed POST retry

Add `"rejectWrongHttpMethodRetry": true` to test a **local-only POST-only
webhook route**. The harness sends a correctly HMAC-signed synthetic JSON
event using HTTP `PUT`. A receiver honoring this explicit contract must
respond `405 Method Not Allowed` with `Allow: POST`, without recording
an effect or reserving the event ID. A subsequent `POST` of the **identical
signed ID, timestamp and raw bytes** must process once; the exact signed
POST replay must deduplicate. HTTP method is not authenticated by this
signature, but it is part of the receiver's routing/authorization policy.

Negative loopback receivers deliberately process PUT, reserve its rejected
event ID, commit before returning 405, or omit the required Allow header.
This is not a universal webhook-provider method policy: opt in only if
your local receiver explicitly promises POST-only handling and 405.
Only the caller-reported processed count is observed; this does not prove
external exactly-once business effects.

### Optional unsupported Content-Encoding rejection and retry

Add `"rejectUnsupportedContentEncodingRetry": true` to verify a local
receiver that **does not support compressed webhook bodies**. The lab sends
correctly HMAC-signed, ordinary uncompressed JSON with the misleading
`Content-Encoding: gzip` header. The receiver must return **415** without
recording an effect or reserving the event ID. The lab then sends the exact
same signed ID, timestamp and raw body with the unsupported header removed;
the corrected delivery must process once, and its identical replay must
deduplicate. The HMAC is unchanged because Content-Encoding is not signed.

Broken localhost receivers demonstrate ignoring the declared encoding,
poisoning the rejected ID's deduplication cache, or returning 415 after an
effect. This opt-in policy is **not universal**: receivers deliberately
supporting gzip should not enable it. The fixture intentionally sends an
uncompressed body with a false encoding claim; it does not test decompression,
compressed payload signing or arbitrary encodings. The observer only reports
its own processed count, not externally guaranteed exactly-once effects.

### Optional JSON charset media-type acceptance

Add `"acceptJsonCharsetContentType": true` when your local receiver promises
to accept JSON webhook requests with
`Content-Type: application/json; charset=utf-8`. The lab sends one correctly
signed JSON event with this parameter, then repeats the **same ID, body,
timestamp and HMAC** using plain
`application/json`. Both must be acknowledged, with only one new observed
effect. This catches an exact-string media-type check that incorrectly returns
415 for valid JSON, and idempotency keyed on the unsigned Content-Type header.
It composes with `rejectWrongContentTypeRetry`, which separately requires
rejecting `text/plain`. Two broken localhost receivers prove the differences.
This tests only the declared local JSON contract; it does not infer provider
Content-Type conventions or prove unobserved external effects.

### Optional exact raw JSON signature bytes

Add `"rawJsonSignatureBytes": true` when a local receiver uses Standard Webhooks
HMAC verification over the **exact UTF-8 request body**, rather than reserialized
JSON. The lab signs a valid pretty-printed JSON payload with a trailing newline,
then sends the same event ID and HMAC with semantically identical compact JSON.
The first delivery must commit once, the changed-byte delivery must be rejected
with a configured 4xx and no new effect, and an exact replay must succeed without
an extra effect. Three deliberately broken localhost receivers demonstrate
reserializing before HMAC verification, deduplicating before authenticating the
changed bytes, and committing an effect before rejecting a tampered delivery.
This is opt-in and composes with JSON charset media-type checks. It does not
promise a provider sends pretty JSON or establish unseen external effects.

### Optional signed oversized-body rejection and retry

Add `"rejectOversizedSignedPayload": true` to test a **local development-only**
body-size policy of **1,024 UTF-8 bytes**. The lab signs a valid synthetic
JSON event containing more than 2 KiB of text; the receiver must return
**HTTP 413** without an effect or deduplication record. It then sends a
smaller JSON event with the **same ID** and a fresh valid HMAC over the
corrected bytes, followed by an identical signed replay. Both must be
acknowledged, with only one observed effect.

Broken local receivers demonstrate accepting oversized signed input, caching
the rejected ID, or returning 413 after committing an effect. An absent
size-check adapter fails the scenario. This is an explicit synthetic contract,
not a universal Standard Webhooks or provider payload limit. Enable it only
when a local receiver intentionally enforces that limit; it does not prove
provider retry behavior or unobserved business effects.

### Optional tenant-scoped signed event ID isolation

Add `"tenantScopedEventIds": true` to `lab.json`, and supply a second,
**distinct synthetic** Standard Webhooks signing key using
`WFL_TENANT_B_SECRET` (in addition to `WFL_SECRET`). Never save either key
in the JSON configuration. A **local development-only** receiver adapter must
select the appropriate tenant signing key from the synthetic
`x-wfl-test-tenant: a` or `b` header, verify the HMAC for that tenant,
and namespace idempotency keys by tenant. Do not expose this header-based
test adapter on production endpoints: the header is not a trusted identity.

The lab sends the **same event ID** with different authenticated bodies for
tenant A and tenant B. Both must be accepted with one additional observed
effect each. A tenant-A event then signed using tenant B's key must be rejected
with a configured 4xx **other than 409 Conflict**, even though tenant A's ID has already been seen,
without an additional effect. Exact signed retries for both tenants must be
acknowledged without another effect. A missing adapter fails the check.
Deliberately broken receivers expose globally keyed deduplication, false
cross-tenant collisions, exposing a cached-ID conflict before authentication,
accepting the other tenant's key, and rejection after
an unauthorized effect. The four default checks are unchanged. This is an
opt-in, synthetic tenant contract; it neither authenticates real tenants nor
proves isolation of real customer data or unobserved business-side effects.

### Optional case-sensitive signed event ID check

Add `"caseSensitiveEventIds": true` to `lab.json` to verify that a receiver
does not collapse two **independent authenticated webhook IDs** merely because
they differ in ASCII letter case. The lab sends two freshly signed events whose
IDs are identical except for a final `a` versus `A`, then retries both
events with their original signatures. All four responses must be accepted;
the observer must increment for each new ID and not for either retry.

Deliberately broken loopback receivers either silently deduplicate the second
ID by a lowercased key or reject it as an alleged collision. This opt-in
contract assumes the provider treats webhook IDs as case-sensitive opaque
strings; do not enable it for an integration that explicitly normalizes IDs.
Passing proves only receiver-reported counts, not external exactly-once effects.

### Optional prototype-property webhook ID check

Add `"prototypePropertyEventIds": true` to `lab.json` to expose an
idempotency cache implemented using an ordinary JavaScript object rather than
a `Set`, `Map`, or prototype-free dictionary. The lab signs two separate
synthetic deliveries with the literal webhook IDs `__proto__` and
`constructor`, then replays both with unchanged HMACs. A receiver declaring
this opt-in opaque-ID contract must accept each new authenticated ID once,
accept both retries, and report exactly two new effects.

Three broken localhost receivers demonstrate inherited object properties
incorrectly treated as already processed, a `__proto__` setter that does not
persist an own dedupe key and therefore reprocesses retries, and blanket 409
rejection of these IDs. The lab uses synthetic signing keys and tests
receiver-reported counters only; it does **not** execute injected code or claim
external exactly-once business effects. Some providers constrain their ID
character set: enable this test only when the receiver explicitly supports
arbitrary opaque string IDs. The option is off by default.

### Optional distinct event IDs targeting one resource

Add `"distinctEventsSameResource": true` to `lab.json` to catch receivers that
confuse a webhook **delivery ID** with the `data.id` of the business resource.
The lab independently signs a synthetic creation and update for one shared
resource ID. Both distinct event IDs must be accepted and each increment the
observer once; exact signed replays of both must be accepted without further
effects. A broken receiver can incorrectly coalesce the second event,
reject it as a conflict, or commit again on replay; all three are exercised
by negative localhost fixtures.

This is an opt-in local contract for receivers expected to act on both event
types, not a universal provider rule or proof of external business effects.
Omitting it leaves the four default scenarios unchanged.

### Optional distinct signed IDs with identical payload bytes

Add `"distinctIdsIdenticalBody": true` to `lab.json` to catch receivers that
deduplicate by a JSON body digest instead of the authenticated webhook delivery
ID. The lab sends two independently signed IDs with **exactly the same raw
JSON bytes**, then replays each unchanged signature. Both new IDs must report
an accepted delivery and increment the observer once each; neither replay
may increment it again. Broken loopback fixtures coalesce by body, reject the
second signed ID as a collision, or count exact retries as fresh effects.

This deliberately uses a synthetic `test.delivery.received` contract in which
each new signed ID represents a separately countable delivery. Enable it only
for a receiver with those semantics: some real event types intentionally
implement resource-level idempotency instead. Passing proves only the
receiver-reported count, not unobserved external effects. The option is
off by default.

### Optional concurrent duplicate race check

Add `"concurrentDuplicateDeliveries": 4` to the local `lab.json` config to also send four **simultaneous, identically signed** requests using a fresh event ID. The check requires every request to return `successStatus` and the observer count to increase by **exactly one** after all requests finish. The count can be set to an integer from 2 through 8; values outside that range are rejected before any requests are sent. Omitting it retains the original four-scenario behavior.

This detects some non-atomic read/check/write idempotency races that ordinary sequential duplicate tests miss. A deliberately broken, local-only receiver fixture is covered in `tests/integration.test.mjs`, along with a passing secure receiver. Concurrent observation still does **not** establish an exactly-once business-side-effect guarantee; it depends on the receiver's observer accurately reporting committed effects.

### Optional concurrent distinct-event processing check

Add `"concurrentDistinctDeliveries": 4` (integer **2–8**) to test the opposite concurrency invariant: **four different, independently signed event IDs must produce four observed committed effects**. The harness sends these requests together, requires every response to equal `successStatus`, then checks that the observer increased by the number of distinct events. The original four baseline scenarios remain unchanged when the option is omitted.

This catches local receivers that mistakenly coalesce unrelated events under one global in-flight deduplication key or acknowledge events without processing them while busy. Two deliberate broken fixtures exercise silent event loss and HTTP 503 rejection; both fail the scenario. It can be combined with `concurrentDuplicateDeliveries` (same ID, one effect) and the retry check. The harness does **not** infer queue fairness, production throughput, real provider retry behavior, or effects hidden from the caller-supplied observer.

### Optional deterministic transient-failure retry check

Add `"retryAfterTransientFailure": true` to `lab.json` to enable a fifth check (or a sixth if the concurrent check is also enabled). This requires an **explicit, development-only fault-injection adapter** in your local receiver. The lab sends a fresh, valid signed event with header `x-wfl-test-fault: reject-before-process-once`. The adapter must return **HTTP 503 without committing the event**; the observer count must remain unchanged. The lab then retries the **same event ID, raw body, timestamp, and signature** without the injection header. The receiver must return `successStatus` and commit exactly one observed effect. A receiver that marks an event as processed before returning 503 will fail the retry count assertion.

This check is opt-in because ordinary webhook handlers will not understand that injection header. If your handler ignores it, the lab reports a failed first-attempt status rather than silently claiming retry coverage. The built-in loopback fixture implements the adapter; its deliberately broken variant is tested in `tests/integration.test.mjs`. **Never enable fault injection on public or production handlers.** This is a controlled failed-before-processing retry, not an automatic retry scheduler, lost-acknowledgement simulation, crash-recovery proof, or exactly-once guarantee.

### Optional HTTP 429 rate-limit recovery

Set `"retryAfterRateLimit": true` for a **local synthetic throttling contract**
distinct from the HTTP 503 failure check. On the first fresh signed
`wfl_429_` delivery, the development-only receiver adapter must recognize
`x-wfl-test-fault: rate-limit-before-process-once`, return HTTP **429** with
`Retry-After: 0`, and neither commit an observed effect nor reserve the
delivery ID. The lab immediately retries the **identical signed bytes**
without the injection header; the retry must succeed once and an exact replay
must remain idempotent. The report includes only a boolean indicating whether
the required `Retry-After: 0` was present, not arbitrary response header text.

Broken loopback fixtures expose deduplication poisoning, a side effect before
the 429, missing retry guidance, or a receiver ignoring the adapter entirely.
This is a deliberately constrained zero-delay retry, **not** a general backoff
scheduler, provider rate-limit policy, traffic load test, or proof of external
exactly-once business effects. Never expose this unsigned fault header or the
observer on a production service.

### Optional committed delivery followed by HTTP 503

Add `"retryAfterCommittedError": true` to `lab.json` for a distinct **ambiguous
server-error** contract. A development-only local receiver must implement
`x-wfl-test-fault: commit-then-respond-503-once`: for the first freshly signed
`wfl_committed503_` event, commit one effect **and** its deduplication key,
then respond HTTP 503. The lab observes the committed count immediately after
that response and retries the **same signed event without the fault header**.
The retry must return `successStatus` without another observed effect.

Unlike `retryAfterTransientFailure`, the first failed HTTP response comes
**after** a commit. Unlike `lostAckAfterCommit`, the receiver actually returns
HTTP 503 rather than dropping the connection. The negative fixtures catch a
lost deduplication record, a failure before committing, and an ignored fault
adapter. Omitting the flag retains the four baseline scenarios. This is not a
general retry scheduler or proof of external exactly-once side effects. Never
enable this unsigned fault-control header or the observer on production routes.

### Optional lost acknowledgement after commit

Add `"lostAckAfterCommit": true` to local `lab.json` to simulate an **ambiguous, already-committed delivery**. This requires a separate, **development-only local adapter**: for a fresh, correctly signed event with `x-wfl-test-fault: commit-then-drop-ack-once`, the receiver must record one effect and its idempotency key, then close the HTTP connection **without sending a response**. The harness expects a transport error and observes the committed count increase by one. It then retries the **identical event ID, body, timestamp, and signature**, without the fault header, and requires an accepted response **without any second observed effect**.

The scenario fails if the adapter ignores the fault (first response succeeds) or if the receiver commits an effect but loses the matching deduplication record (replay increments the count again). Both failure modes have negative fixtures in `tests/integration.test.mjs`. It can be combined with the concurrency and transient-retry options. Omitting it retains the default four checks. The header is an intentionally unsigned local test control; implement it **only in a synthetic development harness**, never a production webhook handler. A passing result demonstrates this in-process fixture and its supplied observer, **not** durable crash/restart recovery or independently verified exactly-once business effects.

### Optional client timeout after committed delivery

Add `"timeoutAfterCommit": true` to `lab.json` to test a different ambiguous
delivery: the **client gives up waiting**, rather than the receiver closing the
connection. A local-only receiver adapter must recognize the synthetic header
`x-wfl-test-fault: commit-then-hold-ack-until-timeout` on the first signed
`wfl_timeout_` event. It must commit one observed effect and its dedupe record
**before** holding the HTTP response open past the configured `timeoutMs`
(100-10000 ms). The harness requires a real client timeout, observes the
committed count, and retries the **identical signed event** without the test
header. The retry must succeed without a second observed effect.

The built-in loopback fixture deliberately holds the response open until the
client aborts. Broken fixtures either forget the dedupe record and reprocess
the retry or ignore the delay header; both fail. This probe complements the
immediate socket drop in `lostAckAfterCommit` and the postcommit HTTP 503 test.
It does not model a real webhook provider's timeout policy, prove durability
across restarts, or independently verify external effects. Only enable the
unsigned fault-injection adapter on an isolated local test receiver; never
expose it in production.

### Optional client timeout before commit

Add `"timeoutBeforeCommit": true` to test the opposite deadline boundary.
The **local-only** adapter recognizes a fresh signed `wfl_precommit_timeout_`
event carrying `x-wfl-test-fault: hold-before-commit-until-timeout`. It must
hold the HTTP response until the client deadline **without committing an
effect or permanently reserving the event ID**. The harness observes a real
client timeout and an unchanged `processedCount`, then retries the exact signed
delivery without the fault header. The retry must commit once; an identical
third delivery must not add an effect.

The negative fixtures detect dedupe poisoning before commit, an unwanted
commit during the declared precommit fault, or an adapter that ignores the
timeout. This tests a declared synthetic **cancellation-before-commit** path,
not a claim that every real timed-out request remains uncommitted; in normal
systems a timeout can be ambiguous. Use only an isolated local test receiver,
never a production fault header. The observer is receiver-reported and does
not prove external exactly-once business effects.

### Optional out-of-order dependent-event transition check

Add `"outOfOrderStateTransitions": true` to local `lab.json` to test an explicit state machine, not merely a processed-count increment. Your **local development-only adapter** must recognize synthetic `test.resource.created` and `test.resource.activated` events sharing a `data.id` resource key. The harness sends a valid signed activation **before** the resource exists; the receiver must respond **409**, leave the observed count unchanged, and report resource state `missing`. It then sends the signed creation (HTTP `successStatus`, state `created`, count +1), followed by the **identical signed activation** previously rejected (HTTP `successStatus`, state `activated`, count +1).

The local observer must support `GET /state?resourceId=<id>` and respond with `{ "processedCount": 3, "resourceState": "activated" }` (example values); valid resource states are `missing`, `created` and `activated`. If the observer does not report a state or the receiver lacks this contract adapter, the scenario fails rather than silently passing. A broken receiver that applies activation before creation, or incorrectly marks a rejected activation as already seen, is detected by the negative fixtures in `tests/integration.test.mjs`. This opt-in scenario composes with the other checks, remains loopback-only, and is **not** proof of ordered delivery from any provider, process-restart durability, or external exactly-once effects. Do not expose the synthetic event adapter or observer publicly.

### Optional late creation replay after resource activation

Add `"delayedCreationReplayAfterActivation": true` to local `lab.json` to
catch receivers that lose ordering when an **older, already-accepted creation
event arrives again after activation**. The same development-only resource
adapter and observer described above are required. The harness sends a valid
signed `test.resource.created` event, a distinct valid signed
`test.resource.activated` event for the same resource, then a **byte-identical
signed retry of creation** (same ID, timestamp, signature and body). All three
responses must equal `successStatus`. The observer must report `created`,
`activated`, `activated` with only two additional processed effects.

Negative loopback receivers expose a replay that rewinds state, rejects a
previously accepted event with 409, or acknowledges the replay while recording
an extra effect without changing the final state. The check uses a separate
synthetic resource and composes with `outOfOrderStateTransitions`. It does not
prove long-term deduplication retention, persistence across restarts, upstream
delivery ordering or effects missing from the receiver-supplied observer.
Keep both the resource-state adapter and observer local-only.

### Optional signing-key rotation grace and retirement check

Add `"secretRotation": true` to the local configuration and supply **three distinct, synthetic Standard Webhooks keys** as environment variables: `WFL_SECRET` (current), `WFL_PREVIOUS_SECRET` (previous key still accepted during the configured grace period), and `WFL_RETIRED_SECRET` (revoked key that must no longer be accepted). Never put these secrets in `lab.json` or Git. This check requires a local receiver configured to accept the current and previous keys but reject the retired key. All three secrets are validated before sending any HTTP requests.

The runner delivers a new, valid event signed with the previous key and requires `successStatus` plus exactly one committed effect. It then delivers a **different event** signed by the retired key and requires a configured 4xx rejection with **no additional effect**. Built-in negative fixtures demonstrate detection of an unexpectedly rejected previous key, an accepted retired key, and a rejected retired key that nevertheless commits an effect. No raw key or signature is included in the result JSON. The option composes with existing scenarios and has no effect when omitted.

This is an explicit key-acceptance contract **at one moment**, not a test of clock-based rotation schedules, key storage, real provider signing, or cross-process durability. No production webhooks or credentials should be used.

### Opt-in reject retired-key replays of cached IDs

Add `"rejectRetiredKeyDuplicate": true` to `lab.json` and provide the same three
**distinct synthetic keys** used for the rotation check: `WFL_SECRET` (current),
`WFL_PREVIOUS_SECRET` (still accepted), and `WFL_RETIRED_SECRET` (revoked).
The runner first processes an event signed by the previous key and then
replays **the same ID, body, and fresh timestamp** signed by the retired key.
The cached ID must not bypass key validation: the first response must equal
`successStatus`, the second must be in `rejectionStatuses`, and the local
observer may record only the first effect. Missing or duplicate keys are
rejected **before** any local requests. The option also composes with
`secretRotation` without reusing event IDs.

Two broken loopback fixtures expose cache-first acknowledgement of a revoked
signature and a receiver that rejects after committing an extra effect.
Unlike the existing rotation check against a new ID, this tests **revocation
after an ID has already been accepted**. The receiver must enforce the
declared key policy; the test cannot prove when a real provider retires a key,
unobserved side effects, or externally guaranteed exactly-once behavior.

### Optional versioned out-of-order update check

Set `"versionedOutOfOrderUpdates": true` in local `lab.json` to verify that
a **new, correctly signed but older resource update** cannot roll back a newer
committed version. A development-only receiver adapter must accept synthetic
`test.resource.versioned` events with `data.id` and positive integer
`data.version`; `GET /state?resourceId=<id>` must report its non-negative
integer `resourceVersion` alongside `processedCount`.

The runner sends three **different authenticated event IDs** for the same
resource, in version order **1, 3, 2**. Versions 1 and 3 must return
`successStatus`, each committing one observed effect; delayed version 2
must return **409 Conflict** without committing an effect or changing the
reported resource version from 3. The local negative fixtures catch both
accepting/applying the stale update and returning 409 **after** applying it.
If the adapter or version observer is absent, the test fails rather than
claiming success. It composes with the prerequisite-activation ordering test
but is independent: no version-gapping or mandatory contiguous sequence is
assumed. This opt-in tests the declared monotonic-version application
contract, not real provider ordering or externally verified side effects.

### Opt-in receiver-process restart and durable idempotency check

Use `restartAfterCommit: true` with the **programmatic** `runLab` API and an
explicit `restartReceiver` callback owned by your local test harness. This
callback must shut down and await the original **local test receiver**, launch
a fresh process using its persisted idempotency data, and return its new
`{ endpoint, observer }` loopback URLs. The runner never executes a shell
command or restarts an application by itself. The JSON CLI intentionally has
**no process-controller capability**: configuring this flag in `lab.json`
without a programmatic callback fails before sending any requests.

The scenario sends a new valid signed event (one committed effect), reads the
receiver's `processedCount` and nonempty `receiverInstanceId`, invokes the
controller, then observes the replacement and retries the **exact same signed
event**. It requires the receiver instance identifier to change and the count
to stay unchanged through both restart and retry. A new instance with a lost
deduplication record fails even when its previous count was preserved. The
regression suite actually starts and stops separate Node child processes and
persists the synthetic receiver's count plus deduplication keys to a temporary
local file **before** HTTP acknowledgement. It also rejects a no-op restart
callback and remote endpoints returned by a controller.

This is a controlled graceful-restart contract, not a simulated sudden process
crash between disk writes, a proof of external database transactions or a
verified exactly-once business-side-effect guarantee. Both the count and
instance identifier are self-reported by the receiver. Keep process control,
the observer endpoint, and all synthetic signing secrets local to your tests.

### Opt-in abrupt receiver exit after persisted commit

Use `crashAfterPersist: true` **only through the programmatic `runLab` API**,
passing a caller-owned `recoverReceiver` callback that confirms the original
test receiver terminated and starts a new local process using the same state.
For a fresh signed event, the runner sends the development-only header
`x-wfl-test-fault: persist-then-crash-before-ack`. The test adapter must
persist its observed effect and deduplication record and exit before an HTTP
reply. The harness expects a transport error, invokes recovery, verifies a
changed `receiverInstanceId` and one durable effect, then replays the
**identical signed event** without the fault header. No extra observed effect
may occur. Both recovery URLs must use HTTP loopback.

The regression fixture exits a real local Node child with code 47 after an
awaited atomic JSON-file rename. Broken variants lose the durable dedupe key
or the effect count and are detected; an ignored fault also fails. The CLI
cannot control processes, so a missing programmatic callback fails closed.
Run `restartAfterCommit` and `crashAfterPersist` separately. Use only
synthetic keys, disposable local storage and a development-only adapter.

Optionally add `parallelCrashRecoveryRetries: 4` (integer 2-8) **together
with** `crashAfterPersist: true`. After observing the real process exit, the
runner sends concurrent copies of the exact signed event to the fresh local
receiver, checks that every request succeeds without increasing the already
committed effect count, then checks one final sequential replay. A deliberately
broken fixture drops the persisted dedupe record on restart and exposes a
check-before-write race; the observed count rises and fails the probe. This
shares the bounded retry-count option with the separate precommit test, but
the two crash modes cannot be enabled together.

This is a **post-rename process-exit** contract, not a proof of power-loss
durability, fsync, a torn multi-write database transaction, or external
exactly-once effects. Both recovery controller and observer are user-supplied.

### Opt-in crash before committing a signed delivery

Use `crashBeforeCommit: true` only with the **programmatic** `runLab` API
and a local process-controller `recoverReceiver` callback. For a fresh,
correctly signed `wfl_precrash_` event, the lab sends the development-only
`x-wfl-test-fault: crash-before-commit` header. The receiver must terminate
without an HTTP acknowledgement **before** persisting either the effect or its
deduplication record. The callback must observe the exit, launch a new process
against the same state and return loopback `{ endpoint, observer }` URLs.

The lab expects a transport error, a different `receiverInstanceId`, and an
unchanged `processedCount` after recovery. A signed retry must then commit
exactly once, while an identical replay must not commit again. The actual
localhost child-process fixture exits with code 48; broken variants persist
only the deduplication ID or an effect counter before crashing, and both fail.
Ignoring the fault or returning a non-loopback recovery URL also fails.

Set `parallelCrashRecoveryRetries: 4` (integer 2-8) **together with**
`crashBeforeCommit: true` to simulate concurrent redelivery by several workers
immediately after recovery, rather than one sequential retry. Every identical
signed retry must be acknowledged, while the observer rises by exactly one
effect in total; an additional sequential replay must remain idempotent. The
fixture includes a deliberately broken recovered process that lets two requests
both pass a stale check-before-write deduplication read, proving the probe
detects the race. The count and prerequisites are validated before HTTP traffic.

The JSON CLI cannot control local processes. Run this scenario separately
from the other restart/crash probes and retention-clock tests. Never expose
the fault adapter on a public receiver. This is a controlled pre-write
process exit, not a proof of transaction atomicity under power loss, fsync
durability, exhaustive concurrency interleavings, or any unobserved business
side effect.

### Opt-in deduplication retention and stale replay boundary

Use `retentionWindowSeconds: 60` (integer 2-240) with the **programmatic**
`runLab(config, { secret, advanceReceiverTime })` API. The callback must advance
only your isolated receiver's synthetic clock by the requested positive number
of seconds; it must not alter the system clock or send real traffic. The
scenario processes one fresh signed event, then replays the identical
event **one second before** the declared retention window expires. Both
responses must succeed, and only the first may increase the observer count.
It then advances the test receiver's clock to **301 seconds** after the
original signature timestamp and replays the unchanged signed event again.
That replay must be rejected without an additional observed effect because
its signature timestamp is stale under the 300-second tolerance.

The built-in synthetic fixture models 60-second deduplication retention and
has negative variants that (a) expire keys prematurely and (b) accept a
previously processed, stale signed event after dedupe eviction. A no-op time
controller is also detected. The JSON CLI intentionally cannot control a
receiver's clock: configuring this option there fails before any requests.
Run this test separately from the process restart and crash checks.

This tests **protection inside a stated retention window and stale-signature
rejection after it**, not whether a receiver must reprocess events after its
retention window. Longer deduplication retention is permissible; an event
replayed with a newly signed, fresh timestamp after expiry is not tested.
The observer is caller-supplied and cannot prove external exactly-once effects.
Never enable synthetic time controls on production receivers.

### Opt-in signed event-ID payload collision check

Add `"conflictingEventIdPayload": true` to the local `lab.json` to test a
**strict immutable-event-ID policy**. The runner sends a fresh signed event,
then an identical signed duplicate (both expected `successStatus`), then
a **different payload with a valid new signature but the same webhook ID**.
The third request must return **409 Conflict** without another observed
effect. A 401 signature rejection is not sufficient: both bodies are
authentically signed. The test detects receivers that silently accept
conflicting content, and receivers that return 409 only after committing.

This rule is an explicit application contract, **not a property of every
webhook provider**. Enable it only for a local receiver that promises
immutable payloads per delivery ID and supports 409 for a conflict. It
does not prove the absence of unobserved external effects.

### Opt-in concurrent conflicting-payload race

Add `"concurrentConflictingEventIdPayload": true` to `lab.json` to send two
**different, independently and correctly signed payloads with the same new
delivery ID** concurrently. The receiver must return one `successStatus`
and one **409 Conflict**, in either order, and its observer count must rise by
exactly one. This detects a check-then-insert idempotency race that can evade
the sequential collision check, as well as silent acknowledgement or
reject-after-commit defects. The local regression suite contains fixtures for
all three bugs. The option composes with both concurrent duplicate and
concurrent distinct-event checks; without the option, the default four checks
are unchanged.

Only enable this **strict, atomic event-ID immutability contract** when your
local receiver promises 409 for an authenticated collision. Two concurrent
requests are a bounded race probe, not proof that every possible scheduling
interleaving has been explored. The observer remains caller-controlled and
cannot establish exactly-once external business effects.

### Opt-in freshly re-signed duplicate delivery

Add `"resignedDuplicateDelivery": true` to `lab.json` to check an event-ID-based
idempotency contract when a retry has the **same event ID and identical body**
but a different, independently valid signing timestamp and HMAC signature.
Both deliveries must return `successStatus`; the first increases the observed
processed count by one and the re-signed retry must not increase it again.
This is distinct from the default byte-identical retry and from the strict
event-ID payload conflict check (which sends a *changed* body).

The built-in synthetic negative receivers detect both signature-keyed
deduplication (a duplicate committed twice) and rejection of a valid
re-signature (HTTP 409). The timestamps differ by one second, without waiting
or changing system time. This opt-in contract is appropriate only when the
receiver/provider explicitly permits re-signing the same delivery ID;
it does **not** prove that any particular provider actually re-signs retries,
nor that unobserved business-side effects occur exactly once.

### Opt-in future-dated signed timestamp rejection

Add `"rejectFutureSignedTimestamp": true` to `lab.json` to verify that a
receiver checks **both sides** of its signing-timestamp freshness window.
The runner sends a fresh synthetic event whose HMAC is correctly signed for
a `webhook-timestamp` **one hour in the future** relative to the runner clock.
The local receiver must return one of the configured `rejectionStatuses` and
must not increase the observed processed count. This is separate from the
baseline's expired timestamp in the past; it catches code that checks only
`now - signedTimestamp > tolerance` and accidentally accepts future events.

Two deliberately broken local receivers demonstrate acceptance of a future
signature and rejection **after** recording an effect. Neither needs a real
clock change or external traffic. The contract assumes a receiver using a
300-second Standard Webhooks timestamp tolerance and reasonably synchronized
clocks; significant local clock skew can fail the check even if the HMAC
implementation is correct. It does not prove any unobserved business effects.

### Opt-in exact signed-timestamp header check

Add `"rejectNoncanonicalTimestamp": true` to `lab.json` to detect receivers
that parse the signed `webhook-timestamp` as a number **before verifying its
original bytes**. The runner signs two independent synthetic events using a
fresh canonical integer timestamp, then alters only their transmitted timestamp
headers to a leading-zero form and a decimal `.0` form. Although those strings
convert to the same number, neither is authenticated by the original HMAC.
Both deliveries must be rejected with a configured 4xx status and cause no
observed effect. No body or signing key is changed.

The built-in verifier now rejects noncanonical timestamp strings instead of
silently normalizing them. Two deliberately broken local receivers prove the
probe catches normalized-header acceptance and rejection after committing.
This does not impose rules on other webhook protocols, prove real provider
formatting, or establish exactly-once external business effects.

### Opt-in authenticate-before-deduplication check

Add `"rejectTamperedDuplicateSignature": true` to `lab.json` to check a
different failure mode from the default tampered-body test. The runner first
sends a valid signed event, then resends its **identical ID, timestamp and raw
body with one character changed in the HMAC digest**. The second delivery must
be rejected with a configured 4xx status, while the observed processed count
remains unchanged. A receiver that trusts a previously processed ID before
verifying its latest signature may silently return 200. Another deliberately
broken local fixture rejects the invalid replay only after committing a second
effect; both regressions are detected. This option composes with re-signed
duplicate and strict payload-collision checks without extra credentials,
dependencies or external traffic.

The test verifies an observable signature-validation ordering contract for a
local Standard Webhooks receiver. It is not a proof of side effects outside
the caller-provided observer or an exactly-once guarantee.

### Opt-in freshness-before-deduplication check

Add `"rejectStaleDuplicateSignature": true` to `lab.json` to catch receivers
that return a success response for a **cached webhook ID before checking the
timestamp freshness of the incoming signed replay**. The runner accepts a
fresh signed event, then resends the same ID and byte-identical body with a
second, correctly calculated HMAC covering a timestamp one hour in the past.
The second request must be rejected with a configured 4xx response and must
not record a second observed effect. The scenario does not change the system
clock or wait for a signature to expire.

Two deliberately broken fixtures demonstrate stale cached-ID acceptance and
rejection after committing a second effect. Unlike the baseline stale event,
this replay has a **previously accepted** event ID; unlike the tampered-HMAC
check, both HMACs are authentic. The opt-in contract assumes a 300-second
Standard Webhooks tolerance and reasonably synchronized clocks. As with all
other checks, the observer is caller-supplied and cannot establish the absence
of unobserved business side effects.

### Opt-in authenticate-before-collision classification

Add `"rejectUnauthenticatedCollision": true` to `lab.json` to verify the
receiver does not classify a *different, unauthenticated body* as a signed
event-ID conflict. The runner delivers a valid signed event, then changes the
body while reusing the same event ID and original HMAC. The second body must
be rejected with one of `rejectionStatuses`, **excluding HTTP 409**, and
must not increase the observed count. The 409 exclusion still applies if it
is included in your custom rejection status list. Unlike the opt-in signed
collision check, the new body has no valid signature; unlike the duplicate
authentication check, its raw bytes have changed.

Two intentionally broken loopback receivers demonstrate collision checking
before HMAC verification (409) and rejection after committing an effect (401
but an increased count). This is a local authentication-ordering contract,
not proof of all unobserved effects or universal provider webhook behavior.

### Opt-in multiple HMAC signatures in one header

Add `"multiSignatureHeader": true` to `lab.json` to verify a Standard
Webhooks receiver can validate a **space-separated list of v1 signatures**.
The runner sends a fresh event with a deliberately incorrect signature first
and the valid signature second, then an identical event with the valid token
first. Both responses must equal `successStatus`, but only the first may
record an observed effect. It then sends a different event with **two invalid
signatures**, requiring a configured 4xx rejection and no effect.

The negative fixtures model first-token-only verification, accepting an
all-invalid signature list, and rejecting only after committing an effect.
This is useful for receivers supporting multiple signatures during key
rotation, but does not simulate real provider rotation timing or validate
provider-specific signature schemes. The baseline four checks remain unchanged
when omitted. Only local synthetic secrets and loopback HTTP are used; the
observer cannot prove the absence of unobserved external effects.

### Opt-in signed webhook ID integrity test

Set `"rejectTamperedEventId": true` in a local `lab.json` to confirm that
a Standard Webhooks receiver authenticates the actual `webhook-id` header.
The test sends a valid signed event and then resends its unchanged body,
timestamp and signature with **only the header ID modified**. The forged
request must be rejected with a configured 4xx status without any additional
receiver-reported processing effect.

Negative localhost fixtures detect receivers that substitute the JSON body's
ID during HMAC verification or commit an effect before rejecting the forged
header. This is opt-in and uses synthetic secrets and loopback requests only;
it cannot establish the absence of unobserved external side effects.

### Opt-in retry after rejected invalid signature

Set `"retryAfterRejectedSignature": true` in local `lab.json`. The lab sends
an event with a deliberately corrupted HMAC digest, then retries the **same
event ID, timestamp and JSON body** with its authentic signature, followed by
an identical valid replay. A compliant receiver rejects the first attempt
without an observed effect or deduplication record, accepts and processes the
corrected delivery once, and acknowledges the replay without processing it
again. Expected responses are a configured 4xx, then `successStatus` twice.

Broken loopback fixtures detect caching the rejected event ID, committing
before returning 401, and accepting the invalid first signature. This is
distinct from testing a tampered **already-processed** duplicate: it verifies
recovery after an **unauthenticated first delivery**. No external endpoints,
production keys or real retry scheduling are used. Receiver-reported counts
do not establish unobserved business-side-effect guarantees.

### Opt-in retry after missing signature header

Set `"rejectMissingSignatureRetry": true` in local `lab.json` to require a
receiver to reject an event that has a valid synthetic ID, timestamp and JSON
body but **no `webhook-signature` header**. The first response must be a
configured 4xx without an observed effect or reserved deduplication ID. The
harness then sends the exact same body and ID with a valid HMAC, followed by
an identical signed replay. Both signed deliveries must be acknowledged with
only one new observed effect. Negative localhost fixtures catch acceptance
without a signature, ID poisoning on rejection and rejection after a commit.
Unlike the invalid-HMAC retry, this checks *absent* authentication metadata.
This is an opt-in local adapter contract, not proof of a provider's redelivery
policy or unseen external side effects.

### Opt-in unsupported signature-version rejection

Set `"rejectUnsupportedSignatureVersion": true` in local `lab.json`.
The harness sends a fresh signed JSON event with a `webhook-signature`
containing the correct HMAC digest but an unsupported `v2,` prefix instead
of `v1,`. A strict Standard Webhooks v1 receiver must reject it with a
configured 4xx **before** reserving the delivery ID or recording an effect.
The harness then retries the same ID, timestamp and body with the correct
`v1,` signature and replays it. Both valid requests must succeed with only
one additional receiver-reported processing effect.

Three deliberately broken localhost receivers detect checking the digest
while ignoring its version prefix, poisoning the rejected event's dedupe
record, and recording an effect before rejection. This opt-in contract
tests **v1-only** verification; it does not rule out a deliberately supported
future signature algorithm, prove a provider retry policy, or guarantee
unobserved external business effects. No production traffic or keys are used.

### Opt-in retry after missing signed timestamp

Set `"rejectMissingTimestampRetry": true` to require that a local webhook
receiver rejects a request missing `webhook-timestamp`, even when its ID,
body and `webhook-signature` were prepared using a valid synthetic timestamp.
The first request must return a configured 4xx, without committing an effect
or reserving the ID. The lab then sends the exact same body, ID and HMAC
**with** the signed timestamp header, followed by an identical replay.
Both corrected deliveries must be accepted, with only one new observed effect.
Broken localhost fixtures detect missing-timestamp acceptance, rejected-ID
poisoning and reject-after-commit behavior. This is distinct from a missing
signature: an HMAC header alone does not supply authenticated freshness.
The opt-in check tests only a declared local receiver contract; it cannot
prove a provider's retry policy or unobserved external side effects.

### Opt-in retry after missing signed event ID

Set `"rejectMissingEventIdRetry": true` to check that a local receiver
rejects a signed webhook delivery without the `webhook-id` header, even
when the JSON body contains an event ID and the HMAC was computed using it.
The missing-header request must return a configured 4xx without recording
an effect or reserving the body ID. A corrected delivery with the exact
same body, timestamp and signature, but with the signed ID header restored,
must commit once; an identical replay must be idempotent.

Three deliberately broken localhost receivers trust the unauthenticated
body ID in place of the wire header, reserve the body ID on rejection, or
commit an effect before returning 401. This opt-in contract assumes a local
Standard Webhooks receiver expecting the `webhook-id` header. A JSON
`data.id` is not a substitute for the signature's event-ID input. The
scenario does not establish provider retry policy or invisible business
effects and does not contact an external endpoint.

### Opt-in duplicate wire event-ID rejection and retry

Set `"rejectDuplicateWireEventIdRetry": true` to detect receivers that
trust the first of two **physical** `webhook-id` HTTP header fields. The lab
uses a direct Node HTTP loopback request (not fetch, which combines duplicate
fields) with a valid signature for the first ID and a different second ID.
The receiver must reject this ambiguous request with a configured 4xx
before any effect or deduplication write. A corrected request with a single
signed ID field and exactly the same body, timestamp and signature must
commit once, and an identical replay must not commit again.

The localhost negative fixtures model first-header-wins authentication,
poisoning the rejected ID's deduplication cache, and committing before
rejecting. This is a declared strict-header policy for a local Standard
Webhooks receiver, not a universal guarantee about provider HTTP stacks or
proxy handling. No redirects or non-loopback destinations are contacted;
the observer still cannot prove external exactly-once effects.

### Opt-in duplicate wire timestamp rejection and retry

Set `"rejectDuplicateWireTimestampRetry": true` to detect receivers that
trust just one of two **physical** `webhook-timestamp` HTTP fields. The
lab sends a fresh timestamp signed by the synthetic key plus an additional
stale timestamp field in **both physical-field orders** through direct Node
HTTP loopback requests. A local receiver enforcing single-valued signed
timestamps must reject the ambiguous
header set with a configured 4xx **without** a committed effect or dedupe
record, then accept a corrected same-ID, same-body, same-HMAC delivery with
only the fresh timestamp once. An identical retry must remain idempotent.

Negative fixtures demonstrate first/last-field-wins authentication, rejected-ID
cache poisoning, and reject-after-commit. This opt-in strict-wire-header
policy is not guaranteed by every proxy or provider; it tests a synthetic
local receiver, not hidden external side effects. Redirects are not followed,
and webhook traffic remains HTTP loopback-only.

### Opt-in duplicate wire signature rejection and retry

Set `"rejectDuplicateWireSignatureRetry": true` for a **strict single
physical `webhook-signature` header** contract. The lab sends a valid v1 HMAC
and a corrupted v1 HMAC as two separate HTTP fields, in both field orders.
The local receiver must reject both ambiguous requests with a configured 4xx,
without an observed effect or reserved ID. A corrected single-header delivery
of the same signed bytes must commit once, and its identical replay must dedupe.

Local negative receivers that trust the first or last physical field, poison
the rejected ID cache, or commit before rejecting are all detected. This is
**different** from `"multiSignatureHeader": true`, which deliberately allows
multiple space-separated signatures **inside one physical header field**.
The strict policy is opt-in because providers and intermediaries can differ.
Only loopback HTTP and synthetic HMAC keys are used; reported processing
counts cannot establish external exactly-once business effects.

### Opt-in conflicting physical Content-Type rejection and retry

Set `"rejectDuplicateWireContentTypeRetry": true` to test a receiver's
**strict single-valued media-type policy**. The harness sends two physical
`Content-Type` fields, one `application/json` and one `text/plain`, in
both orders with an otherwise valid signed JSON event. Both ambiguous
requests must receive a configured 4xx without an observed effect or a
deduplication write. A single `application/json` header with the original
signed body and event ID must then process once; its exact replay must dedupe.

Four deliberately broken localhost receivers detect first- or last-field
trust, rejected-ID cache poisoning, and rejection after a committed effect.
The raw HTTP sender preserves two physical header fields; the ordinary fetch
client cannot represent that wire shape. This is an **opt-in local receiver
contract**, not a universal Standard Webhooks or HTTP mandate for duplicate
media-type handling. Only loopback traffic and synthetic HMAC material are
used, and the observer cannot prove external business-side-effect absence.

### Opt-in conflicting physical Content-Encoding rejection and retry

Set `"rejectDuplicateWireContentEncodingRetry": true` to test a **strict
single-valued encoding policy**. A valid signed JSON body is sent with two
physical `Content-Encoding` fields (`identity` and `gzip`) in both wire orders.
Both ambiguous requests must receive a configured 4xx, with no observed
effect or cached event ID. Removing both fields and retrying the exact signed
event must commit once; an identical replay must not increment the count.

Four deliberately broken local receivers trust the first or last physical
field, reserve the rejected ID, or commit before rejecting. The uncompressed
bytes are never actually gzip-compressed, so the fixture tests header handling
and deduplication, not decompression. This is an **opt-in local policy**, not a
universal requirement imposed on every provider or intermediary. Only
loopback requests and synthetic keys are used; the observer cannot certify
unobserved external business effects.

### Opt-in invalid UTF-8 signed JSON recovery

Set `"rejectInvalidUtf8Retry": true` to detect webhook receivers that
authenticate a JSON payload but silently replace malformed UTF-8 bytes before
processing it. The lab sends JSON containing an invalid byte **inside a JSON
string** and computes a valid Standard Webhooks HMAC over the exact raw bytes.
The receiver must reject the delivery with a configured 4xx, without recording
an effect or reserving the event ID. A corrected, independently signed UTF-8
body using the **same ID** must commit once; an identical replay must dedupe.

Broken localhost fixtures accept lossy Unicode replacement, poison dedupe on
rejection, or commit before returning 400. The local mock buffers request bytes
before UTF-8 decoding and validates this probe with a fatal decoder. This
opt-in rule applies to receivers that require UTF-8 JSON; it is not a universal
provider redelivery contract. All traffic is loopback-only, and the observer
cannot establish hidden business-effect correctness.

### Opt-in delayed HTTP 202 acknowledgement and duplicate processing

Set "asyncAckDelivery": true to verify a local receiver that acknowledges
signed events with **HTTP 202** and processes them later. Two identical signed
deliveries are sent concurrently before the synthetic worker completes.
After a bounded settlement window, the observer must report **one** new
processed event. A third exact signed replay must also return 202 without
recording another event. Use "asyncAckWaitMs": 1000 (default; integer
100-5000) to define how long the harness allows an asynchronous worker to
finish before checking its observer.

Broken local receivers acknowledge but drop queued work, record two effects
for one job, or enqueue each concurrent copy without reserving its ID.
The fixture uses an **in-memory** delayed worker and does not establish
durable queue persistence, process-crash recovery, real provider delivery
timing, or external exactly-once effects. Only one observation after the
settlement window is asserted: a job completing later can change reality
after the test. Enable this contract only for a receiver exposing the local
processed-count adapter and an intentional 202 asynchronous response.

## Safety and scope

- The runner accepts **plain HTTP loopback endpoints only**: `127.0.0.1`, `localhost`, `[::1]`; remote production hosts and TLS are intentionally unsupported. This is a testing tool, not a generic webhook bombardment service.
- The runner never follows redirects. Network timeouts are capped at 10 seconds.
- The observer is supplied by the application author; the runner does **not independently prove** that all external side effects were absent or that real-world exactly-once guarantees hold.
- The Standard Webhooks HMAC v1 surface is narrow. GitHub's `X-Hub-Signature-256` and Stripe-specific signatures are **not implemented**, despite using HMAC.
- The opt-in checks cover concurrent duplicate delivery and concurrent distinct-event processing, injected retries after both pre-commit HTTP 503 and post-commit HTTP 503, a committed event whose HTTP acknowledgement is lost, a synthetic dependent-event state transition delivered out of order, signing-key acceptance during an explicit rotation grace/retirement state and rejection of retired-key replays with cached IDs, a controlled receiver restart, a post-persistence abrupt receiver exit, controlled synthetic-clock dedupe retention/freshness replay (the last three programmatic-only), strict signed event-ID payload conflict handling, changed-body unauthenticated collision rejection, same-ID re-signed retries, future-dated signature rejection, duplicate authentication before deduplication, timestamp freshness before cached-ID deduplication, and multiple HMACs in a single signature header. No scenario proves power-loss safety or external exactly-once effects. This MVP does not support queued retry schedules/backoff, real temporal scheduling, arbitrary provider-specific event-order contracts, or external production testing.
- See [the worker charter](docs/REVENUE_SHOT.md) for bounded autonomous development instructions.

## Product direction

Differentiate from capture/replay tools by testing **correctness of committed effects** under fault scenarios. A future paid offering could include shared reports or integration policy checks, but no pricing or market demand has been established.
