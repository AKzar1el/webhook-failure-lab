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

### Optional concurrent duplicate race check

Add `"concurrentDuplicateDeliveries": 4` to the local `lab.json` config to also send four **simultaneous, identically signed** requests using a fresh event ID. The check requires every request to return `successStatus` and the observer count to increase by **exactly one** after all requests finish. The count can be set to an integer from 2 through 8; values outside that range are rejected before any requests are sent. Omitting it retains the original four-scenario behavior.

This detects some non-atomic read/check/write idempotency races that ordinary sequential duplicate tests miss. A deliberately broken, local-only receiver fixture is covered in `tests/integration.test.mjs`, along with a passing secure receiver. Concurrent observation still does **not** establish an exactly-once business-side-effect guarantee; it depends on the receiver's observer accurately reporting committed effects.

### Optional deterministic transient-failure retry check

Add `"retryAfterTransientFailure": true` to `lab.json` to enable a fifth check (or a sixth if the concurrent check is also enabled). This requires an **explicit, development-only fault-injection adapter** in your local receiver. The lab sends a fresh, valid signed event with header `x-wfl-test-fault: reject-before-process-once`. The adapter must return **HTTP 503 without committing the event**; the observer count must remain unchanged. The lab then retries the **same event ID, raw body, timestamp, and signature** without the injection header. The receiver must return `successStatus` and commit exactly one observed effect. A receiver that marks an event as processed before returning 503 will fail the retry count assertion.

This check is opt-in because ordinary webhook handlers will not understand that injection header. If your handler ignores it, the lab reports a failed first-attempt status rather than silently claiming retry coverage. The built-in loopback fixture implements the adapter; its deliberately broken variant is tested in `tests/integration.test.mjs`. **Never enable fault injection on public or production handlers.** This is a controlled failed-before-processing retry, not an automatic retry scheduler, lost-acknowledgement simulation, crash-recovery proof, or exactly-once guarantee.

### Optional lost acknowledgement after commit

Add `"lostAckAfterCommit": true` to local `lab.json` to simulate an **ambiguous, already-committed delivery**. This requires a separate, **development-only local adapter**: for a fresh, correctly signed event with `x-wfl-test-fault: commit-then-drop-ack-once`, the receiver must record one effect and its idempotency key, then close the HTTP connection **without sending a response**. The harness expects a transport error and observes the committed count increase by one. It then retries the **identical event ID, body, timestamp, and signature**, without the fault header, and requires an accepted response **without any second observed effect**.

The scenario fails if the adapter ignores the fault (first response succeeds) or if the receiver commits an effect but loses the matching deduplication record (replay increments the count again). Both failure modes have negative fixtures in `tests/integration.test.mjs`. It can be combined with the concurrency and transient-retry options. Omitting it retains the default four checks. The header is an intentionally unsigned local test control; implement it **only in a synthetic development harness**, never a production webhook handler. A passing result demonstrates this in-process fixture and its supplied observer, **not** durable crash/restart recovery or independently verified exactly-once business effects.

### Optional out-of-order dependent-event transition check

Add `"outOfOrderStateTransitions": true` to local `lab.json` to test an explicit state machine, not merely a processed-count increment. Your **local development-only adapter** must recognize synthetic `test.resource.created` and `test.resource.activated` events sharing a `data.id` resource key. The harness sends a valid signed activation **before** the resource exists; the receiver must respond **409**, leave the observed count unchanged, and report resource state `missing`. It then sends the signed creation (HTTP `successStatus`, state `created`, count +1), followed by the **identical signed activation** previously rejected (HTTP `successStatus`, state `activated`, count +1).

The local observer must support `GET /state?resourceId=<id>` and respond with `{ "processedCount": 3, "resourceState": "activated" }` (example values); valid resource states are `missing`, `created` and `activated`. If the observer does not report a state or the receiver lacks this contract adapter, the scenario fails rather than silently passing. A broken receiver that applies activation before creation, or incorrectly marks a rejected activation as already seen, is detected by the negative fixtures in `tests/integration.test.mjs`. This opt-in scenario composes with the other checks, remains loopback-only, and is **not** proof of ordered delivery from any provider, process-restart durability, or external exactly-once effects. Do not expose the synthetic event adapter or observer publicly.

### Optional signing-key rotation grace and retirement check

Add `"secretRotation": true` to the local configuration and supply **three distinct, synthetic Standard Webhooks keys** as environment variables: `WFL_SECRET` (current), `WFL_PREVIOUS_SECRET` (previous key still accepted during the configured grace period), and `WFL_RETIRED_SECRET` (revoked key that must no longer be accepted). Never put these secrets in `lab.json` or Git. This check requires a local receiver configured to accept the current and previous keys but reject the retired key. All three secrets are validated before sending any HTTP requests.

The runner delivers a new, valid event signed with the previous key and requires `successStatus` plus exactly one committed effect. It then delivers a **different event** signed by the retired key and requires a configured 4xx rejection with **no additional effect**. Built-in negative fixtures demonstrate detection of an unexpectedly rejected previous key, an accepted retired key, and a rejected retired key that nevertheless commits an effect. No raw key or signature is included in the result JSON. The option composes with existing scenarios and has no effect when omitted.

This is an explicit key-acceptance contract **at one moment**, not a test of clock-based rotation schedules, key storage, real provider signing, or cross-process durability. No production webhooks or credentials should be used.

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

This is a **post-rename process-exit** contract, not a proof of power-loss
durability, fsync, a torn multi-write database transaction, or external
exactly-once effects. Both recovery controller and observer are user-supplied.

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

## Safety and scope

- The runner accepts **plain HTTP loopback endpoints only**: `127.0.0.1`, `localhost`, `[::1]`; remote production hosts and TLS are intentionally unsupported. This is a testing tool, not a generic webhook bombardment service.
- The runner never follows redirects. Network timeouts are capped at 10 seconds.
- The observer is supplied by the application author; the runner does **not independently prove** that all external side effects were absent or that real-world exactly-once guarantees hold.
- The Standard Webhooks HMAC v1 surface is narrow. GitHub's `X-Hub-Signature-256` and Stripe-specific signatures are **not implemented**, despite using HMAC.
- The opt-in checks cover concurrent duplicate delivery, one injected transient-failure retry, a committed event whose HTTP acknowledgement is lost, a synthetic dependent-event state transition delivered out of order, signing-key acceptance during an explicit rotation grace/retirement state, a controlled receiver restart, a post-persistence abrupt receiver exit, controlled synthetic-clock dedupe retention/freshness replay (the last three programmatic-only), and strict signed event-ID payload conflict handling. No scenario proves power-loss safety or external exactly-once effects. This MVP does not support queued retry schedules/backoff, real temporal scheduling, arbitrary provider-specific event-order contracts, or external production testing.
- See [the worker charter](docs/REVENUE_SHOT.md) for bounded autonomous development instructions.

## Product direction

Differentiate from capture/replay tools by testing **correctness of committed effects** under fault scenarios. A future paid offering could include shared reports or integration policy checks, but no pricing or market demand has been established.
