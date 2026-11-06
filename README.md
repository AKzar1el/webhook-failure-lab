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

## Safety and scope

- The runner accepts **plain HTTP loopback endpoints only**: `127.0.0.1`, `localhost`, `[::1]`; remote production hosts and TLS are intentionally unsupported. This is a testing tool, not a generic webhook bombardment service.
- The runner never follows redirects. Network timeouts are capped at 10 seconds.
- The observer is supplied by the application author; the runner does **not independently prove** that all external side effects were absent, or support cross-process exactly-once guarantees.
- The Standard Webhooks HMAC v1 surface is narrow. GitHub's `X-Hub-Signature-256` and Stripe-specific signatures are **not implemented**, despite using HMAC.
- The opt-in checks cover concurrent duplicate delivery and one injected transient-failure retry, not cross-process or crash-safe idempotency. This MVP does not support queued retry schedules/backoff, temporal scheduling, out-of-order events, or external production testing. These should be built and verified incrementally rather than advertised prematurely.
- See [the worker charter](docs/REVENUE_SHOT.md) for bounded autonomous development instructions.

## Product direction

Differentiate from capture/replay tools by testing **correctness of committed effects** under fault scenarios. A future paid offering could include shared reports or integration policy checks, but no pricing or market demand has been established.
