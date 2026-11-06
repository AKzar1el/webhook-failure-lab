import { randomUUID } from 'node:crypto';
import { requireLoopbackUrl } from './loopback.mjs';
import { keyFromSecret, sign } from './standard.mjs';

const DEFAULT_TIMEOUT_MS = 3000;

function checkOptions(config, secret) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw new TypeError('Config must be an object');
  }
  const endpoint = requireLoopbackUrl(config.endpoint, 'endpoint');
  const observer = requireLoopbackUrl(config.observer, 'observer');
  keyFromSecret(secret);
  const successStatus = config.successStatus ?? 200;
  const rejectionStatuses = config.rejectionStatuses ?? [400, 401, 403];
  if (!Number.isInteger(successStatus) || successStatus < 200 || successStatus > 299 ||
      !Array.isArray(rejectionStatuses) || rejectionStatuses.length === 0 ||
      rejectionStatuses.some((x) => !Number.isInteger(x) || x < 400 || x > 499)) {
    throw new TypeError('Invalid expected HTTP statuses');
  }
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) {
    throw new TypeError('timeoutMs must be between 100 and 10000');
  }
  const concurrentDuplicateDeliveries = config.concurrentDuplicateDeliveries;
  if (concurrentDuplicateDeliveries !== undefined &&
      (!Number.isInteger(concurrentDuplicateDeliveries) ||
       concurrentDuplicateDeliveries < 2 || concurrentDuplicateDeliveries > 8)) {
    throw new TypeError('concurrentDuplicateDeliveries must be an integer between 2 and 8');
  }
  const retryAfterTransientFailure = config.retryAfterTransientFailure;
  if (retryAfterTransientFailure !== undefined && typeof retryAfterTransientFailure !== 'boolean') {
    throw new TypeError('retryAfterTransientFailure must be a boolean');
  }
  return { endpoint, observer, successStatus, rejectionStatuses, timeoutMs,
    concurrentDuplicateDeliveries, retryAfterTransientFailure };
}

export async function runLab(config, { secret, request = fetch, clock = () => Math.floor(Date.now() / 1000) } = {}) {
  const options = checkOptions(config, secret);
  const reports = [];
  const timeout = () => AbortSignal.timeout(options.timeoutMs);
  const observe = async () => {
    const response = await request(options.observer, { method: 'GET', redirect: 'manual', signal: timeout() });
    if (response.status !== 200) throw new Error(`Observer returned HTTP ${response.status}`);
    const result = await response.json();
    if (!Number.isSafeInteger(result?.processedCount) || result.processedCount < 0) {
      throw new Error('Observer must return non-negative integer processedCount');
    }
    return result.processedCount;
  };
  let expectedCount = await observe();
  const now = clock();
  const id = `wfl_${randomUUID().replaceAll('-', '')}`;
  const body = JSON.stringify({ type: 'test.created', timestamp: new Date(now * 1000).toISOString(), data: { id } });

  async function deliver(name, messageId, rawBody, signedBody, timestamp, expectAccepted, change) {
    const signature = sign({ secret, id: messageId, timestamp, body: signedBody });
    const response = await request(options.endpoint, {
      method: 'POST',
      redirect: 'manual',
      signal: timeout(),
      headers: {
        'content-type': 'application/json',
        'webhook-id': messageId,
        'webhook-timestamp': String(timestamp),
        'webhook-signature': signature,
      },
      body: rawBody,
    });
    const count = await observe();
    const statusOk = expectAccepted
      ? response.status === options.successStatus
      : options.rejectionStatuses.includes(response.status);
    const countOk = count === expectedCount + change;
    const report = { scenario: name, passed: statusOk && countOk, httpStatus: response.status,
      observedProcessedCount: count, expectedProcessedCount: expectedCount + change };
    reports.push(report);
    // Advance expected baseline independently, so a failure does not mask later failures.
    expectedCount += change;
  }

  await deliver('valid_delivery', id, body, body, now, true, 1);
  await deliver('duplicate_delivery', id, body, body, now, true, 0);
  const tamperId = `wfl_${randomUUID().replaceAll('-', '')}`;
  await deliver('tampered_body', tamperId, body + ' ', body, now, false, 0);
  const staleId = `wfl_${randomUUID().replaceAll('-', '')}`;
  await deliver('stale_timestamp', staleId, body, body, now - 3600, false, 0);

  if (options.concurrentDuplicateDeliveries !== undefined) {
    const raceId = `wfl_race_${randomUUID().replaceAll('-', '')}`;
    const raceBody = JSON.stringify({ type: 'test.created', timestamp: new Date(now * 1000).toISOString(),
      data: { id: raceId } });
    const signature = sign({ secret, id: raceId, timestamp: now, body: raceBody });
    const responses = await Promise.all(Array.from({ length: options.concurrentDuplicateDeliveries }, () =>
      request(options.endpoint, {
        method: 'POST', redirect: 'manual', signal: timeout(),
        headers: { 'content-type': 'application/json', 'webhook-id': raceId,
          'webhook-timestamp': String(now), 'webhook-signature': signature },
        body: raceBody,
      })));
    const httpStatuses = responses.map((response) => response.status);
    const count = await observe();
    const expectedProcessedCount = expectedCount + 1;
    reports.push({ scenario: 'concurrent_duplicate_delivery',
      passed: httpStatuses.every((status) => status === options.successStatus) &&
        count === expectedProcessedCount,
      httpStatuses, observedProcessedCount: count, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.retryAfterTransientFailure) {
    const retryId = `wfl_retry_${randomUUID().replaceAll('-', '')}`;
    const retryBody = JSON.stringify({ type: 'test.created', timestamp: new Date(now * 1000).toISOString(),
      data: { id: retryId } });
    const retrySignature = sign({ secret, id: retryId, timestamp: now, body: retryBody });
    const headers = { 'content-type': 'application/json', 'webhook-id': retryId,
      'webhook-timestamp': String(now), 'webhook-signature': retrySignature };
    // A local test adapter must deliberately fail before processing the first valid delivery.
    const first = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { ...headers, 'x-wfl-test-fault': 'reject-before-process-once' }, body: retryBody,
    });
    const observedCountAfterFailure = await observe();
    const second = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: retryBody,
    });
    const count = await observe();
    const expectedProcessedCount = expectedCount + 1;
    reports.push({ scenario: 'retry_after_transient_failure',
      passed: first.status === 503 && observedCountAfterFailure === expectedCount &&
        second.status === options.successStatus && count === expectedProcessedCount,
      httpStatuses: [first.status, second.status], observedCountAfterFailure,
      expectedCountAfterFailure: expectedCount, observedProcessedCount: count,
      expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  return { success: reports.every((r) => r.passed), scenarios: reports,
    coverage: reports.map((report) => report.scenario),
    caveat: 'processedCount is a user-provided observer, not independently proven business-side-effect correctness' };
}
