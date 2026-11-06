import { randomUUID } from 'node:crypto';
import { requireLoopbackUrl } from './loopback.mjs';
import { keyFromSecret, sign } from './standard.mjs';

const DEFAULT_TIMEOUT_MS = 3000;

function checkOptions(config, secret, previousSecret, retiredSecret) {
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
  const lostAckAfterCommit = config.lostAckAfterCommit;
  if (lostAckAfterCommit !== undefined && typeof lostAckAfterCommit !== 'boolean') {
    throw new TypeError('lostAckAfterCommit must be a boolean');
  }
  const outOfOrderStateTransitions = config.outOfOrderStateTransitions;
  if (outOfOrderStateTransitions !== undefined && typeof outOfOrderStateTransitions !== 'boolean') {
    throw new TypeError('outOfOrderStateTransitions must be a boolean');
  }
  const secretRotation = config.secretRotation;
  if (secretRotation !== undefined && typeof secretRotation !== 'boolean') {
    throw new TypeError('secretRotation must be a boolean');
  }
  const restartAfterCommit = config.restartAfterCommit;
  if (restartAfterCommit !== undefined && typeof restartAfterCommit !== 'boolean') {
    throw new TypeError('restartAfterCommit must be a boolean');
  }
  const crashAfterPersist = config.crashAfterPersist;
  if (crashAfterPersist !== undefined && typeof crashAfterPersist !== 'boolean') {
    throw new TypeError('crashAfterPersist must be a boolean');
  }
  const retentionWindowSeconds = config.retentionWindowSeconds;
  if (retentionWindowSeconds !== undefined &&
      (!Number.isInteger(retentionWindowSeconds) || retentionWindowSeconds < 2 ||
       retentionWindowSeconds > 240)) {
    throw new TypeError('retentionWindowSeconds must be an integer between 2 and 240');
  }
  if (crashAfterPersist && restartAfterCommit) {
    throw new TypeError('crashAfterPersist and restartAfterCommit require separate runs');
  }
  if (retentionWindowSeconds !== undefined && (crashAfterPersist || restartAfterCommit)) {
    throw new TypeError('retentionWindowSeconds and process controllers require separate runs');
  }
  if (secretRotation) {
    keyFromSecret(previousSecret);
    keyFromSecret(retiredSecret);
    if (new Set([secret, previousSecret, retiredSecret]).size !== 3) {
      throw new TypeError('Rotation requires three distinct signing keys');
    }
  }
  return { endpoint, observer, successStatus, rejectionStatuses, timeoutMs,
    concurrentDuplicateDeliveries, retryAfterTransientFailure, lostAckAfterCommit,
    outOfOrderStateTransitions, secretRotation, restartAfterCommit, crashAfterPersist,
    retentionWindowSeconds };
}

export async function runLab(config, { secret, previousSecret, retiredSecret,
  restartReceiver, recoverReceiver, advanceReceiverTime, request = fetch,
  clock = () => Math.floor(Date.now() / 1000) } = {}) {
  const options = checkOptions(config, secret, previousSecret, retiredSecret);
  if (options.restartAfterCommit && typeof restartReceiver !== 'function') {
    throw new TypeError('restartReceiver must be a local process-controller function');
  }
  if (options.crashAfterPersist && typeof recoverReceiver !== 'function') {
    throw new TypeError('recoverReceiver must be a local crashed-process recovery function');
  }
  if (options.retentionWindowSeconds !== undefined && typeof advanceReceiverTime !== 'function') {
    throw new TypeError('advanceReceiverTime must be a local synthetic time-controller function');
  }
  const reports = [];
  const timeout = () => AbortSignal.timeout(options.timeoutMs);
  const observeState = async (resourceId, observerUrl = options.observer) => {
    const target = new URL(observerUrl);
    if (resourceId !== undefined) target.searchParams.set('resourceId', resourceId);
    const response = await request(target, { method: 'GET', redirect: 'manual', signal: timeout() });
    if (response.status !== 200) throw new Error(`Observer returned HTTP ${response.status}`);
    const result = await response.json();
    if (!Number.isSafeInteger(result?.processedCount) || result.processedCount < 0) {
      throw new Error('Observer must return non-negative integer processedCount');
    }
    return result;
  };
  const observe = async () => (await observeState()).processedCount;
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

  if (options.lostAckAfterCommit) {
    const lostAckId = `wfl_lostack_${randomUUID().replaceAll('-', '')}`;
    const lostAckBody = JSON.stringify({ type: 'test.created', timestamp: new Date(now * 1000).toISOString(),
      data: { id: lostAckId } });
    const lostAckSignature = sign({ secret, id: lostAckId, timestamp: now, body: lostAckBody });
    const headers = { 'content-type': 'application/json', 'webhook-id': lostAckId,
      'webhook-timestamp': String(now), 'webhook-signature': lostAckSignature };
    // This opt-in local adapter commits the event, then closes the connection before HTTP acknowledgement.
    let firstAttemptOutcome;
    try {
      const first = await request(options.endpoint, {
        method: 'POST', redirect: 'manual', signal: timeout(),
        headers: { ...headers, 'x-wfl-test-fault': 'commit-then-drop-ack-once' }, body: lostAckBody,
      });
      firstAttemptOutcome = `http_${first.status}`;
    } catch {
      firstAttemptOutcome = 'transport_error';
    }
    const observedCountAfterLostAck = await observe();
    const retry = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: lostAckBody,
    });
    const count = await observe();
    const expectedProcessedCount = expectedCount + 1;
    reports.push({ scenario: 'lost_ack_after_commit',
      passed: firstAttemptOutcome === 'transport_error' &&
        observedCountAfterLostAck === expectedProcessedCount &&
        retry.status === options.successStatus && count === expectedProcessedCount,
      firstAttemptOutcome, observedCountAfterLostAck, retryHttpStatus: retry.status,
      observedProcessedCount: count, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.outOfOrderStateTransitions) {
    const resourceId = `wfl_resource_${randomUUID().replaceAll('-', '')}`;
    const eventTime = new Date(now * 1000).toISOString();
    const makeOrderEvent = (type, name) => {
      const messageId = `wfl_order_${name}_${randomUUID().replaceAll('-', '')}`;
      const rawBody = JSON.stringify({ type, timestamp: eventTime, data: { id: resourceId } });
      return { rawBody, headers: {
        'content-type': 'application/json', 'webhook-id': messageId,
        'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret, id: messageId, timestamp: now, body: rawBody }),
      } };
    };
    const create = makeOrderEvent('test.resource.created', 'create');
    const activate = makeOrderEvent('test.resource.activated', 'activate');
    const send = (event) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: event.headers, body: event.rawBody,
    });
    // Retry the exact activation event after its prerequisite is created.
    const first = await send(activate);
    const afterFirst = await observeState(resourceId);
    const second = await send(create);
    const afterCreate = await observeState(resourceId);
    const third = await send(activate);
    const afterActivation = await observeState(resourceId);
    const httpStatuses = [first.status, second.status, third.status];
    const observedCounts = [afterFirst.processedCount, afterCreate.processedCount,
      afterActivation.processedCount];
    const observedResourceStates = [afterFirst.resourceState ?? null,
      afterCreate.resourceState ?? null, afterActivation.resourceState ?? null];
    const expectedProcessedCount = expectedCount + 2;
    reports.push({ scenario: 'out_of_order_state_transition',
      passed: httpStatuses[0] === 409 &&
        httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedCount + 1 &&
        observedCounts[2] === expectedProcessedCount &&
        observedResourceStates[0] === 'missing' &&
        observedResourceStates[1] === 'created' &&
        observedResourceStates[2] === 'activated',
      httpStatuses, observedCounts, observedResourceStates, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.secretRotation) {
    const makeRotationEvent = (name, signingSecret) => {
      const messageId = `wfl_rotation_${name}_${randomUUID().replaceAll('-', '')}`;
      const rawBody = JSON.stringify({ type: 'test.created',
        timestamp: new Date(now * 1000).toISOString(), data: { id: messageId } });
      return { rawBody, headers: {
        'content-type': 'application/json', 'webhook-id': messageId,
        'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret: signingSecret, id: messageId, timestamp: now, body: rawBody }),
      } };
    };
    const send = (event) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: event.headers, body: event.rawBody,
    });
    const previous = await send(makeRotationEvent('previous', previousSecret));
    const countAfterPrevious = await observe();
    const retired = await send(makeRotationEvent('retired', retiredSecret));
    const countAfterRetired = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [previous.status, retired.status];
    const observedCounts = [countAfterPrevious, countAfterRetired];
    reports.push({ scenario: 'secret_rotation_grace_and_retirement',
      passed: httpStatuses[0] === options.successStatus &&
        options.rejectionStatuses.includes(httpStatuses[1]) &&
        observedCounts[0] === expectedProcessedCount &&
        observedCounts[1] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.restartAfterCommit) {
    const restartId = `wfl_restart_${randomUUID().replaceAll('-', '')}`;
    const restartBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: restartId } });
    const headers = { 'content-type': 'application/json', 'webhook-id': restartId,
      'webhook-timestamp': String(now),
      'webhook-signature': sign({ secret, id: restartId, timestamp: now, body: restartBody }) };
    const first = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: restartBody,
    });
    const afterCommit = await observeState();

    // The caller controls only a local test receiver; never run an arbitrary restart command.
    const restarted = await restartReceiver();
    const restartedEndpoint = requireLoopbackUrl(restarted?.endpoint, 'restartReceiver endpoint');
    const restartedObserver = requireLoopbackUrl(restarted?.observer, 'restartReceiver observer');
    const afterRestart = await observeState(undefined, restartedObserver);
    const retry = await request(restartedEndpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: restartBody,
    });
    const afterRetry = await observeState(undefined, restartedObserver);

    const expectedProcessedCount = expectedCount + 1;
    const receiverInstanceIds = [afterCommit.receiverInstanceId ?? null,
      afterRestart.receiverInstanceId ?? null];
    const observedCounts = [afterCommit.processedCount, afterRestart.processedCount,
      afterRetry.processedCount];
    const httpStatuses = [first.status, retry.status];
    reports.push({ scenario: 'restart_preserves_idempotency',
      passed: httpStatuses.every((status) => status === options.successStatus) &&
        observedCounts.every((count) => count === expectedProcessedCount) &&
        receiverInstanceIds.every((value) => typeof value === 'string' && value.length > 0) &&
        receiverInstanceIds[0] !== receiverInstanceIds[1],
      httpStatuses, observedCounts, receiverInstanceIds, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.crashAfterPersist) {
    const beforeCrash = await observeState();
    const crashId = `wfl_crash_${randomUUID().replaceAll('-', '')}`;
    const crashBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: crashId } });
    const headers = { 'content-type': 'application/json', 'webhook-id': crashId,
      'webhook-timestamp': String(now),
      'webhook-signature': sign({ secret, id: crashId, timestamp: now, body: crashBody }) };
    // Test-owned receiver persists its effect and dedupe record, then exits without an HTTP reply.
    let firstAttemptOutcome;
    try {
      const first = await request(options.endpoint, {
        method: 'POST', redirect: 'manual', signal: timeout(),
        headers: { ...headers, 'x-wfl-test-fault': 'persist-then-crash-before-ack' },
        body: crashBody,
      });
      firstAttemptOutcome = `http_${first.status}`;
    } catch {
      firstAttemptOutcome = 'transport_error';
    }

    // Caller must witness termination and launch a new local OS process; no arbitrary shell commands.
    const recovered = await recoverReceiver();
    const recoveredEndpoint = requireLoopbackUrl(recovered?.endpoint, 'recoverReceiver endpoint');
    const recoveredObserver = requireLoopbackUrl(recovered?.observer, 'recoverReceiver observer');
    const afterRecovery = await observeState(undefined, recoveredObserver);
    const retry = await request(recoveredEndpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: crashBody,
    });
    const afterRetry = await observeState(undefined, recoveredObserver);
    const expectedProcessedCount = expectedCount + 1;
    const observedCounts = [beforeCrash.processedCount, afterRecovery.processedCount,
      afterRetry.processedCount];
    const receiverInstanceIds = [beforeCrash.receiverInstanceId ?? null,
      afterRecovery.receiverInstanceId ?? null];
    reports.push({ scenario: 'crash_after_persist_before_ack',
      passed: firstAttemptOutcome === 'transport_error' &&
        retry.status === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount &&
        receiverInstanceIds.every((value) => typeof value === 'string' && value.length > 0) &&
        receiverInstanceIds[0] !== receiverInstanceIds[1],
      firstAttemptOutcome, retryHttpStatus: retry.status, observedCounts,
      receiverInstanceIds, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.retentionWindowSeconds !== undefined) {
    const retentionId = `wfl_retention_${randomUUID().replaceAll('-', '')}`;
    const retentionBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: retentionId } });
    const headers = { 'content-type': 'application/json', 'webhook-id': retentionId,
      'webhook-timestamp': String(now),
      'webhook-signature': sign({ secret, id: retentionId, timestamp: now, body: retentionBody }) };
    const replay = () => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: retentionBody,
    });
    const first = await replay();
    const afterFirst = await observe();
    // The caller advances only its synthetic test receiver clock; no real wait or system clock change.
    await advanceReceiverTime(options.retentionWindowSeconds - 1);
    const beforeExpiry = await replay();
    const afterBeforeExpiry = await observe();
    // At 301 seconds the unchanged signature is stale under the Standard Webhooks 300s tolerance.
    await advanceReceiverTime(301 - (options.retentionWindowSeconds - 1));
    const staleReplay = await replay();
    const afterStaleReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [first.status, beforeExpiry.status, staleReplay.status];
    const observedCounts = [afterFirst, afterBeforeExpiry, afterStaleReplay];
    reports.push({ scenario: 'retention_boundary_stale_replay',
      passed: httpStatuses[0] === options.successStatus &&
        httpStatuses[1] === options.successStatus &&
        options.rejectionStatuses.includes(httpStatuses[2]) &&
        observedCounts.every((count) => count === expectedProcessedCount),
      httpStatuses, observedCounts, expectedProcessedCount,
      retentionWindowSeconds: options.retentionWindowSeconds });
    expectedCount = expectedProcessedCount;
  }

  return { success: reports.every((r) => r.passed), scenarios: reports,
    coverage: reports.map((report) => report.scenario),
    caveat: 'processedCount is a user-provided observer, not independently proven business-side-effect correctness' };
}
