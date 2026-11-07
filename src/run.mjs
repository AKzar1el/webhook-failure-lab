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
  const concurrentDistinctDeliveries = config.concurrentDistinctDeliveries;
  if (concurrentDistinctDeliveries !== undefined &&
      (!Number.isInteger(concurrentDistinctDeliveries) ||
       concurrentDistinctDeliveries < 2 || concurrentDistinctDeliveries > 8)) {
    throw new TypeError('concurrentDistinctDeliveries must be an integer between 2 and 8');
  }
  const retryAfterTransientFailure = config.retryAfterTransientFailure;
  if (retryAfterTransientFailure !== undefined && typeof retryAfterTransientFailure !== 'boolean') {
    throw new TypeError('retryAfterTransientFailure must be a boolean');
  }
  const retryAfterCommittedError = config.retryAfterCommittedError;
  if (retryAfterCommittedError !== undefined && typeof retryAfterCommittedError !== 'boolean') {
    throw new TypeError('retryAfterCommittedError must be a boolean');
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
  const rejectRetiredKeyDuplicate = config.rejectRetiredKeyDuplicate;
  if (rejectRetiredKeyDuplicate !== undefined && typeof rejectRetiredKeyDuplicate !== 'boolean') {
    throw new TypeError('rejectRetiredKeyDuplicate must be a boolean');
  }
  const multiSignatureHeader = config.multiSignatureHeader;
  if (multiSignatureHeader !== undefined && typeof multiSignatureHeader !== 'boolean') {
    throw new TypeError('multiSignatureHeader must be a boolean');
  }
  const conflictingEventIdPayload = config.conflictingEventIdPayload;
  if (conflictingEventIdPayload !== undefined && typeof conflictingEventIdPayload !== 'boolean') {
    throw new TypeError('conflictingEventIdPayload must be a boolean');
  }
  const concurrentConflictingEventIdPayload = config.concurrentConflictingEventIdPayload;
  if (concurrentConflictingEventIdPayload !== undefined &&
      typeof concurrentConflictingEventIdPayload !== 'boolean') {
    throw new TypeError('concurrentConflictingEventIdPayload must be a boolean');
  }
  const resignedDuplicateDelivery = config.resignedDuplicateDelivery;
  if (resignedDuplicateDelivery !== undefined && typeof resignedDuplicateDelivery !== 'boolean') {
    throw new TypeError('resignedDuplicateDelivery must be a boolean');
  }
  const rejectFutureSignedTimestamp = config.rejectFutureSignedTimestamp;
  if (rejectFutureSignedTimestamp !== undefined && typeof rejectFutureSignedTimestamp !== 'boolean') {
    throw new TypeError('rejectFutureSignedTimestamp must be a boolean');
  }
  const rejectTamperedDuplicateSignature = config.rejectTamperedDuplicateSignature;
  if (rejectTamperedDuplicateSignature !== undefined &&
      typeof rejectTamperedDuplicateSignature !== 'boolean') {
    throw new TypeError('rejectTamperedDuplicateSignature must be a boolean');
  }
  const rejectStaleDuplicateSignature = config.rejectStaleDuplicateSignature;
  if (rejectStaleDuplicateSignature !== undefined &&
      typeof rejectStaleDuplicateSignature !== 'boolean') {
    throw new TypeError('rejectStaleDuplicateSignature must be a boolean');
  }
  const rejectUnauthenticatedCollision = config.rejectUnauthenticatedCollision;
  if (rejectUnauthenticatedCollision !== undefined &&
      typeof rejectUnauthenticatedCollision !== 'boolean') {
    throw new TypeError('rejectUnauthenticatedCollision must be a boolean');
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
  if (secretRotation || rejectRetiredKeyDuplicate) {
    keyFromSecret(previousSecret);
    keyFromSecret(retiredSecret);
    if (new Set([secret, previousSecret, retiredSecret]).size !== 3) {
      throw new TypeError('Rotation requires three distinct signing keys');
    }
  }
  return { endpoint, observer, successStatus, rejectionStatuses, timeoutMs,
    concurrentDuplicateDeliveries, concurrentDistinctDeliveries,
    retryAfterTransientFailure, retryAfterCommittedError, lostAckAfterCommit,
    outOfOrderStateTransitions, secretRotation, rejectRetiredKeyDuplicate, multiSignatureHeader,
    conflictingEventIdPayload,
    concurrentConflictingEventIdPayload, resignedDuplicateDelivery,
    rejectFutureSignedTimestamp, rejectTamperedDuplicateSignature, rejectStaleDuplicateSignature,
    rejectUnauthenticatedCollision,
    restartAfterCommit, crashAfterPersist,
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

  if (options.concurrentDistinctDeliveries !== undefined) {
    // Each independently signed event must commit, unlike concurrent copies of one ID.
    const events = Array.from({ length: options.concurrentDistinctDeliveries }, () => {
      const distinctId = `wfl_unique_${randomUUID().replaceAll('-', '')}`;
      const rawBody = JSON.stringify({ type: 'test.created',
        timestamp: new Date(now * 1000).toISOString(), data: { id: distinctId } });
      return { rawBody, headers: { 'content-type': 'application/json',
        'webhook-id': distinctId, 'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret, id: distinctId, timestamp: now, body: rawBody }) } };
    });
    const responses = await Promise.all(events.map((event) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: event.headers, body: event.rawBody,
    })));
    const httpStatuses = responses.map((response) => response.status);
    const count = await observe();
    const expectedProcessedCount = expectedCount + options.concurrentDistinctDeliveries;
    reports.push({ scenario: 'concurrent_distinct_delivery',
      passed: httpStatuses.every((status) => status === options.successStatus) &&
        count === expectedProcessedCount,
      httpStatuses, observedProcessedCount: count, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.concurrentConflictingEventIdPayload) {
    const conflictId = `wfl_conflict_race_${randomUUID().replaceAll('-', '')}`;
    const makeEvent = (type) => {
      const rawBody = JSON.stringify({ type, timestamp: new Date(now * 1000).toISOString(),
        data: { id: conflictId } });
      return { rawBody, headers: { 'content-type': 'application/json',
        'webhook-id': conflictId, 'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret, id: conflictId, timestamp: now, body: rawBody }) } };
    };
    const events = [makeEvent('test.created'), makeEvent('test.updated')];
    // Either valid payload may win, but exactly one may commit and the other must conflict.
    const responses = await Promise.all(events.map((event) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: event.headers, body: event.rawBody,
    })));
    const httpStatuses = responses.map((response) => response.status).sort((a, b) => a - b);
    const count = await observe();
    const expectedProcessedCount = expectedCount + 1;
    reports.push({ scenario: 'concurrent_signed_event_id_collision',
      passed: httpStatuses[0] === options.successStatus &&
        httpStatuses[1] === 409 && count === expectedProcessedCount,
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

  if (options.retryAfterCommittedError) {
    const retryId = `wfl_committed503_${randomUUID().replaceAll('-', '')}`;
    const retryBody = JSON.stringify({ type: 'test.created', timestamp: new Date(now * 1000).toISOString(),
      data: { id: retryId } });
    const headers = { 'content-type': 'application/json', 'webhook-id': retryId,
      'webhook-timestamp': String(now),
      'webhook-signature': sign({ secret, id: retryId, timestamp: now, body: retryBody }) };
    // A valid delivery can commit successfully even when the HTTP response is 503.
    const first = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { ...headers, 'x-wfl-test-fault': 'commit-then-respond-503-once' }, body: retryBody,
    });
    const firstCount = await observe();
    const retry = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: retryBody,
    });
    const retryCount = await observe();
    const expectedProcessedCount = expectedCount + 1;
    reports.push({ scenario: 'retry_after_committed_503',
      passed: first.status === 503 && firstCount === expectedProcessedCount &&
        retry.status === options.successStatus && retryCount === expectedProcessedCount,
      httpStatuses: [first.status, retry.status], observedCounts: [firstCount, retryCount],
      expectedProcessedCount });
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

  if (options.rejectRetiredKeyDuplicate) {
    const duplicateId = `wfl_revokeddup_${randomUUID().replaceAll('-', '')}`;
    const duplicateBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: duplicateId } });
    // Retiring a key must invalidate its HMAC even when the ID is already in the dedupe cache.
    const send = (signingSecret) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': duplicateId,
        'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret: signingSecret, id: duplicateId,
          timestamp: now, body: duplicateBody }) },
      body: duplicateBody,
    });
    const original = await send(previousSecret);
    const afterOriginal = await observe();
    const revoked = await send(retiredSecret);
    const afterRevoked = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [original.status, revoked.status];
    const observedCounts = [afterOriginal, afterRevoked];
    reports.push({ scenario: 'retired_key_cached_duplicate',
      passed: httpStatuses[0] === options.successStatus &&
        options.rejectionStatuses.includes(httpStatuses[1]) &&
        observedCounts.every((count) => count === expectedProcessedCount),
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

  if (options.conflictingEventIdPayload) {
    const conflictId = `wfl_conflict_${randomUUID().replaceAll('-', '')}`;
    const firstBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: conflictId } });
    const differentBody = JSON.stringify({ type: 'test.updated',
      timestamp: new Date(now * 1000).toISOString(), data: { id: conflictId } });
    // Both bodies have valid independent signatures for the SAME delivery ID.
    // This is an event-ID collision, not an unsigned body-tampering test.
    const send = (rawBody) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': conflictId,
        'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret, id: conflictId, timestamp: now, body: rawBody }) },
      body: rawBody,
    });
    const first = await send(firstBody);
    const afterFirst = await observe();
    const replay = await send(firstBody);
    const afterReplay = await observe();
    const collision = await send(differentBody);
    const afterCollision = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [first.status, replay.status, collision.status];
    const observedCounts = [afterFirst, afterReplay, afterCollision];
    reports.push({ scenario: 'signed_event_id_payload_conflict',
      passed: httpStatuses[0] === options.successStatus &&
        httpStatuses[1] === options.successStatus && httpStatuses[2] === 409 &&
        observedCounts.every((count) => count === expectedProcessedCount),
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.resignedDuplicateDelivery) {
    const replayId = `wfl_resign_${randomUUID().replaceAll('-', '')}`;
    const replayBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: replayId } });
    // Same event ID and bytes, but the second valid signature covers a different timestamp.
    const send = (timestamp) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': replayId,
        'webhook-timestamp': String(timestamp),
        'webhook-signature': sign({ secret, id: replayId, timestamp, body: replayBody }) },
      body: replayBody,
    });
    const first = await send(now);
    const afterFirst = await observe();
    const retry = await send(now - 1);
    const afterRetry = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [first.status, retry.status];
    const observedCounts = [afterFirst, afterRetry];
    reports.push({ scenario: 'resigned_duplicate_delivery',
      passed: httpStatuses.every((status) => status === options.successStatus) &&
        observedCounts.every((count) => count === expectedProcessedCount),
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectFutureSignedTimestamp) {
    const futureId = `wfl_future_${randomUUID().replaceAll('-', '')}`;
    const futureTimestamp = now + 3600;
    const futureBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(futureTimestamp * 1000).toISOString(), data: { id: futureId } });
    // HMAC matches the future timestamp; only freshness policy should reject this delivery.
    await deliver('future_signed_timestamp', futureId, futureBody, futureBody,
      futureTimestamp, false, 0);
  }

  if (options.rejectTamperedDuplicateSignature) {
    const duplicateId = `wfl_dupauth_${randomUUID().replaceAll('-', '')}`;
    const duplicateBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: duplicateId } });
    const validSignature = sign({ secret, id: duplicateId, timestamp: now, body: duplicateBody });
    // Change one digest character, retaining a well-formed but invalid HMAC for the same ID and bytes.
    const tamperedSignature = validSignature.slice(0, 3) +
      (validSignature[3] === 'A' ? 'B' : 'A') + validSignature.slice(4);
    const send = (signature) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': duplicateId,
        'webhook-timestamp': String(now), 'webhook-signature': signature },
      body: duplicateBody,
    });
    const original = await send(validSignature);
    const afterOriginal = await observe();
    const tampered = await send(tamperedSignature);
    const afterTampered = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [original.status, tampered.status];
    const observedCounts = [afterOriginal, afterTampered];
    reports.push({ scenario: 'tampered_duplicate_signature',
      passed: httpStatuses[0] === options.successStatus &&
        options.rejectionStatuses.includes(httpStatuses[1]) &&
        observedCounts.every((count) => count === expectedProcessedCount),
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectStaleDuplicateSignature) {
    const duplicateId = `wfl_staledup_${randomUUID().replaceAll('-', '')}`;
    const duplicateBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: duplicateId } });
    // Both HMACs are authentic: the cached ID must not bypass timestamp freshness.
    const send = (timestamp) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': duplicateId,
        'webhook-timestamp': String(timestamp),
        'webhook-signature': sign({ secret, id: duplicateId, timestamp, body: duplicateBody }) },
      body: duplicateBody,
    });
    const original = await send(now);
    const afterOriginal = await observe();
    const stale = await send(now - 3600);
    const afterStale = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [original.status, stale.status];
    const observedCounts = [afterOriginal, afterStale];
    reports.push({ scenario: 'stale_cached_duplicate_signature',
      passed: httpStatuses[0] === options.successStatus &&
        options.rejectionStatuses.includes(httpStatuses[1]) &&
        observedCounts.every((count) => count === expectedProcessedCount),
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectUnauthenticatedCollision) {
    const collisionId = `wfl_conflict_unauth_${randomUUID().replaceAll('-', '')}`;
    const originalBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: collisionId } });
    const tamperedBody = JSON.stringify({ type: 'test.updated',
      timestamp: new Date(now * 1000).toISOString(), data: { id: collisionId } });
    // Reuse a valid signature from the initial body against changed bytes: no longer authentic.
    const originalSignature = sign({ secret, id: collisionId, timestamp: now, body: originalBody });
    const send = (rawBody) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': collisionId,
        'webhook-timestamp': String(now), 'webhook-signature': originalSignature },
      body: rawBody,
    });
    const original = await send(originalBody);
    const afterOriginal = await observe();
    const unauthenticated = await send(tamperedBody);
    const afterUnauthenticated = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [original.status, unauthenticated.status];
    const observedCounts = [afterOriginal, afterUnauthenticated];
    reports.push({ scenario: 'unauthenticated_event_id_collision',
      passed: httpStatuses[0] === options.successStatus &&
        options.rejectionStatuses.includes(httpStatuses[1]) &&
        httpStatuses[1] !== 409 &&
        observedCounts.every((count) => count === expectedProcessedCount),
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.multiSignatureHeader) {
    const multiId = `wfl_multisig_${randomUUID().replaceAll('-', '')}`;
    const rejectId = `wfl_multisig_reject_${randomUUID().replaceAll('-', '')}`;
    const makeBody = (eventId) => JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: eventId } });
    const multiBody = makeBody(multiId);
    const rejectBody = makeBody(rejectId);
    const corrupt = (value, index) => value.slice(0, index) +
      (value[index] === 'A' ? 'B' : 'A') + value.slice(index + 1);
    const valid = sign({ secret, id: multiId, timestamp: now, body: multiBody });
    const rejectValid = sign({ secret, id: rejectId, timestamp: now, body: rejectBody });
    const invalid = corrupt(valid, 3);
    const send = (messageId, rawBody, signature) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': messageId,
        'webhook-timestamp': String(now), 'webhook-signature': signature },
      body: rawBody,
    });
    // A verifier must search every signature token, while never accepting an all-invalid list.
    const validSecond = await send(multiId, multiBody, `${invalid} ${valid}`);
    const afterValidSecond = await observe();
    const validFirst = await send(multiId, multiBody, `${valid} ${invalid}`);
    const afterValidFirst = await observe();
    const invalidOnly = await send(rejectId, rejectBody,
      `${corrupt(rejectValid, 3)} ${corrupt(rejectValid, 4)}`);
    const afterInvalidOnly = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [validSecond.status, validFirst.status, invalidOnly.status];
    const observedCounts = [afterValidSecond, afterValidFirst, afterInvalidOnly];
    reports.push({ scenario: 'multi_signature_header',
      passed: httpStatuses[0] === options.successStatus &&
        httpStatuses[1] === options.successStatus &&
        options.rejectionStatuses.includes(httpStatuses[2]) &&
        observedCounts.every((count) => count === expectedProcessedCount),
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  return { success: reports.every((r) => r.passed), scenarios: reports,
    coverage: reports.map((report) => report.scenario),
    caveat: 'processedCount is a user-provided observer, not independently proven business-side-effect correctness' };
}
