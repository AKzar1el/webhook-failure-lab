import { randomUUID } from 'node:crypto';
import { Agent as HttpAgent, request as httpRequest } from 'node:http';
import { gzipSync } from 'node:zlib';
import { requireLoopbackUrl } from './loopback.mjs';
import { keyFromSecret, sign } from './standard.mjs';

const DEFAULT_TIMEOUT_MS = 3000;

function postOnKeepAliveAgent(endpoint, { id, timestamp, signature, body, signal }, agent) {
  // A dedicated Node agent allows us to prove actual socket reuse, unlike fetch pooling.
  return new Promise((resolve, reject) => {
    let socket;
    const outgoing = httpRequest(requireLoopbackUrl(endpoint), {
      method: 'POST', agent, signal,
      headers: { 'content-type': 'application/json', 'webhook-id': id,
        'webhook-timestamp': String(timestamp), 'webhook-signature': signature },
    }, (response) => {
      response.resume();
      response.once('end', () => resolve({ status: response.statusCode, socket }));
      response.once('error', reject);
    });
    outgoing.once('socket', (value) => { socket = value; });
    outgoing.once('error', reject);
    outgoing.end(body);
  });
}

function postWithMixedCaseWebhookHeaders(endpoint, { id, timestamp, signature, body, signal }) {
  // The raw Node client preserves field-name spelling; fetch canonicalizes it.
  // HTTP field names are case-insensitive, while the authenticated values stay identical.
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest(requireLoopbackUrl(endpoint), {
      method: 'POST', signal,
      headers: { 'Content-Type': 'application/json', 'WeBhOoK-Id': id,
        'WEBHOOK-TIMESTAMP': String(timestamp), 'WebHook-Signature': signature },
    }, (response) => {
      response.resume();
      response.once('end', () => resolve({ status: response.statusCode }));
      response.once('error', reject);
    });
    outgoing.once('error', reject);
    outgoing.end(body);
  });
}

function postWithDuplicateWireId(endpoint, { id, timestamp, signature, body, signal }) {
  // fetch coalesces duplicate header fields. Node's HTTP client emits two physical
  // webhook-id fields, while the already-validated URL remains loopback-only.
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest(requireLoopbackUrl(endpoint), {
      method: 'POST', signal,
      headers: { 'content-type': 'application/json',
        'webhook-id': [id, `${id}_other`],
        'webhook-timestamp': String(timestamp), 'webhook-signature': signature },
    }, (response) => {
      response.resume();
      response.once('end', () => resolve({ status: response.statusCode }));
      response.once('error', reject);
    });
    outgoing.once('error', reject);
    outgoing.end(body);
  });
}

function postWithDuplicateWireTimestamp(endpoint, {
  id, timestamp, signature, body, signal, staleFirst = false,
}) {
  // A fetch Headers object cannot preserve separate physical timestamp fields.
  const timestamps = [String(timestamp), String(timestamp - 3600)];
  if (staleFirst) timestamps.reverse();
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest(requireLoopbackUrl(endpoint), {
      method: 'POST', signal,
      headers: { 'content-type': 'application/json', 'webhook-id': id,
        'webhook-timestamp': timestamps,
        'webhook-signature': signature },
    }, (response) => {
      response.resume();
      response.once('end', () => resolve({ status: response.statusCode }));
      response.once('error', reject);
    });
    outgoing.once('error', reject);
    outgoing.end(body);
  });
}

function postWithDuplicateWireSignature(endpoint, {
  id, timestamp, signature, body, signal, invalidFirst = false,
}) {
  // Preserve two physical signature fields, not a valid space-separated list
  // inside one field (which the separate multi-signature probe accepts).
  const invalid = signature.slice(0, 3) +
    (signature[3] === 'A' ? 'B' : 'A') + signature.slice(4);
  const signatures = invalidFirst ? [invalid, signature] : [signature, invalid];
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest(requireLoopbackUrl(endpoint), {
      method: 'POST', signal,
      headers: { 'content-type': 'application/json', 'webhook-id': id,
        'webhook-timestamp': String(timestamp), 'webhook-signature': signatures },
    }, (response) => {
      response.resume();
      response.once('end', () => resolve({ status: response.statusCode }));
      response.once('error', reject);
    });
    outgoing.once('error', reject);
    outgoing.end(body);
  });
}

function postWithDuplicateWireContentType(endpoint, {
  id, timestamp, signature, body, signal, jsonFirst = true,
}) {
  // Node's raw HTTP client preserves two physical fields; fetch Headers cannot.
  const types = jsonFirst
    ? ['application/json', 'text/plain'] : ['text/plain', 'application/json'];
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest(requireLoopbackUrl(endpoint), {
      method: 'POST', signal,
      headers: { 'content-type': types, 'webhook-id': id,
        'webhook-timestamp': String(timestamp), 'webhook-signature': signature },
    }, (response) => {
      response.resume();
      response.once('end', () => resolve({ status: response.statusCode }));
      response.once('error', reject);
    });
    outgoing.once('error', reject);
    outgoing.end(body);
  });
}

function postWithDuplicateWireContentEncoding(endpoint, {
  id, timestamp, signature, body, signal, identityFirst = true,
}) {
  // Preserve conflicting physical encoding fields: fetch would merge them.
  const encodings = identityFirst ? ['identity', 'gzip'] : ['gzip', 'identity'];
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest(requireLoopbackUrl(endpoint), {
      method: 'POST', signal,
      headers: { 'content-type': 'application/json', 'content-encoding': encodings,
        'webhook-id': id, 'webhook-timestamp': String(timestamp),
        'webhook-signature': signature },
    }, (response) => {
      response.resume();
      response.once('end', () => resolve({ status: response.statusCode }));
      response.once('error', reject);
    });
    outgoing.once('error', reject);
    outgoing.end(body);
  });
}

function postChunkedSignedUtf8(endpoint, { id, timestamp, signature, body, signal }) {
  const utf8Start = body.indexOf(Buffer.from('€', 'utf8'));
  if (utf8Start < 0) throw new Error('Synthetic UTF-8 split marker missing');
  // Write the first byte of a three-byte character in one HTTP chunk and
  // the remaining bytes in the next; the HMAC authenticates the whole byte stream.
  const split = utf8Start + 1;
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest(requireLoopbackUrl(endpoint), {
      method: 'POST', signal,
      headers: { 'content-type': 'application/json', 'webhook-id': id,
        'webhook-timestamp': String(timestamp), 'webhook-signature': signature },
    }, (response) => {
      response.resume();
      response.once('end', () => resolve({ status: response.statusCode }));
      response.once('error', reject);
    });
    outgoing.once('error', reject);
    outgoing.write(body.subarray(0, split));
    setTimeout(() => {
      if (!outgoing.destroyed) outgoing.end(body.subarray(split));
    }, 20);
  });
}

function postAbortedPartialBody(endpoint, { id, timestamp, signature, body, signal }) {
  // Advertise the complete signed byte length, write only a prefix, then close
  // the client socket. A broken receiver may reserve/commit before body completion.
  return new Promise((resolve, reject) => {
    let responded = false;
    let closedByProbe = false;
    const outgoing = httpRequest(requireLoopbackUrl(endpoint), {
      method: 'POST', signal,
      headers: { 'content-type': 'application/json', 'content-length': body.length,
        'webhook-id': id, 'webhook-timestamp': String(timestamp),
        'webhook-signature': signature },
    }, (response) => {
      responded = true;
      response.resume();
      response.once('end', () => resolve(`http_${response.statusCode}`));
      response.once('error', reject);
    });
    outgoing.once('error', (error) => {
      if (closedByProbe && !responded) resolve('transport_error');
      else reject(error);
    });
    outgoing.once('close', () => {
      if (!responded && closedByProbe) resolve('transport_error');
      else if (!responded) reject(new Error('Upload closed before deliberate abort'));
    });
    const prefix = body.subarray(0, Math.max(1, Math.floor(body.length / 3)));
    outgoing.write(prefix, () => {
      if (!outgoing.destroyed) {
        closedByProbe = true;
        outgoing.destroy();
      }
    });
  });
}

function postAbortedChunkedBody(endpoint, { id, timestamp, signature, body, signal }) {
  // Send a complete HTTP chunk but deliberately omit the terminating zero-length
  // chunk. A receiver must not process signed content until the HTTP body ends.
  return new Promise((resolve, reject) => {
    let responded = false;
    let closedByProbe = false;
    const outgoing = httpRequest(requireLoopbackUrl(endpoint), {
      method: 'POST', signal,
      headers: { 'content-type': 'application/json',
        'webhook-id': id, 'webhook-timestamp': String(timestamp),
        'webhook-signature': signature },
    }, (response) => {
      responded = true;
      response.resume();
      response.once('end', () => resolve(`http_${response.statusCode}`));
      response.once('error', reject);
    });
    outgoing.once('error', (error) => {
      if (closedByProbe && !responded) resolve('transport_error');
      else reject(error);
    });
    outgoing.once('close', () => {
      if (!responded && closedByProbe) resolve('transport_error');
      else if (!responded) reject(new Error('Chunked upload closed before deliberate abort'));
    });
    const prefix = body.subarray(0, Math.max(1, Math.floor(body.length / 2)));
    outgoing.write(prefix, () => {
      if (!outgoing.destroyed) {
        closedByProbe = true;
        outgoing.destroy();
      }
    });
  });
}

function checkOptions(config, secret, previousSecret, retiredSecret, tenantBSecret) {
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
  const asyncAckDelivery = config.asyncAckDelivery;
  if (asyncAckDelivery !== undefined && typeof asyncAckDelivery !== 'boolean') {
    throw new TypeError('asyncAckDelivery must be a boolean');
  }
  const asyncAckWaitMs = config.asyncAckWaitMs === undefined ? 1000 : config.asyncAckWaitMs;
  if (!Number.isInteger(asyncAckWaitMs) || asyncAckWaitMs < 100 || asyncAckWaitMs > 5000) {
    throw new TypeError('asyncAckWaitMs must be an integer between 100 and 5000');
  }
  if (!asyncAckDelivery && config.asyncAckWaitMs !== undefined) {
    throw new TypeError('asyncAckWaitMs requires asyncAckDelivery');
  }
  const rejectMalformedSignedPayload = config.rejectMalformedSignedPayload;
  if (rejectMalformedSignedPayload !== undefined &&
      typeof rejectMalformedSignedPayload !== 'boolean') {
    throw new TypeError('rejectMalformedSignedPayload must be a boolean');
  }
  const rejectWrongContentTypeRetry = config.rejectWrongContentTypeRetry;
  if (rejectWrongContentTypeRetry !== undefined &&
      typeof rejectWrongContentTypeRetry !== 'boolean') {
    throw new TypeError('rejectWrongContentTypeRetry must be a boolean');
  }
  const rejectWrongHttpMethodRetry = config.rejectWrongHttpMethodRetry;
  if (rejectWrongHttpMethodRetry !== undefined &&
      typeof rejectWrongHttpMethodRetry !== 'boolean') {
    throw new TypeError('rejectWrongHttpMethodRetry must be a boolean');
  }
  const rejectUnsupportedContentEncodingRetry = config.rejectUnsupportedContentEncodingRetry;
  if (rejectUnsupportedContentEncodingRetry !== undefined &&
      typeof rejectUnsupportedContentEncodingRetry !== 'boolean') {
    throw new TypeError('rejectUnsupportedContentEncodingRetry must be a boolean');
  }
  const acceptJsonCharsetContentType = config.acceptJsonCharsetContentType;
  if (acceptJsonCharsetContentType !== undefined &&
      typeof acceptJsonCharsetContentType !== 'boolean') {
    throw new TypeError('acceptJsonCharsetContentType must be a boolean');
  }
  const rawJsonSignatureBytes = config.rawJsonSignatureBytes;
  if (rawJsonSignatureBytes !== undefined && typeof rawJsonSignatureBytes !== 'boolean') {
    throw new TypeError('rawJsonSignatureBytes must be a boolean');
  }
  const rejectInvalidSignedEventSchema = config.rejectInvalidSignedEventSchema;
  if (rejectInvalidSignedEventSchema !== undefined &&
      typeof rejectInvalidSignedEventSchema !== 'boolean') {
    throw new TypeError('rejectInvalidSignedEventSchema must be a boolean');
  }
  const rejectDuplicateJsonDataKey = config.rejectDuplicateJsonDataKey;
  if (rejectDuplicateJsonDataKey !== undefined &&
      typeof rejectDuplicateJsonDataKey !== 'boolean') {
    throw new TypeError('rejectDuplicateJsonDataKey must be a boolean');
  }
  const rejectDuplicateNestedResourceId = config.rejectDuplicateNestedResourceId;
  if (rejectDuplicateNestedResourceId !== undefined &&
      typeof rejectDuplicateNestedResourceId !== 'boolean') {
    throw new TypeError('rejectDuplicateNestedResourceId must be a boolean');
  }
  const rejectOversizedSignedPayload = config.rejectOversizedSignedPayload;
  if (rejectOversizedSignedPayload !== undefined &&
      typeof rejectOversizedSignedPayload !== 'boolean') {
    throw new TypeError('rejectOversizedSignedPayload must be a boolean');
  }
  const rejectOversizedGzipRetry = config.rejectOversizedGzipRetry;
  if (rejectOversizedGzipRetry !== undefined && typeof rejectOversizedGzipRetry !== 'boolean') {
    throw new TypeError('rejectOversizedGzipRetry must be a boolean');
  }
  const rejectMalformedGzipRetry = config.rejectMalformedGzipRetry;
  if (rejectMalformedGzipRetry !== undefined && typeof rejectMalformedGzipRetry !== 'boolean') {
    throw new TypeError('rejectMalformedGzipRetry must be a boolean');
  }
  const retryAfterRejectedSignature = config.retryAfterRejectedSignature;
  if (retryAfterRejectedSignature !== undefined &&
      typeof retryAfterRejectedSignature !== 'boolean') {
    throw new TypeError('retryAfterRejectedSignature must be a boolean');
  }
  const rejectMissingSignatureRetry = config.rejectMissingSignatureRetry;
  if (rejectMissingSignatureRetry !== undefined &&
      typeof rejectMissingSignatureRetry !== 'boolean') {
    throw new TypeError('rejectMissingSignatureRetry must be a boolean');
  }
  const rejectUnsupportedSignatureVersion = config.rejectUnsupportedSignatureVersion;
  if (rejectUnsupportedSignatureVersion !== undefined &&
      typeof rejectUnsupportedSignatureVersion !== 'boolean') {
    throw new TypeError('rejectUnsupportedSignatureVersion must be a boolean');
  }
  const rejectMissingTimestampRetry = config.rejectMissingTimestampRetry;
  if (rejectMissingTimestampRetry !== undefined &&
      typeof rejectMissingTimestampRetry !== 'boolean') {
    throw new TypeError('rejectMissingTimestampRetry must be a boolean');
  }
  const rejectMissingEventIdRetry = config.rejectMissingEventIdRetry;
  if (rejectMissingEventIdRetry !== undefined &&
      typeof rejectMissingEventIdRetry !== 'boolean') {
    throw new TypeError('rejectMissingEventIdRetry must be a boolean');
  }
  const rejectDuplicateWireEventIdRetry = config.rejectDuplicateWireEventIdRetry;
  if (rejectDuplicateWireEventIdRetry !== undefined &&
      typeof rejectDuplicateWireEventIdRetry !== 'boolean') {
    throw new TypeError('rejectDuplicateWireEventIdRetry must be a boolean');
  }
  const rejectDuplicateWireTimestampRetry = config.rejectDuplicateWireTimestampRetry;
  if (rejectDuplicateWireTimestampRetry !== undefined &&
      typeof rejectDuplicateWireTimestampRetry !== 'boolean') {
    throw new TypeError('rejectDuplicateWireTimestampRetry must be a boolean');
  }
  const rejectDuplicateWireSignatureRetry = config.rejectDuplicateWireSignatureRetry;
  if (rejectDuplicateWireSignatureRetry !== undefined &&
      typeof rejectDuplicateWireSignatureRetry !== 'boolean') {
    throw new TypeError('rejectDuplicateWireSignatureRetry must be a boolean');
  }
  const rejectDuplicateWireContentTypeRetry = config.rejectDuplicateWireContentTypeRetry;
  if (rejectDuplicateWireContentTypeRetry !== undefined &&
      typeof rejectDuplicateWireContentTypeRetry !== 'boolean') {
    throw new TypeError('rejectDuplicateWireContentTypeRetry must be a boolean');
  }
  const rejectDuplicateWireContentEncodingRetry = config.rejectDuplicateWireContentEncodingRetry;
  if (rejectDuplicateWireContentEncodingRetry !== undefined &&
      typeof rejectDuplicateWireContentEncodingRetry !== 'boolean') {
    throw new TypeError('rejectDuplicateWireContentEncodingRetry must be a boolean');
  }
  const chunkedSignedUtf8Replay = config.chunkedSignedUtf8Replay;
  if (chunkedSignedUtf8Replay !== undefined && typeof chunkedSignedUtf8Replay !== 'boolean') {
    throw new TypeError('chunkedSignedUtf8Replay must be a boolean');
  }
  const mixedCaseWebhookHeaders = config.mixedCaseWebhookHeaders;
  if (mixedCaseWebhookHeaders !== undefined && typeof mixedCaseWebhookHeaders !== 'boolean') {
    throw new TypeError('mixedCaseWebhookHeaders must be a boolean');
  }
  const keepAliveConnectionIsolation = config.keepAliveConnectionIsolation;
  if (keepAliveConnectionIsolation !== undefined &&
      typeof keepAliveConnectionIsolation !== 'boolean') {
    throw new TypeError('keepAliveConnectionIsolation must be a boolean');
  }
  const partialBodyUploadAbort = config.partialBodyUploadAbort;
  if (partialBodyUploadAbort !== undefined && typeof partialBodyUploadAbort !== 'boolean') {
    throw new TypeError('partialBodyUploadAbort must be a boolean');
  }
  const abortedChunkedUploadRetry = config.abortedChunkedUploadRetry;
  if (abortedChunkedUploadRetry !== undefined && typeof abortedChunkedUploadRetry !== 'boolean') {
    throw new TypeError('abortedChunkedUploadRetry must be a boolean');
  }
  const rejectInvalidUtf8Retry = config.rejectInvalidUtf8Retry;
  if (rejectInvalidUtf8Retry !== undefined && typeof rejectInvalidUtf8Retry !== 'boolean') {
    throw new TypeError('rejectInvalidUtf8Retry must be a boolean');
  }
  const caseSensitiveEventIds = config.caseSensitiveEventIds;
  if (caseSensitiveEventIds !== undefined && typeof caseSensitiveEventIds !== 'boolean') {
    throw new TypeError('caseSensitiveEventIds must be a boolean');
  }
  const prototypePropertyEventIds = config.prototypePropertyEventIds;
  if (prototypePropertyEventIds !== undefined && typeof prototypePropertyEventIds !== 'boolean') {
    throw new TypeError('prototypePropertyEventIds must be a boolean');
  }
  const distinctEventsSameResource = config.distinctEventsSameResource;
  if (distinctEventsSameResource !== undefined && typeof distinctEventsSameResource !== 'boolean') {
    throw new TypeError('distinctEventsSameResource must be a boolean');
  }
  const distinctIdsIdenticalBody = config.distinctIdsIdenticalBody;
  if (distinctIdsIdenticalBody !== undefined && typeof distinctIdsIdenticalBody !== 'boolean') {
    throw new TypeError('distinctIdsIdenticalBody must be a boolean');
  }
  const tenantScopedEventIds = config.tenantScopedEventIds;
  if (tenantScopedEventIds !== undefined && typeof tenantScopedEventIds !== 'boolean') {
    throw new TypeError('tenantScopedEventIds must be a boolean');
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
  const retryAfterRateLimit = config.retryAfterRateLimit;
  if (retryAfterRateLimit !== undefined && typeof retryAfterRateLimit !== 'boolean') {
    throw new TypeError('retryAfterRateLimit must be a boolean');
  }
  const retryAfterCommittedError = config.retryAfterCommittedError;
  if (retryAfterCommittedError !== undefined && typeof retryAfterCommittedError !== 'boolean') {
    throw new TypeError('retryAfterCommittedError must be a boolean');
  }
  const lostAckAfterCommit = config.lostAckAfterCommit;
  if (lostAckAfterCommit !== undefined && typeof lostAckAfterCommit !== 'boolean') {
    throw new TypeError('lostAckAfterCommit must be a boolean');
  }
  const timeoutAfterCommit = config.timeoutAfterCommit;
  if (timeoutAfterCommit !== undefined && typeof timeoutAfterCommit !== 'boolean') {
    throw new TypeError('timeoutAfterCommit must be a boolean');
  }
  const timeoutBeforeCommit = config.timeoutBeforeCommit;
  if (timeoutBeforeCommit !== undefined && typeof timeoutBeforeCommit !== 'boolean') {
    throw new TypeError('timeoutBeforeCommit must be a boolean');
  }
  const outOfOrderStateTransitions = config.outOfOrderStateTransitions;
  if (outOfOrderStateTransitions !== undefined && typeof outOfOrderStateTransitions !== 'boolean') {
    throw new TypeError('outOfOrderStateTransitions must be a boolean');
  }
  const delayedCreationReplayAfterActivation = config.delayedCreationReplayAfterActivation;
  if (delayedCreationReplayAfterActivation !== undefined &&
      typeof delayedCreationReplayAfterActivation !== 'boolean') {
    throw new TypeError('delayedCreationReplayAfterActivation must be a boolean');
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
  const rejectFutureDuplicateSignature = config.rejectFutureDuplicateSignature;
  if (rejectFutureDuplicateSignature !== undefined &&
      typeof rejectFutureDuplicateSignature !== 'boolean') {
    throw new TypeError('rejectFutureDuplicateSignature must be a boolean');
  }
  const rejectNoncanonicalTimestamp = config.rejectNoncanonicalTimestamp;
  if (rejectNoncanonicalTimestamp !== undefined && typeof rejectNoncanonicalTimestamp !== 'boolean') {
    throw new TypeError('rejectNoncanonicalTimestamp must be a boolean');
  }
  const rejectTamperedDuplicateSignature = config.rejectTamperedDuplicateSignature;
  if (rejectTamperedDuplicateSignature !== undefined &&
      typeof rejectTamperedDuplicateSignature !== 'boolean') {
    throw new TypeError('rejectTamperedDuplicateSignature must be a boolean');
  }
  const rejectTamperedEventId = config.rejectTamperedEventId;
  if (rejectTamperedEventId !== undefined && typeof rejectTamperedEventId !== 'boolean') {
    throw new TypeError('rejectTamperedEventId must be a boolean');
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
  const versionedOutOfOrderUpdates = config.versionedOutOfOrderUpdates;
  if (versionedOutOfOrderUpdates !== undefined && typeof versionedOutOfOrderUpdates !== 'boolean') {
    throw new TypeError('versionedOutOfOrderUpdates must be a boolean');
  }
  const restartAfterCommit = config.restartAfterCommit;
  if (restartAfterCommit !== undefined && typeof restartAfterCommit !== 'boolean') {
    throw new TypeError('restartAfterCommit must be a boolean');
  }
  const crashAfterPersist = config.crashAfterPersist;
  if (crashAfterPersist !== undefined && typeof crashAfterPersist !== 'boolean') {
    throw new TypeError('crashAfterPersist must be a boolean');
  }
  const crashBeforeCommit = config.crashBeforeCommit;
  if (crashBeforeCommit !== undefined && typeof crashBeforeCommit !== 'boolean') {
    throw new TypeError('crashBeforeCommit must be a boolean');
  }
  const parallelCrashRecoveryRetries = config.parallelCrashRecoveryRetries;
  if (parallelCrashRecoveryRetries !== undefined &&
      (!Number.isInteger(parallelCrashRecoveryRetries) ||
       parallelCrashRecoveryRetries < 2 || parallelCrashRecoveryRetries > 8)) {
    throw new TypeError('parallelCrashRecoveryRetries must be an integer between 2 and 8');
  }
  if (parallelCrashRecoveryRetries !== undefined && !crashBeforeCommit && !crashAfterPersist) {
    throw new TypeError('parallelCrashRecoveryRetries requires crashBeforeCommit or crashAfterPersist');
  }
  const retentionWindowSeconds = config.retentionWindowSeconds;
  if (retentionWindowSeconds !== undefined &&
      (!Number.isInteger(retentionWindowSeconds) || retentionWindowSeconds < 2 ||
       retentionWindowSeconds > 240)) {
    throw new TypeError('retentionWindowSeconds must be an integer between 2 and 240');
  }
  if ([crashAfterPersist, crashBeforeCommit, restartAfterCommit].filter(Boolean).length > 1) {
    throw new TypeError('Process crash and restart probes require separate runs');
  }
  if (retentionWindowSeconds !== undefined &&
      (crashAfterPersist || crashBeforeCommit || restartAfterCommit)) {
    throw new TypeError('retentionWindowSeconds and process controllers require separate runs');
  }
  if (secretRotation || rejectRetiredKeyDuplicate) {
    keyFromSecret(previousSecret);
    keyFromSecret(retiredSecret);
    if (new Set([secret, previousSecret, retiredSecret]).size !== 3) {
      throw new TypeError('Rotation requires three distinct signing keys');
    }
  }
  if (tenantScopedEventIds) {
    keyFromSecret(tenantBSecret);
    if ([secret, previousSecret, retiredSecret].includes(tenantBSecret)) {
      throw new TypeError('tenantBSecret must be distinct from the other signing keys');
    }
  }
  return { endpoint, observer, successStatus, rejectionStatuses, timeoutMs,
    asyncAckDelivery, asyncAckWaitMs,
    rejectWrongContentTypeRetry, rejectWrongHttpMethodRetry,
    rejectUnsupportedContentEncodingRetry,
    acceptJsonCharsetContentType, rawJsonSignatureBytes,
    rejectInvalidSignedEventSchema, rejectDuplicateJsonDataKey,
    rejectDuplicateNestedResourceId, rejectOversizedSignedPayload, rejectOversizedGzipRetry,
    rejectMalformedGzipRetry,
    retryAfterRejectedSignature, rejectMissingSignatureRetry, rejectUnsupportedSignatureVersion,
    rejectMissingTimestampRetry,
    rejectMissingEventIdRetry, rejectDuplicateWireEventIdRetry,
    rejectDuplicateWireTimestampRetry, rejectDuplicateWireSignatureRetry,
    rejectDuplicateWireContentTypeRetry, rejectDuplicateWireContentEncodingRetry,
    chunkedSignedUtf8Replay, mixedCaseWebhookHeaders, keepAliveConnectionIsolation,
    partialBodyUploadAbort, abortedChunkedUploadRetry,
    rejectInvalidUtf8Retry,
    concurrentDuplicateDeliveries, concurrentDistinctDeliveries,
    retryAfterTransientFailure, retryAfterRateLimit, retryAfterCommittedError,
    lostAckAfterCommit, timeoutAfterCommit,
    timeoutBeforeCommit,
    outOfOrderStateTransitions, delayedCreationReplayAfterActivation,
    secretRotation, rejectRetiredKeyDuplicate, multiSignatureHeader,
    conflictingEventIdPayload,
    concurrentConflictingEventIdPayload, resignedDuplicateDelivery, caseSensitiveEventIds,
    prototypePropertyEventIds,
    distinctEventsSameResource, distinctIdsIdenticalBody,
    tenantScopedEventIds,
    rejectFutureSignedTimestamp, rejectFutureDuplicateSignature, rejectNoncanonicalTimestamp,
    rejectTamperedDuplicateSignature, rejectTamperedEventId, rejectStaleDuplicateSignature,
    rejectUnauthenticatedCollision,
    restartAfterCommit, crashAfterPersist, crashBeforeCommit, parallelCrashRecoveryRetries,
    retentionWindowSeconds };
}

export async function runLab(config, { secret, previousSecret, retiredSecret, tenantBSecret,
  restartReceiver, recoverReceiver, advanceReceiverTime, request = fetch,
  clock = () => Math.floor(Date.now() / 1000) } = {}) {
  const options = checkOptions(config, secret, previousSecret, retiredSecret, tenantBSecret);
  if (options.restartAfterCommit && typeof restartReceiver !== 'function') {
    throw new TypeError('restartReceiver must be a local process-controller function');
  }
  if ((options.crashAfterPersist || options.crashBeforeCommit) &&
      typeof recoverReceiver !== 'function') {
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

  if (options.mixedCaseWebhookHeaders) {
    const headerCaseId = `wfl_headercase_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      data: { id: headerCaseId } });
    const signature = sign({ secret, id: headerCaseId, timestamp: now, body: rawBody });
    const mixed = await postWithMixedCaseWebhookHeaders(options.endpoint,
      { id: headerCaseId, timestamp: now, signature, body: rawBody, signal: timeout() });
    const afterMixed = await observe();
    const replay = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': headerCaseId,
        'webhook-timestamp': String(now), 'webhook-signature': signature },
      body: rawBody,
    });
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [mixed.status, replay.status];
    const observedCounts = [afterMixed, afterReplay];
    reports.push({ scenario: 'mixed_case_header_replay',
      passed: httpStatuses.every((status) => status === options.successStatus) &&
        observedCounts.every((count) => count === expectedProcessedCount),
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.chunkedSignedUtf8Replay) {
    const chunkedId = `wfl_chunked_${randomUUID().replaceAll('-', '')}`;
    const rawBody = Buffer.from(JSON.stringify({ type: 'test.created',
      data: { id: chunkedId, note: '€' } }), 'utf8');
    const signature = sign({ secret, id: chunkedId, timestamp: now, body: rawBody });
    const headers = { 'content-type': 'application/json', 'webhook-id': chunkedId,
      'webhook-timestamp': String(now), 'webhook-signature': signature };
    const first = await postChunkedSignedUtf8(options.endpoint,
      { id: chunkedId, timestamp: now, signature, body: rawBody, signal: timeout() });
    const afterChunked = await observe();
    // Same authenticated bytes and ID with ordinary fixed-length HTTP framing.
    const replay = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: rawBody,
    });
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [first.status, replay.status];
    const observedCounts = [afterChunked, afterReplay];
    reports.push({ scenario: 'chunked_utf8_signed_replay',
      passed: httpStatuses.every((status) => status === options.successStatus) &&
        observedCounts.every((count) => count === expectedProcessedCount),
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (config.rejectMalformedSignedPayload) {
    const malformedId = `wfl_malformed_${randomUUID().replaceAll('-', '')}`;
    const malformedBody = '{"type":"test.created","data":';
    const correctedBody = JSON.stringify({ type: 'test.created',
      data: { id: malformedId } });
    const send = (rawBody) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': malformedId,
        'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret, id: malformedId, timestamp: now, body: rawBody }) },
      body: rawBody,
    });
    // The authenticated but unparseable delivery must not reserve its dedupe ID.
    const invalid = await send(malformedBody);
    const afterInvalid = await observe();
    const corrected = await send(correctedBody);
    const afterCorrected = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [invalid.status, corrected.status];
    const observedCounts = [afterInvalid, afterCorrected];
    reports.push({ scenario: 'malformed_signed_payload_retry',
      passed: options.rejectionStatuses.includes(httpStatuses[0]) &&
        httpStatuses[1] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectWrongContentTypeRetry) {
    const mediaId = `wfl_media_${randomUUID().replaceAll('-', '')}`;
    const mediaBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: mediaId } });
    const signature = sign({ secret, id: mediaId, timestamp: now, body: mediaBody });
    const send = (contentType) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': contentType, 'webhook-id': mediaId,
        'webhook-timestamp': String(now), 'webhook-signature': signature },
      body: mediaBody,
    });
    // Changing the unsigned media type must not turn a rejected ID into a duplicate.
    const invalid = await send('text/plain');
    const afterInvalid = await observe();
    const corrected = await send('application/json');
    const afterCorrected = await observe();
    const replay = await send('application/json');
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [invalid.status, corrected.status, replay.status];
    const observedCounts = [afterInvalid, afterCorrected, afterReplay];
    reports.push({ scenario: 'wrong_content_type_retry',
      passed: httpStatuses[0] === 415 &&
        httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectWrongHttpMethodRetry) {
    const methodId = `wfl_method_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: methodId } });
    const signature = sign({ secret, id: methodId, timestamp: now, body: rawBody });
    const headers = { 'content-type': 'application/json', 'webhook-id': methodId,
      'webhook-timestamp': String(now), 'webhook-signature': signature };
    const send = (method) => request(options.endpoint, {
      method, redirect: 'manual', signal: timeout(), headers, body: rawBody,
    });
    // The method is not signed. A rejected method must neither commit nor reserve this ID.
    const wrongMethod = await send('PUT');
    const afterWrongMethod = await observe();
    const corrected = await send('POST');
    const afterCorrected = await observe();
    const replay = await send('POST');
    const afterReplay = await observe();
    const allowPost = wrongMethod.headers?.get?.('allow')?.split(',')
      .some((method) => method.trim().toUpperCase() === 'POST') ?? false;
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [wrongMethod.status, corrected.status, replay.status];
    const observedCounts = [afterWrongMethod, afterCorrected, afterReplay];
    reports.push({ scenario: 'wrong_http_method_retry',
      passed: httpStatuses[0] === 405 && allowPost &&
        httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      httpStatuses, allowPost, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectUnsupportedContentEncodingRetry) {
    const encodingId = `wfl_encoding_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: encodingId } });
    const signature = sign({ secret, id: encodingId, timestamp: now, body: rawBody });
    const headers = { 'content-type': 'application/json', 'webhook-id': encodingId,
      'webhook-timestamp': String(now), 'webhook-signature': signature };
    const send = (declaredEncoding) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: declaredEncoding ? { ...headers, 'content-encoding': declaredEncoding } : headers,
      body: rawBody,
    });
    // The intentionally false gzip declaration is unsigned; rejecting it must not cache the ID.
    const unsupported = await send('gzip');
    const afterUnsupported = await observe();
    const corrected = await send();
    const afterCorrected = await observe();
    const replay = await send();
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [unsupported.status, corrected.status, replay.status];
    const observedCounts = [afterUnsupported, afterCorrected, afterReplay];
    reports.push({ scenario: 'unsupported_content_encoding_retry',
      passed: httpStatuses[0] === 415 &&
        httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.acceptJsonCharsetContentType) {
    const charsetId = `wfl_charset_${randomUUID().replaceAll('-', '')}`;
    const charsetBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: charsetId } });
    const signature = sign({ secret, id: charsetId, timestamp: now, body: charsetBody });
    const send = (contentType) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': contentType, 'webhook-id': charsetId,
        'webhook-timestamp': String(now), 'webhook-signature': signature },
      body: charsetBody,
    });
    // Charset is an unsigned media-type parameter, not part of the event's identity.
    const parameterized = await send('application/json; charset=utf-8');
    const afterParameterized = await observe();
    const plain = await send('application/json');
    const afterPlain = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [parameterized.status, plain.status];
    const observedCounts = [afterParameterized, afterPlain];
    reports.push({ scenario: 'json_charset_content_type',
      passed: httpStatuses.every((status) => status === options.successStatus) &&
        observedCounts.every((count) => count === expectedProcessedCount),
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rawJsonSignatureBytes) {
    const rawId = `wfl_rawjson_${randomUUID().replaceAll('-', '')}`;
    const event = { type: 'test.created', timestamp: new Date(now * 1000).toISOString(),
      data: { id: rawId } };
    const prettyBody = JSON.stringify(event, null, 2) + '\n';
    const compactBody = JSON.stringify(event);
    const signature = sign({ secret, id: rawId, timestamp: now, body: prettyBody });
    const send = (wireBody) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': rawId,
        'webhook-timestamp': String(now), 'webhook-signature': signature },
      body: wireBody,
    });
    // Parsing or reserializing before HMAC verification can erase authenticated byte differences.
    const original = await send(prettyBody);
    const afterOriginal = await observe();
    const modified = await send(compactBody);
    const afterModified = await observe();
    const replay = await send(prettyBody);
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [original.status, modified.status, replay.status];
    const observedCounts = [afterOriginal, afterModified, afterReplay];
    reports.push({ scenario: 'raw_json_signature_bytes',
      passed: httpStatuses[0] === options.successStatus &&
        options.rejectionStatuses.includes(httpStatuses[1]) &&
        httpStatuses[2] === options.successStatus &&
        observedCounts.every((count) => count === expectedProcessedCount),
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectInvalidSignedEventSchema) {
    const schemaId = `wfl_schema_${randomUUID().replaceAll('-', '')}`;
    const invalidBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: {} });
    const validBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: schemaId } });
    const send = (rawBody) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': schemaId,
        'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret, id: schemaId, timestamp: now, body: rawBody }) },
      body: rawBody,
    });
    // Both payloads authenticate; schema rejection must not reserve the same event ID.
    const invalid = await send(invalidBody);
    const afterInvalid = await observe();
    const corrected = await send(validBody);
    const afterCorrected = await observe();
    const replay = await send(validBody);
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [invalid.status, corrected.status, replay.status];
    const observedCounts = [afterInvalid, afterCorrected, afterReplay];
    reports.push({ scenario: 'invalid_signed_event_schema_retry',
      passed: httpStatuses[0] === 422 &&
        httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectDuplicateJsonDataKey) {
    const eventId = `wfl_dupdata_${randomUUID().replaceAll('-', '')}`;
    const timestamp = new Date(now * 1000).toISOString();
    const early = JSON.stringify({ id: eventId, note: 'first' });
    const late = JSON.stringify({ id: eventId, note: 'second' });
    // JSON.parse accepts the last "data" key; a strict receiver must reject ambiguous bytes.
    const ambiguousBody = '{"type":"test.created","timestamp":' +
      JSON.stringify(timestamp) + ',"data":' + early + ',"data":' + late + '}';
    // A JSON escape can spell the same logical key without repeating its raw bytes.
    const escapedAmbiguousBody = '{"type":"test.created","timestamp":' +
      JSON.stringify(timestamp) + ',"data":' + early + ',"d\\u0061ta":' + late + '}';
    const correctedBody = JSON.stringify({ type: 'test.created', timestamp,
      data: { id: eventId, note: 'corrected' } });
    const send = (rawBody) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': eventId,
        'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret, id: eventId, timestamp: now, body: rawBody }) },
      body: rawBody,
    });
    const ambiguous = await send(ambiguousBody);
    const afterAmbiguous = await observe();
    const escapedAmbiguous = await send(escapedAmbiguousBody);
    const afterEscapedAmbiguous = await observe();
    const corrected = await send(correctedBody);
    const afterCorrected = await observe();
    const replay = await send(correctedBody);
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [ambiguous.status, escapedAmbiguous.status,
      corrected.status, replay.status];
    const observedCounts = [afterAmbiguous, afterEscapedAmbiguous,
      afterCorrected, afterReplay];
    reports.push({ scenario: 'duplicate_json_data_key_retry',
      passed: httpStatuses[0] === 422 &&
        httpStatuses[1] === 422 &&
        httpStatuses[2] === options.successStatus &&
        httpStatuses[3] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedCount &&
        observedCounts[2] === expectedProcessedCount &&
        observedCounts[3] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectDuplicateNestedResourceId) {
    const eventId = `wfl_nestedid_${randomUUID().replaceAll('-', '')}`;
    const timestamp = new Date(now * 1000).toISOString();
    const prefix = '{"type":"test.created","timestamp":' + JSON.stringify(timestamp) +
      ',"data":{"id":' + JSON.stringify('wfl_untrusted_resource_' + eventId);
    // Both bodies authenticate but give conflicting logical data.id values.
    const literalDuplicate = prefix + ',"id":' + JSON.stringify(eventId) + '}}';
    const escapedDuplicate = prefix + ',"i\\u0064":' + JSON.stringify(eventId) + '}}';
    const corrected = JSON.stringify({ type: 'test.created', timestamp, data: { id: eventId } });
    const send = (rawBody) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': eventId,
        'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret, id: eventId, timestamp: now, body: rawBody }) },
      body: rawBody,
    });
    const first = await send(literalDuplicate);
    const afterFirst = await observe();
    const escaped = await send(escapedDuplicate);
    const afterEscaped = await observe();
    const valid = await send(corrected);
    const afterValid = await observe();
    const replay = await send(corrected);
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [first.status, escaped.status, valid.status, replay.status];
    const observedCounts = [afterFirst, afterEscaped, afterValid, afterReplay];
    reports.push({ scenario: 'duplicate_nested_resource_id_retry',
      passed: httpStatuses[0] === 422 && httpStatuses[1] === 422 &&
        httpStatuses[2] === options.successStatus &&
        httpStatuses[3] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedCount &&
        observedCounts[2] === expectedProcessedCount &&
        observedCounts[3] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectMissingSignatureRetry) {
    const missingId = `wfl_missinghmac_${randomUUID().replaceAll('-', '')}`;
    const missingBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: missingId } });
    const signature = sign({ secret, id: missingId, timestamp: now, body: missingBody });
    const send = (withSignature) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': missingId,
        'webhook-timestamp': String(now),
        ...(withSignature ? { 'webhook-signature': signature } : {}) },
      body: missingBody,
    });
    // Rejecting an unauthenticated ID must not poison its later signed retry.
    const missing = await send(false);
    const afterMissing = await observe();
    const corrected = await send(true);
    const afterCorrected = await observe();
    const replay = await send(true);
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [missing.status, corrected.status, replay.status];
    const observedCounts = [afterMissing, afterCorrected, afterReplay];
    reports.push({ scenario: 'missing_signature_retry',
      passed: options.rejectionStatuses.includes(httpStatuses[0]) &&
        httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectUnsupportedSignatureVersion) {
    const eventId = `wfl_sigversion_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: eventId } });
    const validSignature = sign({ secret, id: eventId, timestamp: now, body: rawBody });
    // Preserve the correct digest; changing only the version catches parsers
    // that authenticate the bytes but silently ignore the algorithm identifier.
    const unsupportedSignature = `v2,${validSignature.slice(3)}`;
    const send = (signature) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': eventId,
        'webhook-timestamp': String(now), 'webhook-signature': signature },
      body: rawBody,
    });
    const unsupported = await send(unsupportedSignature);
    const afterUnsupported = await observe();
    const corrected = await send(validSignature);
    const afterCorrected = await observe();
    const replay = await send(validSignature);
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [unsupported.status, corrected.status, replay.status];
    const observedCounts = [afterUnsupported, afterCorrected, afterReplay];
    reports.push({ scenario: 'unsupported_signature_version_retry',
      passed: options.rejectionStatuses.includes(httpStatuses[0]) &&
        httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectMissingTimestampRetry) {
    const missingId = `wfl_missingts_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: missingId } });
    const signature = sign({ secret, id: missingId, timestamp: now, body: rawBody });
    const send = (withTimestamp) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': missingId,
        ...(withTimestamp ? { 'webhook-timestamp': String(now) } : {}),
        'webhook-signature': signature },
      body: rawBody,
    });
    // An event with no signed timestamp must not reserve its ID before a valid retry.
    const missing = await send(false);
    const afterMissing = await observe();
    const corrected = await send(true);
    const afterCorrected = await observe();
    const replay = await send(true);
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [missing.status, corrected.status, replay.status];
    const observedCounts = [afterMissing, afterCorrected, afterReplay];
    reports.push({ scenario: 'missing_timestamp_retry',
      passed: options.rejectionStatuses.includes(httpStatuses[0]) &&
        httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectMissingEventIdRetry) {
    const missingId = `wfl_missingid_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: missingId } });
    const signature = sign({ secret, id: missingId, timestamp: now, body: rawBody });
    const send = (withId) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json',
        ...(withId ? { 'webhook-id': missingId } : {}),
        'webhook-timestamp': String(now), 'webhook-signature': signature },
      body: rawBody,
    });
    // An unsigned body field cannot replace the authenticated event ID header.
    const missing = await send(false);
    const afterMissing = await observe();
    const corrected = await send(true);
    const afterCorrected = await observe();
    const replay = await send(true);
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [missing.status, corrected.status, replay.status];
    const observedCounts = [afterMissing, afterCorrected, afterReplay];
    reports.push({ scenario: 'missing_event_id_retry',
      passed: options.rejectionStatuses.includes(httpStatuses[0]) &&
        httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectDuplicateWireEventIdRetry) {
    const eventId = `wfl_dupheader_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: eventId } });
    const signature = sign({ secret, id: eventId, timestamp: now, body: rawBody });
    const headers = { 'content-type': 'application/json', 'webhook-id': eventId,
      'webhook-timestamp': String(now), 'webhook-signature': signature };
    const ambiguous = await postWithDuplicateWireId(options.endpoint, {
      id: eventId, timestamp: now, signature, body: rawBody, signal: timeout(),
    });
    const afterAmbiguous = await observe();
    const send = () => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: rawBody,
    });
    const corrected = await send();
    const afterCorrected = await observe();
    const replay = await send();
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [ambiguous.status, corrected.status, replay.status];
    const observedCounts = [afterAmbiguous, afterCorrected, afterReplay];
    reports.push({ scenario: 'duplicate_wire_event_id_retry',
      passed: options.rejectionStatuses.includes(httpStatuses[0]) &&
        httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectDuplicateWireTimestampRetry) {
    const eventId = `wfl_dupts_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: eventId } });
    const signature = sign({ secret, id: eventId, timestamp: now, body: rawBody });
    const headers = { 'content-type': 'application/json', 'webhook-id': eventId,
      'webhook-timestamp': String(now), 'webhook-signature': signature };
    const ambiguousFirst = await postWithDuplicateWireTimestamp(options.endpoint, {
      id: eventId, timestamp: now, signature, body: rawBody, signal: timeout(),
    });
    const afterFirst = await observe();
    const ambiguousLast = await postWithDuplicateWireTimestamp(options.endpoint, {
      id: eventId, timestamp: now, signature, body: rawBody, signal: timeout(), staleFirst: true,
    });
    const afterLast = await observe();
    const send = () => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: rawBody,
    });
    const corrected = await send();
    const afterCorrected = await observe();
    const replay = await send();
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [ambiguousFirst.status, ambiguousLast.status,
      corrected.status, replay.status];
    const observedCounts = [afterFirst, afterLast, afterCorrected, afterReplay];
    reports.push({ scenario: 'duplicate_wire_timestamp_retry',
      passed: options.rejectionStatuses.includes(httpStatuses[0]) &&
        options.rejectionStatuses.includes(httpStatuses[1]) &&
        httpStatuses[2] === options.successStatus &&
        httpStatuses[3] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedCount &&
        observedCounts[2] === expectedProcessedCount &&
        observedCounts[3] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectDuplicateWireSignatureRetry) {
    const eventId = `wfl_dupsig_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: eventId } });
    const signature = sign({ secret, id: eventId, timestamp: now, body: rawBody });
    const headers = { 'content-type': 'application/json', 'webhook-id': eventId,
      'webhook-timestamp': String(now), 'webhook-signature': signature };
    const validFirst = await postWithDuplicateWireSignature(options.endpoint, {
      id: eventId, timestamp: now, signature, body: rawBody, signal: timeout(),
    });
    const afterValidFirst = await observe();
    const invalidFirst = await postWithDuplicateWireSignature(options.endpoint, {
      id: eventId, timestamp: now, signature, body: rawBody,
      signal: timeout(), invalidFirst: true,
    });
    const afterInvalidFirst = await observe();
    const send = () => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: rawBody,
    });
    const corrected = await send();
    const afterCorrected = await observe();
    const replay = await send();
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [validFirst.status, invalidFirst.status,
      corrected.status, replay.status];
    const observedCounts = [afterValidFirst, afterInvalidFirst, afterCorrected, afterReplay];
    reports.push({ scenario: 'duplicate_wire_signature_retry',
      passed: options.rejectionStatuses.includes(httpStatuses[0]) &&
        options.rejectionStatuses.includes(httpStatuses[1]) &&
        httpStatuses[2] === options.successStatus &&
        httpStatuses[3] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedCount &&
        observedCounts[2] === expectedProcessedCount &&
        observedCounts[3] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectDuplicateWireContentTypeRetry) {
    const eventId = `wfl_dupctype_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: eventId } });
    const signature = sign({ secret, id: eventId, timestamp: now, body: rawBody });
    const headers = { 'content-type': 'application/json', 'webhook-id': eventId,
      'webhook-timestamp': String(now), 'webhook-signature': signature };
    const jsonFirst = await postWithDuplicateWireContentType(options.endpoint, {
      id: eventId, timestamp: now, signature, body: rawBody, signal: timeout(),
    });
    const afterJsonFirst = await observe();
    const textFirst = await postWithDuplicateWireContentType(options.endpoint, {
      id: eventId, timestamp: now, signature, body: rawBody, signal: timeout(),
      jsonFirst: false,
    });
    const afterTextFirst = await observe();
    const send = () => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: rawBody,
    });
    const corrected = await send();
    const afterCorrected = await observe();
    const replay = await send();
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [jsonFirst.status, textFirst.status,
      corrected.status, replay.status];
    const observedCounts = [afterJsonFirst, afterTextFirst, afterCorrected, afterReplay];
    reports.push({ scenario: 'duplicate_wire_content_type_retry',
      passed: options.rejectionStatuses.includes(httpStatuses[0]) &&
        options.rejectionStatuses.includes(httpStatuses[1]) &&
        httpStatuses[2] === options.successStatus &&
        httpStatuses[3] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedCount &&
        observedCounts[2] === expectedProcessedCount &&
        observedCounts[3] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectDuplicateWireContentEncodingRetry) {
    const eventId = `wfl_dupencoding_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: eventId } });
    const signature = sign({ secret, id: eventId, timestamp: now, body: rawBody });
    const headers = { 'content-type': 'application/json', 'webhook-id': eventId,
      'webhook-timestamp': String(now), 'webhook-signature': signature };
    const identityFirst = await postWithDuplicateWireContentEncoding(options.endpoint, {
      id: eventId, timestamp: now, signature, body: rawBody, signal: timeout(),
    });
    const afterIdentityFirst = await observe();
    const gzipFirst = await postWithDuplicateWireContentEncoding(options.endpoint, {
      id: eventId, timestamp: now, signature, body: rawBody, signal: timeout(),
      identityFirst: false,
    });
    const afterGzipFirst = await observe();
    const send = () => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: rawBody,
    });
    const corrected = await send();
    const afterCorrected = await observe();
    const replay = await send();
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [identityFirst.status, gzipFirst.status,
      corrected.status, replay.status];
    const observedCounts = [afterIdentityFirst, afterGzipFirst, afterCorrected, afterReplay];
    reports.push({ scenario: 'duplicate_wire_content_encoding_retry',
      passed: options.rejectionStatuses.includes(httpStatuses[0]) &&
        options.rejectionStatuses.includes(httpStatuses[1]) &&
        httpStatuses[2] === options.successStatus &&
        httpStatuses[3] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedCount &&
        observedCounts[2] === expectedProcessedCount &&
        observedCounts[3] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectInvalidUtf8Retry) {
    const eventId = `wfl_utf8_${randomUUID().replaceAll('-', '')}`;
    const event = { type: 'test.created', timestamp: new Date(now * 1000).toISOString(),
      data: { id: eventId, note: '!' } };
    // Replace a JSON string's ASCII marker with an invalid standalone UTF-8 byte.
    // A lossy decoder still produces parseable JSON, exposing silent replacement.
    const malformed = Buffer.from(JSON.stringify(event), 'utf8');
    const marker = malformed.lastIndexOf(0x21);
    if (marker === -1) throw new Error('UTF-8 probe marker was not found');
    malformed[marker] = 0xff;
    const corrected = JSON.stringify({ ...event, data: { id: eventId, note: 'valid' } });
    const send = (body) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': eventId,
        'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret, id: eventId, timestamp: now, body }) },
      body,
    });
    const invalid = await send(malformed);
    const afterInvalid = await observe();
    const valid = await send(corrected);
    const afterValid = await observe();
    const replay = await send(corrected);
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [invalid.status, valid.status, replay.status];
    const observedCounts = [afterInvalid, afterValid, afterReplay];
    reports.push({ scenario: 'invalid_utf8_signed_retry',
      passed: options.rejectionStatuses.includes(httpStatuses[0]) &&
        httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectOversizedSignedPayload) {
    const oversizedId = `wfl_oversize_${randomUUID().replaceAll('-', '')}`;
    const event = { type: 'test.created', timestamp: new Date(now * 1000).toISOString(),
      data: { id: oversizedId } };
    const oversizedBody = JSON.stringify({ ...event, data: { ...event.data,
      note: 'x'.repeat(2048) } });
    const correctedBody = JSON.stringify(event);
    const send = (rawBody) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': oversizedId,
        'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret, id: oversizedId, timestamp: now, body: rawBody }) },
      body: rawBody,
    });
    // Valid HMACs do not exempt a payload from a local body-size policy.
    const invalid = await send(oversizedBody);
    const afterInvalid = await observe();
    const corrected = await send(correctedBody);
    const afterCorrected = await observe();
    const replay = await send(correctedBody);
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [invalid.status, corrected.status, replay.status];
    const observedCounts = [afterInvalid, afterCorrected, afterReplay];
    reports.push({ scenario: 'oversized_signed_payload_retry',
      passed: httpStatuses[0] === 413 &&
        httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectOversizedGzipRetry) {
    const compressedId = `wfl_gzipcap_${randomUUID().replaceAll('-', '')}`;
    const event = { type: 'test.created', timestamp: new Date(now * 1000).toISOString(),
      data: { id: compressedId } };
    const oversizedBody = JSON.stringify({ ...event,
      data: { ...event.data, note: 'x'.repeat(2048) } });
    const oversizedGzip = gzipSync(Buffer.from(oversizedBody, 'utf8'));
    const correctedGzip = gzipSync(Buffer.from(JSON.stringify(event), 'utf8'));
    const compressedBodyBelowLimit = oversizedGzip.length < 1024;
    const inflatedBodyExceedsLimit = Buffer.byteLength(oversizedBody, 'utf8') > 1024;
    const send = (wireBody) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'content-encoding': 'gzip',
        'webhook-id': compressedId, 'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret, id: compressedId, timestamp: now, body: wireBody }) },
      body: wireBody,
    });
    // Authenticate compressed wire bytes; enforce the local size cap on inflated JSON.
    const invalid = await send(oversizedGzip);
    const afterInvalid = await observe();
    const corrected = await send(correctedGzip);
    const afterCorrected = await observe();
    const replay = await send(correctedGzip);
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [invalid.status, corrected.status, replay.status];
    const observedCounts = [afterInvalid, afterCorrected, afterReplay];
    reports.push({ scenario: 'oversized_gzip_retry',
      passed: compressedBodyBelowLimit && inflatedBodyExceedsLimit &&
        httpStatuses[0] === 413 && httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount,
      compressedBodyBelowLimit, inflatedBodyExceedsLimit });
    expectedCount = expectedProcessedCount;
  }

  if (options.rejectMalformedGzipRetry) {
    const gzipId = `wfl_gzipbad_${randomUUID().replaceAll('-', '')}`;
    const event = { type: 'test.created', timestamp: new Date(now * 1000).toISOString(),
      data: { id: gzipId } };
    const correctedGzip = gzipSync(Buffer.from(JSON.stringify(event), 'utf8'));
    // Both malformed deliveries carry a valid HMAC over their exact corrupt wire bytes.
    const truncatedGzip = correctedGzip.subarray(0, correctedGzip.length - 4);
    const badChecksumGzip = Buffer.from(correctedGzip);
    badChecksumGzip[badChecksumGzip.length - 8] ^= 1;
    const corruptWireBodiesBelowLimit = truncatedGzip.length < 1024 &&
      badChecksumGzip.length < 1024;
    const send = (wireBody) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'content-encoding': 'gzip',
        'webhook-id': gzipId, 'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret, id: gzipId, timestamp: now, body: wireBody }) },
      body: wireBody,
    });
    const truncated = await send(truncatedGzip);
    const afterTruncated = await observe();
    const badChecksum = await send(badChecksumGzip);
    const afterBadChecksum = await observe();
    const corrected = await send(correctedGzip);
    const afterCorrected = await observe();
    const replay = await send(correctedGzip);
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [truncated.status, badChecksum.status, corrected.status, replay.status];
    const observedCounts = [afterTruncated, afterBadChecksum, afterCorrected, afterReplay];
    reports.push({ scenario: 'malformed_gzip_retry',
      passed: corruptWireBodiesBelowLimit &&
        httpStatuses[0] === 400 && httpStatuses[1] === 400 &&
        httpStatuses[2] === options.successStatus &&
        httpStatuses[3] === options.successStatus &&
        observedCounts[0] === expectedCount && observedCounts[1] === expectedCount &&
        observedCounts[2] === expectedProcessedCount &&
        observedCounts[3] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount, corruptWireBodiesBelowLimit });
    expectedCount = expectedProcessedCount;
  }

  if (options.retryAfterRejectedSignature) {
    const retryId = `wfl_authretry_${randomUUID().replaceAll('-', '')}`;
    const retryBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: retryId } });
    const validSignature = sign({ secret, id: retryId, timestamp: now, body: retryBody });
    const invalidSignature = validSignature.slice(0, 3) +
      (validSignature[3] === 'A' ? 'B' : 'A') + validSignature.slice(4);
    const send = (signature) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': retryId,
        'webhook-timestamp': String(now), 'webhook-signature': signature },
      body: retryBody,
    });
    // A rejected unauthenticated delivery must not reserve its future valid retry's ID.
    const invalid = await send(invalidSignature);
    const afterInvalid = await observe();
    const valid = await send(validSignature);
    const afterValid = await observe();
    const replay = await send(validSignature);
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [invalid.status, valid.status, replay.status];
    const observedCounts = [afterInvalid, afterValid, afterReplay];
    reports.push({ scenario: 'retry_after_rejected_signature',
      passed: options.rejectionStatuses.includes(httpStatuses[0]) &&
        httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

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

  if (options.retryAfterRateLimit) {
    const id = `wfl_429_${randomUUID().replaceAll('-', '')}`;
    const body = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id } });
    const headers = { 'content-type': 'application/json', 'webhook-id': id,
      'webhook-timestamp': String(now),
      'webhook-signature': sign({ secret, id, timestamp: now, body }) };
    // A declared local adapter refuses the first attempt before reserving the signed ID.
    const throttled = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { ...headers, 'x-wfl-test-fault': 'rate-limit-before-process-once' }, body,
    });
    const afterThrottle = await observe();
    const retryAfterZero = throttled.headers?.get('retry-after') === '0';
    const retry = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body,
    });
    const afterRetry = await observe();
    const replay = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body,
    });
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [throttled.status, retry.status, replay.status];
    const observedCounts = [afterThrottle, afterRetry, afterReplay];
    reports.push({ scenario: 'retry_after_rate_limit',
      passed: httpStatuses[0] === 429 && retryAfterZero &&
        httpStatuses[1] === options.successStatus &&
        httpStatuses[2] === options.successStatus &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      httpStatuses, retryAfterZero, observedCounts, expectedProcessedCount });
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

  if (options.timeoutAfterCommit) {
    const timeoutId = `wfl_timeout_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: timeoutId } });
    const headers = { 'content-type': 'application/json', 'webhook-id': timeoutId,
      'webhook-timestamp': String(now),
      'webhook-signature': sign({ secret, id: timeoutId, timestamp: now, body: rawBody }) };
    // The test-only receiver commits before holding HTTP acknowledgement until the client aborts.
    let firstAttemptOutcome;
    try {
      const first = await request(options.endpoint, {
        method: 'POST', redirect: 'manual', signal: timeout(),
        headers: { ...headers, 'x-wfl-test-fault': 'commit-then-hold-ack-until-timeout' },
        body: rawBody,
      });
      firstAttemptOutcome = `http_${first.status}`;
    } catch (error) {
      firstAttemptOutcome = error?.name === 'TimeoutError' ? 'client_timeout' : 'transport_error';
    }
    const observedCountAfterTimeout = await observe();
    const retry = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: rawBody,
    });
    const count = await observe();
    const expectedProcessedCount = expectedCount + 1;
    reports.push({ scenario: 'client_timeout_after_commit',
      passed: firstAttemptOutcome === 'client_timeout' &&
        observedCountAfterTimeout === expectedProcessedCount &&
        retry.status === options.successStatus && count === expectedProcessedCount,
      firstAttemptOutcome, observedCountAfterTimeout, retryHttpStatus: retry.status,
      observedProcessedCount: count, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.timeoutBeforeCommit) {
    const timeoutId = `wfl_precommit_timeout_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: timeoutId } });
    const headers = { 'content-type': 'application/json', 'webhook-id': timeoutId,
      'webhook-timestamp': String(now),
      'webhook-signature': sign({ secret, id: timeoutId, timestamp: now, body: rawBody }) };
    // The synthetic fault holds the response without committing or reserving the ID.
    let firstAttemptOutcome;
    try {
      const first = await request(options.endpoint, {
        method: 'POST', redirect: 'manual', signal: timeout(),
        headers: { ...headers, 'x-wfl-test-fault': 'hold-before-commit-until-timeout' },
        body: rawBody,
      });
      firstAttemptOutcome = `http_${first.status}`;
    } catch (error) {
      firstAttemptOutcome = error?.name === 'TimeoutError' ? 'client_timeout' : 'transport_error';
    }
    const observedCountAfterTimeout = await observe();
    const retry = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: rawBody,
    });
    const observedCountAfterRetry = await observe();
    const replay = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: rawBody,
    });
    const count = await observe();
    const expectedProcessedCount = expectedCount + 1;
    reports.push({ scenario: 'client_timeout_before_commit',
      passed: firstAttemptOutcome === 'client_timeout' &&
        observedCountAfterTimeout === expectedCount &&
        retry.status === options.successStatus &&
        observedCountAfterRetry === expectedProcessedCount &&
        replay.status === options.successStatus && count === expectedProcessedCount,
      firstAttemptOutcome, observedCountAfterTimeout, retryHttpStatus: retry.status,
      observedCountAfterRetry, replayHttpStatus: replay.status,
      observedProcessedCount: count, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (config.versionedOutOfOrderUpdates) {
    const resourceId = `wfl_version_resource_${randomUUID().replaceAll('-', '')}`;
    const makeVersion = (version) => {
      const messageId = `wfl_version_event_${randomUUID().replaceAll('-', '')}`;
      const rawBody = JSON.stringify({ type: 'test.resource.versioned',
        data: { id: resourceId, version } });
      return { rawBody, headers: { 'content-type': 'application/json',
        'webhook-id': messageId, 'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret, id: messageId, timestamp: now, body: rawBody }) } };
    };
    const send = (event) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: event.headers, body: event.rawBody,
    });
    // A delayed v2 is a new authenticated event, not a duplicate of v3.
    const first = await send(makeVersion(1));
    const afterFirst = await observeState(resourceId);
    const newest = await send(makeVersion(3));
    const afterNewest = await observeState(resourceId);
    const late = await send(makeVersion(2));
    const afterLate = await observeState(resourceId);
    const httpStatuses = [first.status, newest.status, late.status];
    const observedCounts = [afterFirst.processedCount, afterNewest.processedCount,
      afterLate.processedCount];
    const observedResourceVersions = [afterFirst.resourceVersion ?? null,
      afterNewest.resourceVersion ?? null, afterLate.resourceVersion ?? null];
    const expectedProcessedCount = expectedCount + 2;
    reports.push({ scenario: 'versioned_out_of_order_update',
      passed: httpStatuses[0] === options.successStatus &&
        httpStatuses[1] === options.successStatus && httpStatuses[2] === 409 &&
        observedCounts[0] === expectedCount + 1 &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount &&
        observedResourceVersions[0] === 1 &&
        observedResourceVersions[1] === 3 &&
        observedResourceVersions[2] === 3,
      httpStatuses, observedCounts, observedResourceVersions, expectedProcessedCount });
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

  if (options.delayedCreationReplayAfterActivation) {
    const resourceId = `wfl_resource_${randomUUID().replaceAll('-', '')}`;
    const makeEvent = (type, name) => {
      const messageId = `wfl_order_latecreate_${name}_${randomUUID().replaceAll('-', '')}`;
      const rawBody = JSON.stringify({ type, timestamp: new Date(now * 1000).toISOString(),
        data: { id: resourceId } });
      return { rawBody, headers: {
        'content-type': 'application/json', 'webhook-id': messageId,
        'webhook-timestamp': String(now),
        'webhook-signature': sign({ secret, id: messageId, timestamp: now, body: rawBody }),
      } };
    };
    const create = makeEvent('test.resource.created', 'create');
    const activate = makeEvent('test.resource.activated', 'activate');
    const send = (event) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: event.headers, body: event.rawBody,
    });
    // Re-delivery of the exact creation event must not rewind an already activated resource.
    const first = await send(create);
    const afterCreate = await observeState(resourceId);
    const second = await send(activate);
    const afterActivation = await observeState(resourceId);
    const third = await send(create);
    const afterReplay = await observeState(resourceId);
    const httpStatuses = [first.status, second.status, third.status];
    const observedCounts = [afterCreate.processedCount,
      afterActivation.processedCount, afterReplay.processedCount];
    const observedResourceStates = [afterCreate.resourceState ?? null,
      afterActivation.resourceState ?? null, afterReplay.resourceState ?? null];
    const expectedProcessedCount = expectedCount + 2;
    reports.push({ scenario: 'delayed_creation_replay_after_activation',
      passed: httpStatuses.every((status) => status === options.successStatus) &&
        observedCounts[0] === expectedCount + 1 &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount &&
        observedResourceStates[0] === 'created' &&
        observedResourceStates[1] === 'activated' &&
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
    const retries = await Promise.all(Array.from({
      length: options.parallelCrashRecoveryRetries ?? 1,
    }, () => request(recoveredEndpoint, {
        method: 'POST', redirect: 'manual', signal: timeout(), headers, body: crashBody,
    })));
    const afterRetry = await observeState(undefined, recoveredObserver);
    const replay = options.parallelCrashRecoveryRetries === undefined ? null :
      await request(recoveredEndpoint, {
        method: 'POST', redirect: 'manual', signal: timeout(), headers, body: crashBody,
      });
    const afterReplay = replay === null ? null :
      await observeState(undefined, recoveredObserver);
    const expectedProcessedCount = expectedCount + 1;
    const observedCounts = [beforeCrash.processedCount, afterRecovery.processedCount,
      afterRetry.processedCount];
    if (afterReplay !== null) observedCounts.push(afterReplay.processedCount);
    const receiverInstanceIds = [beforeCrash.receiverInstanceId ?? null,
      afterRecovery.receiverInstanceId ?? null];
    const retryHttpStatuses = retries.map((response) => response.status);
    reports.push({ scenario: options.parallelCrashRecoveryRetries === undefined ?
      'crash_after_persist_before_ack' : 'crash_after_persist_parallel_retries',
      passed: firstAttemptOutcome === 'transport_error' &&
        retryHttpStatuses.every((status) => status === options.successStatus) &&
        (replay === null || replay.status === options.successStatus) &&
        observedCounts[0] === expectedCount &&
        observedCounts.slice(1).every((count) => count === expectedProcessedCount) &&
        receiverInstanceIds.every((value) => typeof value === 'string' && value.length > 0) &&
        receiverInstanceIds[0] !== receiverInstanceIds[1],
      firstAttemptOutcome, retryHttpStatus: retryHttpStatuses[0], retryHttpStatuses,
      ...(replay === null ? {} : { replayHttpStatus: replay.status }),
      observedCounts,
      receiverInstanceIds, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.crashBeforeCommit) {
    const beforeCrash = await observeState();
    const crashId = `wfl_precrash_${randomUUID().replaceAll('-', '')}`;
    const crashBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: crashId } });
    const headers = { 'content-type': 'application/json', 'webhook-id': crashId,
      'webhook-timestamp': String(now),
      'webhook-signature': sign({ secret, id: crashId, timestamp: now, body: crashBody }) };
    let firstAttemptOutcome;
    try {
      const first = await request(options.endpoint, {
        method: 'POST', redirect: 'manual', signal: timeout(),
        headers: { ...headers, 'x-wfl-test-fault': 'crash-before-commit' }, body: crashBody,
      });
      firstAttemptOutcome = `http_${first.status}`;
    } catch {
      firstAttemptOutcome = 'transport_error';
    }
    // Only a test-controlled local process may be recovered, never an arbitrary endpoint.
    const recovered = await recoverReceiver();
    const recoveredEndpoint = requireLoopbackUrl(recovered?.endpoint, 'recoverReceiver endpoint');
    const recoveredObserver = requireLoopbackUrl(recovered?.observer, 'recoverReceiver observer');
    const afterRecovery = await observeState(undefined, recoveredObserver);
    const retries = await Promise.all(Array.from({
      length: options.parallelCrashRecoveryRetries ?? 1,
    }, () => request(recoveredEndpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: crashBody,
    })));
    const afterRetry = await observeState(undefined, recoveredObserver);
    const replay = await request(recoveredEndpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: crashBody,
    });
    const afterReplay = await observeState(undefined, recoveredObserver);
    const expectedProcessedCount = expectedCount + 1;
    const observedCounts = [beforeCrash.processedCount, afterRecovery.processedCount,
      afterRetry.processedCount, afterReplay.processedCount];
    const receiverInstanceIds = [beforeCrash.receiverInstanceId ?? null,
      afterRecovery.receiverInstanceId ?? null];
    const retryHttpStatuses = retries.map((response) => response.status);
    reports.push({ scenario: options.parallelCrashRecoveryRetries === undefined ?
      'crash_before_commit_retry' : 'crash_before_commit_parallel_retries',
      passed: firstAttemptOutcome === 'transport_error' &&
        retryHttpStatuses.every((status) => status === options.successStatus) &&
        replay.status === options.successStatus &&
        observedCounts[0] === expectedCount && observedCounts[1] === expectedCount &&
        observedCounts[2] === expectedProcessedCount &&
        observedCounts[3] === expectedProcessedCount &&
        receiverInstanceIds.every((value) => typeof value === 'string' && value.length > 0) &&
        receiverInstanceIds[0] !== receiverInstanceIds[1],
      firstAttemptOutcome, retryHttpStatus: retryHttpStatuses[0], retryHttpStatuses,
      replayHttpStatus: replay.status,
      observedCounts, receiverInstanceIds, expectedProcessedCount });
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

  if (options.tenantScopedEventIds) {
    const tenantId = `wfl_tenant_${randomUUID().replaceAll('-', '')}`;
    const bodyA = JSON.stringify({ type: 'test.created', data: { id: tenantId, tenant: 'a' } });
    const bodyB = JSON.stringify({ type: 'test.created', data: { id: tenantId, tenant: 'b' } });
    const send = (tenant, signingKey, rawBody) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': tenantId,
        'webhook-timestamp': String(now), 'x-wfl-test-tenant': tenant,
        'webhook-signature': sign({ secret: signingKey, id: tenantId,
          timestamp: now, body: rawBody }) },
      body: rawBody,
    });
    const deliveries = [
      ['a', secret, bodyA],
      ['b', tenantBSecret, bodyB],
      ['a', tenantBSecret, bodyA],
      ['a', secret, bodyA],
      ['b', tenantBSecret, bodyB],
    ];
    const httpStatuses = [];
    const observedCounts = [];
    for (const [tenant, signingKey, rawBody] of deliveries) {
      const response = await send(tenant, signingKey, rawBody);
      httpStatuses.push(response.status);
      observedCounts.push(await observe());
    }
    const expectedCounts = [expectedCount + 1, expectedCount + 2,
      expectedCount + 2, expectedCount + 2, expectedCount + 2];
    reports.push({ scenario: 'tenant_scoped_signed_event_ids',
      passed: httpStatuses.every((status, index) => index === 2
        ? options.rejectionStatuses.includes(status) && status !== 409
        : status === options.successStatus) &&
        observedCounts.every((count, index) => count === expectedCounts[index]),
      httpStatuses, observedCounts, expectedProcessedCount: expectedCount + 2 });
    expectedCount += 2;
  }

  if (options.distinctEventsSameResource) {
    const resourceId = `wfl_shared_resource_${randomUUID().replaceAll('-', '')}`;
    const eventRoot = `wfl_sharedres_${randomUUID().replaceAll('-', '')}`;
    const events = ['created', 'updated'].map((kind, index) => {
      const eventId = `${eventRoot}_${kind}`;
      const rawBody = JSON.stringify({ type: `test.resource.${kind}`,
        timestamp: new Date(now * 1000).toISOString(),
        data: { id: resourceId, sequence: index + 1 } });
      return { eventId, rawBody,
        signature: sign({ secret, id: eventId, timestamp: now, body: rawBody }) };
    });
    const httpStatuses = [];
    const observedCounts = [];
    for (const event of [...events, ...events]) {
      const response = await request(options.endpoint, {
        method: 'POST', redirect: 'manual', signal: timeout(),
        headers: { 'content-type': 'application/json',
          'webhook-id': event.eventId, 'webhook-timestamp': String(now),
          'webhook-signature': event.signature },
        body: event.rawBody,
      });
      httpStatuses.push(response.status);
      observedCounts.push(await observe());
    }
    // Delivery IDs, not the shared business resource ID, define idempotency here.
    const expectedCounts = [expectedCount + 1, expectedCount + 2,
      expectedCount + 2, expectedCount + 2];
    reports.push({ scenario: 'distinct_events_same_resource',
      passed: httpStatuses.every((status) => status === options.successStatus) &&
        observedCounts.every((count, index) => count === expectedCounts[index]),
      httpStatuses, observedCounts, expectedProcessedCount: expectedCount + 2 });
    expectedCount += 2;
  }

  if (options.distinctIdsIdenticalBody) {
    const eventRoot = `wfl_identical_${randomUUID().replaceAll('-', '')}`;
    const eventIds = [`${eventRoot}_one`, `${eventRoot}_two`];
    // Neither signed delivery ID appears in the body: the raw bytes must match.
    const rawBody = JSON.stringify({ type: 'test.delivery.received',
      timestamp: new Date(now * 1000).toISOString(),
      data: { id: `wfl_identical_payload_${randomUUID().replaceAll('-', '')}` } });
    const events = eventIds.map((eventId) => ({
      eventId, signature: sign({ secret, id: eventId, timestamp: now, body: rawBody }),
    }));
    const httpStatuses = [];
    const observedCounts = [];
    for (const event of [...events, ...events]) {
      const response = await request(options.endpoint, {
        method: 'POST', redirect: 'manual', signal: timeout(),
        headers: { 'content-type': 'application/json',
          'webhook-id': event.eventId, 'webhook-timestamp': String(now),
          'webhook-signature': event.signature },
        body: rawBody,
      });
      httpStatuses.push(response.status);
      observedCounts.push(await observe());
    }
    const expectedCounts = [expectedCount + 1, expectedCount + 2,
      expectedCount + 2, expectedCount + 2];
    reports.push({ scenario: 'distinct_ids_identical_signed_body',
      passed: httpStatuses.every((status) => status === options.successStatus) &&
        observedCounts.every((count, index) => count === expectedCounts[index]),
      httpStatuses, observedCounts, expectedProcessedCount: expectedCount + 2 });
    expectedCount += 2;
  }

  if (options.caseSensitiveEventIds) {
    const rootId = `wfl_case_${randomUUID().replaceAll('-', '')}`;
    const ids = [`${rootId}_a`, `${rootId}_A`];
    const send = (eventId) => {
      const rawBody = JSON.stringify({ type: 'test.created',
        timestamp: new Date(now * 1000).toISOString(), data: { id: eventId } });
      return request(options.endpoint, {
        method: 'POST', redirect: 'manual', signal: timeout(),
        headers: { 'content-type': 'application/json', 'webhook-id': eventId,
          'webhook-timestamp': String(now),
          'webhook-signature': sign({ secret, id: eventId, timestamp: now, body: rawBody }) },
        body: rawBody,
      });
    };
    // Only the ASCII-case variant differs: each authentic ID is independently deliverable.
    const httpStatuses = [];
    const observedCounts = [];
    for (const eventId of [ids[0], ids[1], ids[0], ids[1]]) {
      const response = await send(eventId);
      httpStatuses.push(response.status);
      observedCounts.push(await observe());
    }
    const expectedCounts = [expectedCount + 1, expectedCount + 2,
      expectedCount + 2, expectedCount + 2];
    reports.push({ scenario: 'case_sensitive_event_ids',
      passed: httpStatuses.every((status) => status === options.successStatus) &&
        observedCounts.every((count, index) => count === expectedCounts[index]),
      httpStatuses, observedCounts, expectedProcessedCount: expectedCount + 2 });
    expectedCount += 2;
  }

  if (options.prototypePropertyEventIds) {
    // Exact object-prototype names expose JavaScript object-backed dedupe maps.
    // This opt-in contract requires receivers to accept these signed ID values.
    const ids = ['__proto__', 'constructor'];
    const messages = ids.map((eventId) => {
      const rawBody = JSON.stringify({ type: 'test.created',
        timestamp: new Date(now * 1000).toISOString(),
        data: { id: `wfl_property_payload_${randomUUID().replaceAll('-', '')}` } });
      return { eventId, rawBody,
        signature: sign({ secret, id: eventId, timestamp: now, body: rawBody }) };
    });
    const httpStatuses = [];
    const observedCounts = [];
    for (const message of [...messages, ...messages]) {
      const response = await request(options.endpoint, {
        method: 'POST', redirect: 'manual', signal: timeout(),
        headers: { 'content-type': 'application/json',
          'webhook-id': message.eventId, 'webhook-timestamp': String(now),
          'webhook-signature': message.signature },
        body: message.rawBody,
      });
      httpStatuses.push(response.status);
      observedCounts.push(await observe());
    }
    const expectedCounts = [expectedCount + 1, expectedCount + 2,
      expectedCount + 2, expectedCount + 2];
    reports.push({ scenario: 'prototype_property_event_ids',
      passed: httpStatuses.every((status) => status === options.successStatus) &&
        observedCounts.every((count, index) => count === expectedCounts[index]),
      httpStatuses, observedCounts, expectedProcessedCount: expectedCount + 2 });
    expectedCount += 2;
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

  if (options.rejectFutureDuplicateSignature) {
    const duplicateId = `wfl_futuredup_${randomUUID().replaceAll('-', '')}`;
    const duplicateBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: duplicateId } });
    // A valid new HMAC over a future timestamp must not bypass freshness via a cached ID.
    const send = (timestamp) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': duplicateId,
        'webhook-timestamp': String(timestamp),
        'webhook-signature': sign({ secret, id: duplicateId, timestamp, body: duplicateBody }) },
      body: duplicateBody,
    });
    const original = await send(now);
    const afterOriginal = await observe();
    const future = await send(now + 3600);
    const afterFuture = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [original.status, future.status];
    const observedCounts = [afterOriginal, afterFuture];
    reports.push({ scenario: 'future_cached_duplicate_signature',
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

  if (options.rejectNoncanonicalTimestamp) {
    // These HMACs authenticate the canonical integer but not the transmitted timestamp bytes.
    const noncanonicalValues = [`0${now}`, `${now}.0`];
    const httpStatuses = [];
    const observedCounts = [];
    for (const timestampHeader of noncanonicalValues) {
      const malformedId = `wfl_noncanonical_${randomUUID().replaceAll('-', '')}`;
      const malformedBody = JSON.stringify({ type: 'test.created',
        timestamp: new Date(now * 1000).toISOString(), data: { id: malformedId } });
      const response = await request(options.endpoint, {
        method: 'POST', redirect: 'manual', signal: timeout(),
        headers: { 'content-type': 'application/json', 'webhook-id': malformedId,
          'webhook-timestamp': timestampHeader,
          'webhook-signature': sign({ secret, id: malformedId, timestamp: now, body: malformedBody }) },
        body: malformedBody,
      });
      httpStatuses.push(response.status);
      observedCounts.push(await observe());
    }
    reports.push({ scenario: 'noncanonical_signed_timestamp',
      passed: httpStatuses.every((status) => options.rejectionStatuses.includes(status)) &&
        observedCounts.every((count) => count === expectedCount),
      httpStatuses, observedCounts, expectedProcessedCount: expectedCount });
  }

  if (options.rejectTamperedEventId) {
    const originalId = `wfl_idtamper_${randomUUID().replaceAll('-', '')}`;
    const body = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: originalId } });
    const signature = sign({ secret, id: originalId, timestamp: now, body });
    const send = (headerId) => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': headerId,
        'webhook-timestamp': String(now), 'webhook-signature': signature },
      body,
    });
    // Only the event ID header changes; its old HMAC cannot authenticate it.
    const accepted = await send(originalId);
    const afterAccepted = await observe();
    const tampered = await send(`${originalId}_altered`);
    const afterTampered = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [accepted.status, tampered.status];
    const observedCounts = [afterAccepted, afterTampered];
    reports.push({ scenario: 'tampered_webhook_id_header',
      passed: httpStatuses[0] === options.successStatus &&
        options.rejectionStatuses.includes(httpStatuses[1]) &&
        observedCounts.every((count) => count === expectedProcessedCount),
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.asyncAckDelivery) {
    const eventId = 'wfl_asyncack_' + randomUUID().replaceAll('-', '');
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: eventId } });
    const signature = sign({ secret, id: eventId, timestamp: now, body: rawBody });
    const send = () => request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(),
      headers: { 'content-type': 'application/json', 'webhook-id': eventId,
        'webhook-timestamp': String(now), 'webhook-signature': signature },
      body: rawBody,
    });
    // Two copies arrive before the synthetic worker settles. A 202 alone is
    // not evidence that an event was eventually processed or enqueued once.
    const [first, duplicate] = await Promise.all([send(), send()]);
    await new Promise((resolve) => setTimeout(resolve, options.asyncAckWaitMs));
    const afterSettlement = await observe();
    const replay = await send();
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [first.status, duplicate.status, replay.status];
    const observedCounts = [afterSettlement, afterReplay];
    reports.push({ scenario: 'async_ack_dedupe',
      passed: httpStatuses.every((status) => status === 202) &&
        observedCounts.every((count) => count === expectedProcessedCount),
      httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.partialBodyUploadAbort) {
    const eventId = `wfl_partialupload_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: eventId } });
    const bodyBytes = Buffer.from(rawBody);
    const signature = sign({ secret, id: eventId, timestamp: now, body: bodyBytes });
    const headers = { 'content-type': 'application/json', 'webhook-id': eventId,
      'webhook-timestamp': String(now), 'webhook-signature': signature };
    const firstAttemptOutcome = await postAbortedPartialBody(options.endpoint,
      { id: eventId, timestamp: now, signature, body: bodyBytes, signal: timeout() });
    // Allow the receiver to observe the socket termination before checking state.
    // This is a bounded observation window, not a durability guarantee.
    await new Promise((resolve) => setTimeout(resolve, 100));
    const afterAbort = await observe();
    const retry = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: rawBody,
    });
    const afterRetry = await observe();
    const replay = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: rawBody,
    });
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [retry.status, replay.status];
    const observedCounts = [afterAbort, afterRetry, afterReplay];
    reports.push({ scenario: 'partial_body_upload_abort_retry',
      passed: firstAttemptOutcome === 'transport_error' &&
        httpStatuses.every((status) => status === options.successStatus) &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      firstAttemptOutcome, httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.abortedChunkedUploadRetry) {
    const eventId = `wfl_partialchunk_${randomUUID().replaceAll('-', '')}`;
    const rawBody = JSON.stringify({ type: 'test.created',
      timestamp: new Date(now * 1000).toISOString(), data: { id: eventId } });
    const bodyBytes = Buffer.from(rawBody);
    const signature = sign({ secret, id: eventId, timestamp: now, body: bodyBytes });
    const headers = { 'content-type': 'application/json', 'webhook-id': eventId,
      'webhook-timestamp': String(now), 'webhook-signature': signature };
    const firstAttemptOutcome = await postAbortedChunkedBody(options.endpoint,
      { id: eventId, timestamp: now, signature, body: bodyBytes, signal: timeout() });
    // Let the local receiver observe the incomplete chunk stream before retry.
    await new Promise((resolve) => setTimeout(resolve, 100));
    const afterAbort = await observe();
    const retry = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: rawBody,
    });
    const afterRetry = await observe();
    const replay = await request(options.endpoint, {
      method: 'POST', redirect: 'manual', signal: timeout(), headers, body: rawBody,
    });
    const afterReplay = await observe();
    const expectedProcessedCount = expectedCount + 1;
    const httpStatuses = [retry.status, replay.status];
    const observedCounts = [afterAbort, afterRetry, afterReplay];
    reports.push({ scenario: 'aborted_chunked_upload_retry',
      passed: firstAttemptOutcome === 'transport_error' &&
        httpStatuses.every((status) => status === options.successStatus) &&
        observedCounts[0] === expectedCount &&
        observedCounts[1] === expectedProcessedCount &&
        observedCounts[2] === expectedProcessedCount,
      firstAttemptOutcome, httpStatuses, observedCounts, expectedProcessedCount });
    expectedCount = expectedProcessedCount;
  }

  if (options.keepAliveConnectionIsolation) {
    const eventRoot = `wfl_keepalive_${randomUUID().replaceAll('-', '')}`;
    const events = ['one', 'two'].map((suffix) => {
      const eventId = `${eventRoot}_${suffix}`;
      const body = JSON.stringify({ type: 'test.created',
        timestamp: new Date(now * 1000).toISOString(), data: { id: eventId } });
      return { id: eventId, timestamp: now, body,
        signature: sign({ secret, id: eventId, timestamp: now, body }) };
    });
    const originalAgent = new HttpAgent({ keepAlive: true, maxSockets: 1 });
    const freshAgent = new HttpAgent({ keepAlive: true, maxSockets: 1 });
    let responses;
    try {
      // Three sequential requests must share a socket; the fourth uses a new one.
      const first = await postOnKeepAliveAgent(options.endpoint,
        { ...events[0], signal: timeout() }, originalAgent);
      const countFirst = await observe();
      const second = await postOnKeepAliveAgent(options.endpoint,
        { ...events[1], signal: timeout() }, originalAgent);
      const countSecond = await observe();
      const sameSocketReplay = await postOnKeepAliveAgent(options.endpoint,
        { ...events[0], signal: timeout() }, originalAgent);
      const countReplay = await observe();
      const freshSocketReplay = await postOnKeepAliveAgent(options.endpoint,
        { ...events[1], signal: timeout() }, freshAgent);
      const countFresh = await observe();
      responses = {
        httpStatuses: [first.status, second.status,
          sameSocketReplay.status, freshSocketReplay.status],
        observedCounts: [countFirst, countSecond, countReplay, countFresh],
        sameSocketReused: !!first.socket && first.socket === second.socket &&
          first.socket === sameSocketReplay.socket,
        freshSocketUsed: !!freshSocketReplay.socket &&
          freshSocketReplay.socket !== first.socket,
      };
    } finally {
      originalAgent.destroy();
      freshAgent.destroy();
    }
    const expectedCounts = [expectedCount + 1, expectedCount + 2,
      expectedCount + 2, expectedCount + 2];
    reports.push({ scenario: 'keep_alive_connection_isolation',
      passed: responses.sameSocketReused && responses.freshSocketUsed &&
        responses.httpStatuses.every((status) => status === options.successStatus) &&
        responses.observedCounts.every((count, index) => count === expectedCounts[index]),
      ...responses, expectedProcessedCount: expectedCount + 2 });
    expectedCount += 2;
  }

  return { success: reports.every((r) => r.passed), scenarios: reports,
    coverage: reports.map((report) => report.scenario),
    caveat: 'processedCount is a user-provided observer, not independently proven business-side-effect correctness' };
}
