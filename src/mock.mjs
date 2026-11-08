import { createServer } from 'node:http';
import { verify } from './standard.mjs';

export async function startMock({ secret, previousSecret, retiredSecret, tenantBSecret,
  unsafeRejectPreviousSecret = false, unsafeAcceptRetiredSecret = false,
  unsafeProcessRetiredBeforeReject = false, dedupe = true, verifySignatures = true,
  verifyFreshness = true, unsafeConcurrentDedupe = false, supportRetryFault = true,
  supportRateLimitFault = true, unsafeReserveRateLimitedId = false,
  unsafeCommitRateLimitedBeforeReject = false, unsafeOmitRateLimitRetryAfter = false,
  supportMalformedValidation = true, unsafeAcceptMalformedSignedPayload = false,
  unsafePoisonMalformedDedupe = false, unsafeCommitMalformedBeforeReject = false,
  supportEventSchemaValidation = true, unsafeAcceptInvalidEventSchema = false,
  unsafePoisonInvalidSchemaDedupe = false, unsafeCommitInvalidSchemaBeforeReject = false,
  supportDuplicateDataValidation = true, unsafeAcceptDuplicateDataKey = false,
  unsafeAcceptEscapedDuplicateDataKey = false,
  unsafePoisonDuplicateDataDedupe = false, unsafeCommitDuplicateDataBeforeReject = false,
  supportPayloadSizeValidation = true, unsafeAcceptOversizedSignedPayload = false,
  unsafePoisonOversizedDedupe = false, unsafeCommitOversizedBeforeReject = false,
  supportContentTypeValidation = true, unsafeAcceptWrongContentType = false,
  unsafePoisonWrongContentTypeDedupe = false,
  unsafeCommitWrongContentTypeBeforeReject = false,
  supportContentEncodingValidation = true, unsafeAcceptUnsupportedContentEncoding = false,
  unsafePoisonUnsupportedEncodingDedupe = false,
  unsafeCommitUnsupportedEncodingBeforeReject = false,
  unsafeRejectJsonCharset = false, unsafeDedupeByContentType = false,
  unsafeCanonicalizeRawJsonBeforeVerify = false,
  unsafeAcknowledgeRawJsonBeforeAuth = false, unsafeCommitRawJsonBeforeReject = false,
  unsafeCacheRejectedSignature = false, unsafeCommitRejectedSignature = false,
  unsafeAcceptRejectedSignature = false,
  unsafeAcceptMissingSignature = false, unsafeCacheMissingSignature = false,
  unsafeCommitMissingSignatureBeforeReject = false,
  unsafeAcceptMissingTimestamp = false, unsafeCacheMissingTimestamp = false,
  unsafeCommitMissingTimestampBeforeReject = false,
  unsafeAcceptMissingEventId = false, unsafeCacheMissingEventId = false,
  unsafeCommitMissingEventIdBeforeReject = false,
  unsafeAcceptDuplicateWireEventId = false, unsafeCacheDuplicateWireEventId = false,
  unsafeCommitDuplicateWireEventIdBeforeReject = false,
  unsafeAcceptDuplicateWireTimestamp = false, unsafeAcceptLastDuplicateWireTimestamp = false,
  unsafeCacheDuplicateWireTimestamp = false,
  unsafeCommitDuplicateWireTimestampBeforeReject = false,
  unsafeAcceptDuplicateWireSignature = false, unsafeAcceptLastDuplicateWireSignature = false,
  unsafeCacheDuplicateWireSignature = false,
  unsafeCommitDuplicateWireSignatureBeforeReject = false,
  unsafeAcceptFirstDuplicateContentType = false, unsafeAcceptLastDuplicateContentType = false,
  unsafeCacheDuplicateContentType = false,
  unsafeCommitDuplicateContentTypeBeforeReject = false,
  unsafeDecodeChunkSeparately = false, unsafeRejectChunkedTransfer = false,
  unsafeDedupeByTransferFraming = false,
  supportUtf8Validation = true, unsafeAcceptInvalidUtf8 = false,
  unsafeCacheInvalidUtf8 = false, unsafeCommitInvalidUtf8BeforeReject = false,
  unsafeCoalesceDistinctEvents = false, unsafeRejectConcurrentDistinct = false,
  unsafeMarkFailedRetrySeen = false, supportLostAckFault = true,
  unsafeForgetLostAckDedupe = false, supportOrderTransitions = true,
  supportTimeoutFault = true, unsafeForgetTimeoutDedupe = false,
  supportPrecommitTimeoutFault = true, unsafeReservePrecommitTimeoutDedupe = false,
  unsafeCommitBeforePrecommitTimeout = false,
  supportCommitted503Fault = true, unsafeForgetCommitted503Dedupe = false,
  unsafeRejectCommitted503BeforeProcess = false,
  unsafeApplyOutOfOrder = false, unsafeMarkRejectedOrderSeen = false,
  unsafeReapplyDelayedCreation = false, unsafeRejectDelayedCreation = false,
  unsafeCountDelayedCreationReplay = false,
  unsafeAcknowledgeConflictingPayload = false, unsafeCommitConflictingPayload = false,
  unsafeRacyConcurrentConflict = false,
  unsafeDedupeBySignature = false, unsafeRejectResignedDuplicate = false,
  unsafeCaseFoldEventIds = false, unsafeRejectCaseVariantEventId = false,
  unsafeDedupeByResourceId = false, unsafeRejectSecondResourceEvent = false,
  unsafeReprocessSharedResourceReplays = false,
  unsafeDedupeByBodyHash = false, unsafeRejectIdenticalBodyAsCollision = false,
  unsafeReprocessIdenticalBodyReplays = false,
  supportTenantScopes = true, unsafeGlobalTenantDedupe = false,
  unsafeRejectTenantCollision = false, unsafeAcceptOtherTenantKey = false,
  unsafeCommitWrongTenantBeforeReject = false,
  unsafeClassifyTenantCollisionBeforeAuth = false,
  unsafeAcceptFutureTimestamp = false, unsafeCommitFutureBeforeReject = false,
  unsafeAcknowledgeTamperedDuplicate = false, unsafeCommitTamperedDuplicateBeforeReject = false,
  unsafeAcknowledgeRetiredDuplicate = false, unsafeCommitRetiredDuplicateBeforeReject = false,
  unsafeAcknowledgeStaleDuplicate = false, unsafeCommitStaleDuplicateBeforeReject = false,
  unsafeAcknowledgeFutureDuplicate = false, unsafeCommitFutureDuplicateBeforeReject = false,
  unsafeInspectCollisionBeforeAuth = false, unsafeCommitUnauthenticatedCollision = false,
  unsafeFirstSignatureOnly = false, unsafeAcceptInvalidMultiSignature = false,
  unsafeCommitInvalidMultiSignatureBeforeReject = false,
  unsafeVerifyBodyIdInsteadOfHeader = false, unsafeCommitTamperedIdBeforeReject = false,
  unsafeNormalizeTimestamp = false, unsafeCommitNoncanonicalBeforeReject = false,
  clock = () => Math.floor(Date.now() / 1000), dedupeRetentionSeconds,
  unsafePrematureRetentionEviction = false, unsafeAcceptExpiredReplay = false,
  supportVersionedUpdates = true, unsafeApplyStaleVersionedUpdate = false,
  unsafeCommitStaleVersionBeforeReject = false } = {}) {
  const seen = new Set();
  const seenCharsetKeys = new Set();
  const seenTransferKeys = new Set();
  const seenAt = new Map();
  const seenConflictBodies = new Map();
  const seenResignedSignatures = new Set();
  const caseFoldedIds = new Map();
  const sharedResourceFirstEvent = new Map();
  const identicalBodyFirstEvent = new Map();
  const tenantScopedIds = new Set();
  const tenantGlobalOwners = new Map();
  const failedRetryIds = new Set();
  const rateLimitedIds = new Set();
  const lostAckIds = new Set();
  const committed503Ids = new Set();
  const resourceStates = new Map();
  const resourceVersions = new Map();
  let processedCount = 0;
  const pendingRaces = new Map();
  let distinctBatchCommitted = false;
  function rendezvous(id, expected = 4) {
    return new Promise((resolve) => {
      let group = pendingRaces.get(id);
      if (!group) {
        group = { waiters: [], timer: null };
        pendingRaces.set(id, group);
        // Avoid leaving the local fixture hanging if fewer than four requests arrive.
        group.timer = setTimeout(() => release(), 1000);
      }
      function release() {
        if (pendingRaces.get(id) !== group) return;
        clearTimeout(group.timer);
        pendingRaces.delete(id);
        for (const waiter of group.waiters) waiter();
      }
      group.waiters.push(resolve);
      if (group.waiters.length === expected) release();
    });
  }
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && url.pathname === '/state') {
      res.writeHead(200, { 'content-type': 'application/json' });
      const resourceId = url.searchParams.get('resourceId');
      res.end(JSON.stringify({ processedCount,
        ...(resourceId && supportOrderTransitions
          ? { resourceState: resourceStates.get(resourceId) ?? 'missing' } : {}),
        ...(resourceId && supportVersionedUpdates
          ? { resourceVersion: resourceVersions.get(resourceId) ?? 0 } : {}) }));
      return;
    }
    if (req.method !== 'POST' || url.pathname !== '/webhook') {
      res.writeHead(404); res.end(); return;
    }
    const chunks = [];
    let bodyBytes = 0;
    for await (const chunk of req) {
      bodyBytes += chunk.length;
      if (bodyBytes > 65536) { res.writeHead(413); res.end(); req.destroy(); return; }
      chunks.push(chunk);
    }
    const rawBody = Buffer.concat(chunks);
    const body = rawBody.toString('utf8');
    const wireEventIds = [];
    const wireTimestamps = [];
    const wireSignatures = [];
    const wireContentTypes = [];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      if (req.rawHeaders[i].toLowerCase() === 'content-type') {
        wireContentTypes.push(req.rawHeaders[i + 1]);
      }
      if (req.rawHeaders[i].toLowerCase() === 'webhook-id') {
        wireEventIds.push(req.rawHeaders[i + 1]);
      }
      if (req.rawHeaders[i].toLowerCase() === 'webhook-timestamp') {
        wireTimestamps.push(req.rawHeaders[i + 1]);
      }
      if (req.rawHeaders[i].toLowerCase() === 'webhook-signature') {
        wireSignatures.push(req.rawHeaders[i + 1]);
      }
    }
    const duplicateWireId = wireEventIds.length > 1 &&
      wireEventIds[0].startsWith('wfl_dupheader_');
    // Explicitly use the first physical field for the broken first-wins fixture.
    const id = duplicateWireId ? wireEventIds[0] : req.headers['webhook-id'];
    const duplicateWireTimestamp = wireTimestamps.length > 1 &&
      typeof id === 'string' && id.startsWith('wfl_dupts_');
    const duplicateWireSignature = wireSignatures.length > 1 &&
      typeof id === 'string' && id.startsWith('wfl_dupsig_');
    const duplicateWireContentType = wireContentTypes.length > 1 &&
      typeof id === 'string' && id.startsWith('wfl_dupctype_');
    let missingEventBodyId;
    if (id === undefined) {
      try {
        const bodyId = JSON.parse(body)?.data?.id;
        if (typeof bodyId === 'string' && bodyId.startsWith('wfl_missingid_')) {
          missingEventBodyId = bodyId;
        }
      } catch { /* An invalid JSON body is not an event-ID recovery fixture. */ }
    }
    const tenantProbe = typeof id === 'string' && id.startsWith('wfl_tenant_');
    const tenant = req.headers['x-wfl-test-tenant'];
    if (unsafeClassifyTenantCollisionBeforeAuth && tenantProbe && tenant === 'a' &&
        tenantScopedIds.has(`a:${id}`)) {
      res.writeHead(409); res.end('cached tenant ID exposed before authentication'); return;
    }
    // The broken first-wins receiver authenticates one field and ignores the
    // other. The correct receiver rejects the ambiguous raw wire envelope.
    const timestampHeader = duplicateWireTimestamp && unsafeAcceptDuplicateWireTimestamp
      ? wireTimestamps[0]
      : duplicateWireTimestamp && unsafeAcceptLastDuplicateWireTimestamp
        ? wireTimestamps.at(-1) : req.headers['webhook-timestamp'];
    const ts = Number(timestampHeader);
    const receiverNow = clock();
    const effectiveRetention = unsafePrematureRetentionEviction
      ? Math.floor(dedupeRetentionSeconds / 2) : dedupeRetentionSeconds;
    if (effectiveRetention !== undefined && seenAt.has(id) &&
        receiverNow - seenAt.get(id) >= effectiveRetention) {
      seen.delete(id);
    }
    const expiredReplay = seenAt.has(id) && !seen.has(id);
    const unauthenticatedCollision = typeof id === 'string' &&
      id.startsWith('wfl_conflict_unauth_') && seenConflictBodies.has(id) &&
      seenConflictBodies.get(id) !== body;
    if (unsafeInspectCollisionBeforeAuth && unauthenticatedCollision) {
      // Broken receiver reveals the stored-ID conflict without authenticating the new bytes.
      res.writeHead(409); res.end('conflicting event ID payload'); return;
    }
    if (unsafeAcknowledgeTamperedDuplicate && typeof id === 'string' &&
        id.startsWith('wfl_dupauth_') && seen.has(id)) {
      // Broken receiver acknowledges known IDs before verifying the incoming HMAC.
      res.writeHead(200); res.end('accepted duplicate'); return;
    }
    const rawJsonProbe = typeof id === 'string' && id.startsWith('wfl_rawjson_');
    if (unsafeAcknowledgeRawJsonBeforeAuth && rawJsonProbe && seen.has(id)) {
      res.writeHead(200); res.end('accepted cached event without HMAC'); return;
    }
    const retiredCachedDuplicate = typeof id === 'string' &&
      id.startsWith('wfl_revokeddup_') && seen.has(id) &&
      retiredSecret !== undefined &&
      verify({ secret: retiredSecret, id, timestamp: ts, body,
        signature: req.headers['webhook-signature'], now: receiverNow });
    if (unsafeAcknowledgeRetiredDuplicate && retiredCachedDuplicate) {
      // Broken receiver returns from its dedupe cache without checking key retirement.
      res.writeHead(200); res.end('accepted duplicate'); return;
    }
    const staleCachedDuplicate = typeof id === 'string' &&
      id.startsWith('wfl_staledup_') && seen.has(id) && ts < receiverNow - 300 &&
      verify({ secret, id, timestamp: ts, body, signature: req.headers['webhook-signature'], now: ts });
    if (unsafeAcknowledgeStaleDuplicate && staleCachedDuplicate) {
      // Broken receiver checks its idempotency cache before enforcing freshness.
      res.writeHead(200); res.end('accepted duplicate'); return;
    }
    const futureCachedDuplicate = typeof id === 'string' &&
      id.startsWith('wfl_futuredup_') && seen.has(id) && ts > receiverNow + 300 &&
      verify({ secret, id, timestamp: ts, body, signature: req.headers['webhook-signature'],
        now: ts });
    if (unsafeAcknowledgeFutureDuplicate && futureCachedDuplicate) {
      // Broken receiver acknowledges a cached ID without checking future skew.
      res.writeHead(200); res.end('accepted duplicate'); return;
    }
    const firstOnly = unsafeFirstSignatureOnly && typeof id === 'string' &&
      id.startsWith('wfl_multisig_');
    const signatureHeader = duplicateWireSignature && unsafeAcceptDuplicateWireSignature
      ? wireSignatures[0]
      : duplicateWireSignature && unsafeAcceptLastDuplicateWireSignature
        ? wireSignatures.at(-1) : req.headers['webhook-signature'];
    const signature = firstOnly
      ? String(signatureHeader ?? '').split(/\s+/)[0] : signatureHeader;
    const noncanonicalTimestamp = typeof timestampHeader === 'string' &&
      timestampHeader !== String(ts);
    const normalizeTestTimestamp = unsafeNormalizeTimestamp && typeof id === 'string' &&
      id.startsWith('wfl_noncanonical_');
    let authenticatedId = id;
    if (unsafeAcceptMissingEventId && missingEventBodyId) {
      // Broken receiver trusts an unauthenticated body field as the signed wire ID.
      authenticatedId = missingEventBodyId;
    }
    if (unsafeVerifyBodyIdInsteadOfHeader && typeof id === 'string' &&
        id.startsWith('wfl_idtamper_') && id.endsWith('_altered')) {
      try { authenticatedId = JSON.parse(body)?.data?.id; }
      catch { authenticatedId = undefined; }
    }
    let authenticatedBody = rawBody;
    if (unsafeDecodeChunkSeparately && typeof id === 'string' &&
        id.startsWith('wfl_chunked_') && req.headers['transfer-encoding'] === 'chunked') {
      // Broken stream decoder inserts replacement characters at chunk boundaries.
      authenticatedBody = Buffer.from(chunks.map((chunk) => chunk.toString('utf8')).join(''));
    }
    if (unsafeCanonicalizeRawJsonBeforeVerify && rawJsonProbe) {
      try { authenticatedBody = JSON.stringify(JSON.parse(body)); }
      catch { /* Malformed JSON remains invalid under the ordinary verifier. */ }
    }
    const metadata = { id: authenticatedId, timestamp: normalizeTestTimestamp ? ts : timestampHeader,
      body: authenticatedBody, signature,
      now: receiverNow, tolerance: verifyFreshness ? 300 : Number.POSITIVE_INFINITY };
    const syntheticFuture = typeof id === 'string' && id.startsWith('wfl_future_') &&
      ts > receiverNow + 300;
    const hasValidFutureSignature = syntheticFuture &&
      verify({ secret, ...metadata, now: ts });
    const acceptedCurrent = verify({ secret, ...metadata }) ||
      (unsafeAcceptFutureTimestamp && hasValidFutureSignature) ||
      (unsafeAcceptExpiredReplay && expiredReplay &&
        verify({ secret, ...metadata, tolerance: Number.POSITIVE_INFINITY }));
    const acceptedPrevious = previousSecret !== undefined && !unsafeRejectPreviousSecret &&
      verify({ secret: previousSecret, ...metadata });
    const signedByRetired = retiredSecret !== undefined && verify({ secret: retiredSecret, ...metadata });
    const tenantKey = tenant === 'a' ? secret : tenant === 'b' ? tenantBSecret : undefined;
    const validTenantSignature = tenantKey !== undefined &&
      verify({ secret: tenantKey, ...metadata });
    const validWrongTenantSignature = tenant === 'a' && tenantBSecret !== undefined &&
      verify({ secret: tenantBSecret, ...metadata });
    const accepted = tenantProbe && supportTenantScopes
      ? validTenantSignature || (unsafeAcceptOtherTenantKey && validWrongTenantSignature)
      : acceptedCurrent || acceptedPrevious || (unsafeAcceptRetiredSecret && signedByRetired) ||
        (unsafeAcceptRejectedSignature && typeof id === 'string' &&
          id.startsWith('wfl_authretry_')) ||
        (unsafeAcceptMissingSignature && typeof id === 'string' &&
          id.startsWith('wfl_missinghmac_') && signature === undefined) ||
        (unsafeAcceptMissingTimestamp && typeof id === 'string' &&
          id.startsWith('wfl_missingts_') && timestampHeader === undefined) ||
        (unsafeAcceptInvalidMultiSignature && typeof id === 'string' &&
          id.startsWith('wfl_multisig_reject_'));
    if (duplicateWireId && !unsafeAcceptDuplicateWireEventId) {
      if (unsafeCacheDuplicateWireEventId) seen.add(id);
      if (unsafeCommitDuplicateWireEventIdBeforeReject) {
        processedCount += 1; seen.add(id);
      }
      res.writeHead(400); res.end('duplicate wire event ID'); return;
    }
    if (duplicateWireTimestamp && !unsafeAcceptDuplicateWireTimestamp &&
        !unsafeAcceptLastDuplicateWireTimestamp) {
      if (unsafeCacheDuplicateWireTimestamp) seen.add(id);
      if (unsafeCommitDuplicateWireTimestampBeforeReject) {
        processedCount += 1; seen.add(id);
      }
      res.writeHead(400); res.end('duplicate wire timestamp'); return;
    }
    if (duplicateWireSignature && !unsafeAcceptDuplicateWireSignature &&
        !unsafeAcceptLastDuplicateWireSignature) {
      if (unsafeCacheDuplicateWireSignature) seen.add(id);
      if (unsafeCommitDuplicateWireSignatureBeforeReject) {
        processedCount += 1; seen.add(id);
      }
      res.writeHead(400); res.end('duplicate wire signature'); return;
    }
    if (duplicateWireContentType && !unsafeAcceptFirstDuplicateContentType &&
        !unsafeAcceptLastDuplicateContentType) {
      if (unsafeCacheDuplicateContentType) seen.add(id);
      if (unsafeCommitDuplicateContentTypeBeforeReject) {
        processedCount += 1; seen.add(id);
      }
      res.writeHead(400); res.end('ambiguous physical content type'); return;
    }
    if (duplicateWireContentType) {
      const selected = unsafeAcceptFirstDuplicateContentType
        ? wireContentTypes[0] : wireContentTypes.at(-1);
      if (selected !== 'application/json') {
        res.writeHead(415); res.end('unsupported selected media type'); return;
      }
    }
    if (verifySignatures && !accepted) {
      if (missingEventBodyId) {
        if (unsafeCacheMissingEventId) seen.add(missingEventBodyId);
        if (unsafeCommitMissingEventIdBeforeReject) {
          processedCount += 1;
          seen.add(missingEventBodyId);
        }
      }
      if (unsafeCommitRawJsonBeforeReject && rawJsonProbe && seen.has(id)) {
        processedCount += 1;
      }
      if (typeof id === 'string' && id.startsWith('wfl_authretry_')) {
        if (unsafeCacheRejectedSignature) seen.add(id);
        if (unsafeCommitRejectedSignature) {
          processedCount += 1;
          seen.add(id);
        }
      }
      if (typeof id === 'string' && id.startsWith('wfl_missinghmac_') &&
          signature === undefined) {
        if (unsafeCacheMissingSignature) seen.add(id);
        if (unsafeCommitMissingSignatureBeforeReject) {
          processedCount += 1;
          seen.add(id);
        }
      }
      if (typeof id === 'string' && id.startsWith('wfl_missingts_') &&
          timestampHeader === undefined) {
        if (unsafeCacheMissingTimestamp) seen.add(id);
        if (unsafeCommitMissingTimestampBeforeReject) {
          processedCount += 1;
          seen.add(id);
        }
      }
      if (unsafeCommitWrongTenantBeforeReject && tenantProbe && validWrongTenantSignature) {
        processedCount += 1;
      }
      if (unsafeCommitTamperedIdBeforeReject && typeof id === 'string' &&
          id.startsWith('wfl_idtamper_') && id.endsWith('_altered')) {
        processedCount += 1;
      }
      if (unsafeCommitNoncanonicalBeforeReject && noncanonicalTimestamp &&
          typeof id === 'string' && id.startsWith('wfl_noncanonical_')) {
        processedCount += 1;
      }
      if (unsafeCommitInvalidMultiSignatureBeforeReject && typeof id === 'string' &&
          id.startsWith('wfl_multisig_reject_')) {
        processedCount += 1;
      }
      if (unsafeCommitUnauthenticatedCollision && unauthenticatedCollision) {
        processedCount += 1;
      }
      if (unsafeCommitTamperedDuplicateBeforeReject && typeof id === 'string' &&
          id.startsWith('wfl_dupauth_') && seen.has(id)) {
        // Broken receiver rejects the invalid HMAC only after another effect.
        processedCount += 1;
      }
      if (unsafeCommitRetiredDuplicateBeforeReject && retiredCachedDuplicate) {
        processedCount += 1;
      }
      if (unsafeCommitStaleDuplicateBeforeReject && staleCachedDuplicate) {
        processedCount += 1;
      }
      if (unsafeCommitFutureDuplicateBeforeReject && futureCachedDuplicate) {
        processedCount += 1;
      }
      if (unsafeCommitFutureBeforeReject && hasValidFutureSignature && !seen.has(id)) {
        // Broken fixture writes the effect before ultimately rejecting the future timestamp.
        processedCount += 1; seen.add(id);
      }
      if (unsafeProcessRetiredBeforeReject && signedByRetired && !seen.has(id)) {
        // Broken fixture commits the untrusted event but still returns a rejection status.
        processedCount += 1; seen.add(id);
      }
      res.writeHead(401); res.end(); return;
    }
    if (supportUtf8Validation && typeof id === 'string' && id.startsWith('wfl_utf8_')) {
      let validUtf8 = true;
      try { new TextDecoder('utf-8', { fatal: true }).decode(rawBody); }
      catch { validUtf8 = false; }
      if (!validUtf8) {
        if (unsafeAcceptInvalidUtf8) {
          processedCount += 1; seen.add(id);
          res.writeHead(200); res.end('invalid UTF-8 accepted'); return;
        }
        if (unsafeCacheInvalidUtf8) seen.add(id);
        if (unsafeCommitInvalidUtf8BeforeReject) {
          processedCount += 1; seen.add(id);
        }
        res.writeHead(400); res.end('invalid UTF-8 in signed JSON'); return;
      }
    }
    if (supportMalformedValidation && typeof id === 'string' &&
        id.startsWith('wfl_malformed_')) {
      let parseError = false;
      try { JSON.parse(body); } catch { parseError = true; }
      if (parseError) {
        if (unsafeAcceptMalformedSignedPayload) {
          processedCount += 1; seen.add(id);
          res.writeHead(200); res.end('unparseable payload accepted'); return;
        }
        if (unsafePoisonMalformedDedupe) seen.add(id);
        if (unsafeCommitMalformedBeforeReject) {
          processedCount += 1; seen.add(id);
        }
        res.writeHead(400); res.end('unparseable JSON'); return;
      }
    }
    if (supportEventSchemaValidation && typeof id === 'string' &&
        id.startsWith('wfl_schema_')) {
      let event;
      try { event = JSON.parse(body); } catch { event = null; }
      const schemaValid = event?.type === 'test.created' &&
        typeof event?.data?.id === 'string' && event.data.id === id;
      if (!schemaValid) {
        if (unsafeAcceptInvalidEventSchema) {
          processedCount += 1; seen.add(id);
          res.writeHead(200); res.end('schema-invalid delivery accepted'); return;
        }
        if (unsafePoisonInvalidSchemaDedupe) seen.add(id);
        if (unsafeCommitInvalidSchemaBeforeReject) {
          processedCount += 1; seen.add(id);
        }
        res.writeHead(422); res.end('invalid synthetic event schema'); return;
      }
    }
    if (supportDuplicateDataValidation && typeof id === 'string' &&
        id.startsWith('wfl_dupdata_')) {
      // Match the two synthetic shapes, including a JSON-unescaped logical data collision.
      const literalDuplicate = /,"data"\s*:\s*\{[^{}]*\}\s*,\s*"data"\s*:/.test(body);
      const escapedDuplicate = /,"data"\s*:\s*\{[^{}]*\}\s*,\s*"d\\u0061ta"\s*:/.test(body);
      if ((literalDuplicate && !unsafeAcceptDuplicateDataKey) ||
          (escapedDuplicate && !unsafeAcceptEscapedDuplicateDataKey)) {
        if (unsafePoisonDuplicateDataDedupe) seen.add(id);
        if (unsafeCommitDuplicateDataBeforeReject) {
          processedCount += 1; seen.add(id);
        }
        res.writeHead(422); res.end('duplicate synthetic data property'); return;
      }
    }
    if (supportPayloadSizeValidation && typeof id === 'string' &&
        id.startsWith('wfl_oversize_') && Buffer.byteLength(body, 'utf8') > 1024) {
      if (unsafeAcceptOversizedSignedPayload) {
        processedCount += 1; seen.add(id);
        res.writeHead(200); res.end('oversized signed payload accepted'); return;
      }
      if (unsafePoisonOversizedDedupe) seen.add(id);
      if (unsafeCommitOversizedBeforeReject) {
        processedCount += 1; seen.add(id);
      }
      res.writeHead(413); res.end('synthetic body size limit exceeded'); return;
    }
    if (supportContentTypeValidation && typeof id === 'string' &&
        id.startsWith('wfl_media_') && req.headers['content-type'] !== 'application/json') {
      if (unsafeAcceptWrongContentType) {
        processedCount += 1; seen.add(id);
        res.writeHead(200); res.end('wrong media type accepted'); return;
      }
      if (unsafePoisonWrongContentTypeDedupe) seen.add(id);
      if (unsafeCommitWrongContentTypeBeforeReject) {
        processedCount += 1; seen.add(id);
      }
      res.writeHead(415); res.end('unsupported media type'); return;
    }
    if (supportContentEncodingValidation && typeof id === 'string' &&
        id.startsWith('wfl_encoding_') && req.headers['content-encoding'] !== undefined) {
      if (unsafeAcceptUnsupportedContentEncoding) {
        processedCount += 1; seen.add(id);
        res.writeHead(200); res.end('unsupported encoding accepted'); return;
      }
      if (unsafePoisonUnsupportedEncodingDedupe) seen.add(id);
      if (unsafeCommitUnsupportedEncodingBeforeReject) {
        processedCount += 1; seen.add(id);
      }
      res.writeHead(415); res.end('unsupported content encoding'); return;
    }
    if (unsafeRejectChunkedTransfer && typeof id === 'string' &&
        id.startsWith('wfl_chunked_') && req.headers['transfer-encoding'] === 'chunked') {
      res.writeHead(415); res.end('signed HTTP chunked body rejected'); return;
    }
    if (tenantProbe && supportTenantScopes) {
      const priorOwner = tenantGlobalOwners.get(id);
      if ((unsafeGlobalTenantDedupe || unsafeRejectTenantCollision) && priorOwner !== undefined) {
        res.writeHead(unsafeRejectTenantCollision && priorOwner !== tenant ? 409 : 200);
        res.end('global tenant ID collision'); return;
      }
      const scopedKey = `${tenant}:${id}`;
      if (!tenantScopedIds.has(scopedKey)) {
        tenantScopedIds.add(scopedKey);
        tenantGlobalOwners.set(id, tenant);
        processedCount += 1;
      }
      res.writeHead(200); res.end('tenant event accepted'); return;
    }
    if ((unsafeDedupeByResourceId || unsafeRejectSecondResourceEvent ||
        unsafeReprocessSharedResourceReplays) &&
        typeof id === 'string' && id.startsWith('wfl_sharedres_')) {
      let event;
      try { event = JSON.parse(body); } catch { res.writeHead(400); res.end(); return; }
      const resourceId = event?.data?.id;
      if (typeof resourceId !== 'string' || !resourceId.startsWith('wfl_shared_resource_')) {
        res.writeHead(400); res.end('invalid synthetic resource'); return;
      }
      if (unsafeReprocessSharedResourceReplays) {
        processedCount += 1;
        res.writeHead(200); res.end('reprocessed without event ID dedupe'); return;
      }
      const firstId = sharedResourceFirstEvent.get(resourceId);
      if (firstId !== undefined) {
        res.writeHead(unsafeRejectSecondResourceEvent && firstId !== id ? 409 : 200);
        res.end('incorrect resource-keyed dedupe'); return;
      }
      sharedResourceFirstEvent.set(resourceId, id);
      seen.add(id);
      processedCount += 1;
      res.writeHead(200); res.end('accepted'); return;
    }
    if (typeof id === 'string' && id.startsWith('wfl_identical_') &&
        (unsafeDedupeByBodyHash || unsafeRejectIdenticalBodyAsCollision ||
          unsafeReprocessIdenticalBodyReplays)) {
      const firstId = identicalBodyFirstEvent.get(body);
      if (unsafeReprocessIdenticalBodyReplays) {
        processedCount += 1; seen.add(id);
        res.writeHead(200); res.end('replayed as new effect'); return;
      }
      if (firstId !== undefined && firstId !== id) {
        res.writeHead(unsafeRejectIdenticalBodyAsCollision ? 409 : 200);
        res.end('incorrect body-keyed deduplication'); return;
      }
      if (!seen.has(id)) {
        identicalBodyFirstEvent.set(body, id);
        seen.add(id);
        processedCount += 1;
      }
      res.writeHead(200); res.end('accepted'); return;
    }
    if ((unsafeCaseFoldEventIds || unsafeRejectCaseVariantEventId) &&
        typeof id === 'string' && id.startsWith('wfl_case_')) {
      const foldedId = id.toLowerCase();
      const firstId = caseFoldedIds.get(foldedId);
      if (firstId !== undefined) {
        // Broken receivers treat two distinct authenticated IDs as one dedupe key.
        res.writeHead(unsafeRejectCaseVariantEventId && firstId !== id ? 409 : 200);
        res.end('case-folded ID collision'); return;
      }
      caseFoldedIds.set(foldedId, id);
      seen.add(id);
      processedCount += 1;
      res.writeHead(200); res.end('accepted'); return;
    }
    if (typeof id === 'string' && id.startsWith('wfl_conflict_')) {
      const priorBody = seenConflictBodies.get(id);
      if (unsafeRacyConcurrentConflict && id.startsWith('wfl_conflict_race_')) {
        // Both requests read the empty dedupe state before either is allowed to commit.
        await rendezvous(id, 2);
      }
      if (priorBody !== undefined) {
        if (priorBody !== body) {
          // Broken fixtures either hide a signed ID collision or reject it after committing.
          if (unsafeCommitConflictingPayload) processedCount += 1;
          res.writeHead(unsafeAcknowledgeConflictingPayload ? 200 : 409);
          res.end('conflicting event ID payload'); return;
        }
        res.writeHead(200); res.end('accepted duplicate'); return;
      }
      processedCount += 1;
      seen.add(id);
      seenConflictBodies.set(id, body);
      res.writeHead(200); res.end('accepted'); return;
    }
    if (typeof id === 'string' && id.startsWith('wfl_resign_') &&
        (unsafeDedupeBySignature || unsafeRejectResignedDuplicate)) {
      const signatureSeen = seenResignedSignatures.has(req.headers['webhook-signature']);
      if (unsafeRejectResignedDuplicate && seen.has(id) && !signatureSeen) {
        res.writeHead(409); res.end('new signature for duplicate event'); return;
      }
      // Broken receiver either deduplicates by the changing HMAC or rejects a valid re-signature.
      if (unsafeDedupeBySignature ? !signatureSeen : !seen.has(id)) processedCount += 1;
      seenResignedSignatures.add(req.headers['webhook-signature']);
      seen.add(id);
      res.writeHead(200); res.end('accepted'); return;
    }
    if (supportOrderTransitions && typeof id === 'string' && id.startsWith('wfl_order_')) {
      let event;
      try { event = JSON.parse(body); } catch { res.writeHead(400); res.end(); return; }
      const resourceId = event?.data?.id;
      if (typeof resourceId !== 'string' || !resourceId.startsWith('wfl_resource_') ||
          !['test.resource.created', 'test.resource.activated'].includes(event?.type)) {
        res.writeHead(400); res.end(); return;
      }
      const state = resourceStates.get(resourceId) ?? 'missing';
      if (seen.has(id)) {
        if (id.startsWith('wfl_order_latecreate_create_') &&
            event.type === 'test.resource.created' && state === 'activated') {
          if (unsafeRejectDelayedCreation) {
            res.writeHead(409); res.end('already activated'); return;
          }
          if (unsafeReapplyDelayedCreation) {
            resourceStates.set(resourceId, 'created');
            processedCount += 1;
          }
          if (unsafeCountDelayedCreationReplay) processedCount += 1;
        }
        res.writeHead(200); res.end('accepted duplicate'); return;
      }
      if (event.type === 'test.resource.activated' && state === 'missing') {
        // Negative fixtures model two distinct precondition-handling bugs.
        if (unsafeApplyOutOfOrder) {
          resourceStates.set(resourceId, 'activated');
          processedCount += 1;
        }
        if (unsafeMarkRejectedOrderSeen) seen.add(id);
        res.writeHead(409); res.end('resource does not exist'); return;
      }
      if ((event.type === 'test.resource.created' && state !== 'missing') ||
          (event.type === 'test.resource.activated' && state !== 'created')) {
        res.writeHead(409); res.end('invalid state transition'); return;
      }
      resourceStates.set(resourceId, event.type === 'test.resource.created' ? 'created' : 'activated');
      processedCount += 1;
      seen.add(id);
      res.writeHead(200); res.end('transition accepted'); return;
    }
    if (supportRetryFault && req.headers['x-wfl-test-fault'] === 'reject-before-process-once' &&
        typeof id === 'string' && id.startsWith('wfl_retry_') && !failedRetryIds.has(id)) {
      failedRetryIds.add(id);
      // Broken fixture marks an event as handled even though it rejected the delivery.
      if (unsafeMarkFailedRetrySeen) seen.add(id);
      res.writeHead(503); res.end('synthetic pre-processing failure'); return;
    }
    if (supportRateLimitFault &&
        req.headers['x-wfl-test-fault'] === 'rate-limit-before-process-once' &&
        typeof id === 'string' && id.startsWith('wfl_429_') && !rateLimitedIds.has(id)) {
      rateLimitedIds.add(id);
      if (unsafeReserveRateLimitedId) seen.add(id);
      if (unsafeCommitRateLimitedBeforeReject) {
        processedCount += 1;
        seen.add(id);
      }
      res.writeHead(429, unsafeOmitRateLimitRetryAfter ? {} : { 'retry-after': '0' });
      res.end('synthetic local rate limit'); return;
    }
    if (supportLostAckFault && req.headers['x-wfl-test-fault'] === 'commit-then-drop-ack-once' &&
        typeof id === 'string' && id.startsWith('wfl_lostack_') && !lostAckIds.has(id)) {
      lostAckIds.add(id);
      if (!seen.has(id)) {
        processedCount += 1;
        // Broken fixture commits the effect but loses the corresponding dedupe record.
        if (!unsafeForgetLostAckDedupe) seen.add(id);
      }
      res.destroy();
      return;
    }
    if (supportTimeoutFault &&
        req.headers['x-wfl-test-fault'] === 'commit-then-hold-ack-until-timeout' &&
        typeof id === 'string' && id.startsWith('wfl_timeout_')) {
      if (!seen.has(id)) {
        processedCount += 1;
        if (!unsafeForgetTimeoutDedupe) seen.add(id);
      }
      // Intentionally leave the connection open; only the client's deadline ends the attempt.
      return;
    }
    if (supportPrecommitTimeoutFault &&
        req.headers['x-wfl-test-fault'] === 'hold-before-commit-until-timeout' &&
        typeof id === 'string' && id.startsWith('wfl_precommit_timeout_')) {
      // Unsafe implementations may reserve the event ID or even commit before timeout.
      if (unsafeReservePrecommitTimeoutDedupe) seen.add(id);
      if (unsafeCommitBeforePrecommitTimeout) {
        processedCount += 1;
        seen.add(id);
      }
      // No response and no deferred work: the client deadline aborts this request.
      return;
    }
    if (supportCommitted503Fault && req.headers['x-wfl-test-fault'] === 'commit-then-respond-503-once' &&
        typeof id === 'string' && id.startsWith('wfl_committed503_') && !committed503Ids.has(id)) {
      committed503Ids.add(id);
      if (!unsafeRejectCommitted503BeforeProcess && !seen.has(id)) {
        processedCount += 1;
        // Broken receiver commits before its 503, but fails to retain the dedupe key.
        if (!unsafeForgetCommitted503Dedupe) seen.add(id);
      }
      res.writeHead(503); res.end('synthetic error after commit'); return;
    }
    if ((unsafeCoalesceDistinctEvents || unsafeRejectConcurrentDistinct) &&
        typeof id === 'string' && id.startsWith('wfl_unique_')) {
      // Broken global in-flight lock: unrelated IDs are wrongly treated as one batch.
      await rendezvous('wfl_distinct_broken_batch');
      if (!distinctBatchCommitted) {
        distinctBatchCommitted = true;
        processedCount += 1; seen.add(id);
        res.writeHead(200); res.end('accepted'); return;
      }
      res.writeHead(unsafeRejectConcurrentDistinct ? 503 : 200);
      res.end('dropped distinct event'); return;
    }
    if (supportVersionedUpdates && typeof id === 'string' && id.startsWith('wfl_version_event_')) {
      let event;
      try { event = JSON.parse(body); } catch { res.writeHead(400); res.end(); return; }
      const resourceId = event?.data?.id;
      const version = event?.data?.version;
      if (event?.type !== 'test.resource.versioned' ||
          typeof resourceId !== 'string' || !resourceId.startsWith('wfl_version_resource_') ||
          !Number.isSafeInteger(version) || version <= 0) {
        res.writeHead(400); res.end(); return;
      }
      if (seen.has(id)) { res.writeHead(200); res.end('accepted duplicate'); return; }
      const stale = version <= (resourceVersions.get(resourceId) ?? 0);
      if (stale && !unsafeApplyStaleVersionedUpdate &&
          !unsafeCommitStaleVersionBeforeReject) {
        res.writeHead(409); res.end('stale resource version'); return;
      }
      if (!stale || unsafeApplyStaleVersionedUpdate || unsafeCommitStaleVersionBeforeReject) {
        resourceVersions.set(resourceId, version);
        processedCount += 1;
        seen.add(id);
      }
      res.writeHead(stale && !unsafeApplyStaleVersionedUpdate ? 409 : 200);
      res.end(stale ? 'stale resource version' : 'version accepted');
      return;
    }
    if (typeof id === 'string' && id.startsWith('wfl_charset_')) {
      const contentType = req.headers['content-type'];
      if (unsafeRejectJsonCharset && contentType === 'application/json; charset=utf-8') {
        res.writeHead(415); res.end('JSON charset incorrectly rejected'); return;
      }
      if (unsafeDedupeByContentType) {
        const badKey = `${id}:${contentType}`;
        if (!seenCharsetKeys.has(badKey)) {
          processedCount += 1;
          seenCharsetKeys.add(badKey);
        }
      } else if (!seen.has(id)) {
        processedCount += 1;
        seen.add(id);
      }
      res.writeHead(200); res.end('accepted'); return;
    }
    if (unsafeDedupeByTransferFraming && typeof id === 'string' && id.startsWith('wfl_chunked_')) {
      const badKey = `${id}:${req.headers['transfer-encoding'] === 'chunked' ? 'chunked' : 'fixed'}`;
      if (!seenTransferKeys.has(badKey)) {
        seenTransferKeys.add(badKey);
        processedCount += 1;
      }
      res.writeHead(200); res.end('accepted'); return;
    }
    const alreadySeen = seen.has(id);
    if (unsafeConcurrentDedupe && typeof id === 'string' && id.startsWith('wfl_race_')) {
      // Broken fixture: every concurrent request reads state before any write.
      await rendezvous(id);
    }
    if (!dedupe || !alreadySeen) {
      processedCount += 1; seen.add(id);
      if (dedupeRetentionSeconds !== undefined) seenAt.set(id, receiverNow);
    }
    res.writeHead(200); res.end('accepted');
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;
  return {
    config: { endpoint: `${base}/webhook`, observer: `${base}/state` },
    stop: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}
