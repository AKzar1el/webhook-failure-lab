import { createServer } from 'node:http';
import { verify } from './standard.mjs';

export async function startMock({ secret, previousSecret, retiredSecret, tenantBSecret,
  unsafeRejectPreviousSecret = false, unsafeAcceptRetiredSecret = false,
  unsafeProcessRetiredBeforeReject = false, dedupe = true, verifySignatures = true,
  verifyFreshness = true, unsafeConcurrentDedupe = false, supportRetryFault = true,
  supportMalformedValidation = true, unsafeAcceptMalformedSignedPayload = false,
  unsafePoisonMalformedDedupe = false, unsafeCommitMalformedBeforeReject = false,
  supportEventSchemaValidation = true, unsafeAcceptInvalidEventSchema = false,
  unsafePoisonInvalidSchemaDedupe = false, unsafeCommitInvalidSchemaBeforeReject = false,
  supportContentTypeValidation = true, unsafeAcceptWrongContentType = false,
  unsafePoisonWrongContentTypeDedupe = false,
  unsafeCommitWrongContentTypeBeforeReject = false,
  unsafeCacheRejectedSignature = false, unsafeCommitRejectedSignature = false,
  unsafeAcceptRejectedSignature = false,
  unsafeCoalesceDistinctEvents = false, unsafeRejectConcurrentDistinct = false,
  unsafeMarkFailedRetrySeen = false, supportLostAckFault = true,
  unsafeForgetLostAckDedupe = false, supportOrderTransitions = true,
  supportCommitted503Fault = true, unsafeForgetCommitted503Dedupe = false,
  unsafeRejectCommitted503BeforeProcess = false,
  unsafeApplyOutOfOrder = false, unsafeMarkRejectedOrderSeen = false,
  unsafeReapplyDelayedCreation = false, unsafeRejectDelayedCreation = false,
  unsafeCountDelayedCreationReplay = false,
  unsafeAcknowledgeConflictingPayload = false, unsafeCommitConflictingPayload = false,
  unsafeRacyConcurrentConflict = false,
  unsafeDedupeBySignature = false, unsafeRejectResignedDuplicate = false,
  unsafeCaseFoldEventIds = false, unsafeRejectCaseVariantEventId = false,
  supportTenantScopes = true, unsafeGlobalTenantDedupe = false,
  unsafeRejectTenantCollision = false, unsafeAcceptOtherTenantKey = false,
  unsafeCommitWrongTenantBeforeReject = false,
  unsafeClassifyTenantCollisionBeforeAuth = false,
  unsafeAcceptFutureTimestamp = false, unsafeCommitFutureBeforeReject = false,
  unsafeAcknowledgeTamperedDuplicate = false, unsafeCommitTamperedDuplicateBeforeReject = false,
  unsafeAcknowledgeRetiredDuplicate = false, unsafeCommitRetiredDuplicateBeforeReject = false,
  unsafeAcknowledgeStaleDuplicate = false, unsafeCommitStaleDuplicateBeforeReject = false,
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
  const seenAt = new Map();
  const seenConflictBodies = new Map();
  const seenResignedSignatures = new Set();
  const caseFoldedIds = new Map();
  const tenantScopedIds = new Set();
  const tenantGlobalOwners = new Map();
  const failedRetryIds = new Set();
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
    let body = '';
    for await (const chunk of req) {
      body += chunk.toString('utf8');
      if (body.length > 65536) { res.writeHead(413); res.end(); req.destroy(); return; }
    }
    const id = req.headers['webhook-id'];
    const tenantProbe = typeof id === 'string' && id.startsWith('wfl_tenant_');
    const tenant = req.headers['x-wfl-test-tenant'];
    if (unsafeClassifyTenantCollisionBeforeAuth && tenantProbe && tenant === 'a' &&
        tenantScopedIds.has(`a:${id}`)) {
      res.writeHead(409); res.end('cached tenant ID exposed before authentication'); return;
    }
    const timestampHeader = req.headers['webhook-timestamp'];
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
    const firstOnly = unsafeFirstSignatureOnly && typeof id === 'string' &&
      id.startsWith('wfl_multisig_');
    const signature = firstOnly
      ? String(req.headers['webhook-signature'] ?? '').split(/\s+/)[0]
      : req.headers['webhook-signature'];
    const noncanonicalTimestamp = typeof timestampHeader === 'string' &&
      timestampHeader !== String(ts);
    const normalizeTestTimestamp = unsafeNormalizeTimestamp && typeof id === 'string' &&
      id.startsWith('wfl_noncanonical_');
    let authenticatedId = id;
    if (unsafeVerifyBodyIdInsteadOfHeader && typeof id === 'string' &&
        id.startsWith('wfl_idtamper_') && id.endsWith('_altered')) {
      try { authenticatedId = JSON.parse(body)?.data?.id; }
      catch { authenticatedId = undefined; }
    }
    const metadata = { id: authenticatedId, timestamp: normalizeTestTimestamp ? ts : timestampHeader, body, signature,
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
        (unsafeAcceptInvalidMultiSignature && typeof id === 'string' &&
          id.startsWith('wfl_multisig_reject_'));
    if (verifySignatures && !accepted) {
      if (typeof id === 'string' && id.startsWith('wfl_authretry_')) {
        if (unsafeCacheRejectedSignature) seen.add(id);
        if (unsafeCommitRejectedSignature) {
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
