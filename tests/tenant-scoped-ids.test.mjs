import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { runLab } from '../src/run.mjs';
import { startMock } from '../src/mock.mjs';

const execFileAsync = promisify(execFile);
const secret = `whsec_${randomBytes(32).toString('base64')}`;
const tenantBSecret = `whsec_${randomBytes(32).toString('base64')}`;
const scenario = (result) => result.scenarios.find((item) => item.scenario === 'tenant_scoped_signed_event_ids');

async function withReceiver(options, fn) {
  const receiver = await startMock({ secret, tenantBSecret, ...options });
  try { return await fn(receiver.config); }
  finally { await receiver.stop(); }
}

test('two tenants independently process the same signed ID; wrong-tenant key rejected before dedupe', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, tenantScopedEventIds: true }, { secret, tenantBSecret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    assert.deepEqual(scenario(result).httpStatuses, [200, 200, 401, 200, 200]);
    assert.deepEqual(scenario(result).observedCounts, [2, 3, 3, 3, 3]);
    assert.equal(scenario(result).expectedProcessedCount, 3);
  });
});

test('detects a global dedupe key silently dropping second tenant event', async () => {
  await withReceiver({ unsafeGlobalTenantDedupe: true }, async (config) => {
    const result = await runLab({ ...config, tenantScopedEventIds: true }, { secret, tenantBSecret });
    assert.equal(result.success, false);
    assert.deepEqual(scenario(result).httpStatuses, [200, 200, 401, 200, 200]);
    assert.deepEqual(scenario(result).observedCounts, [2, 2, 2, 2, 2]);
  });
});

test('detects a global ID collision wrongly rejecting the second tenant', async () => {
  await withReceiver({ unsafeRejectTenantCollision: true }, async (config) => {
    const result = await runLab({ ...config, tenantScopedEventIds: true }, { secret, tenantBSecret });
    assert.equal(result.success, false);
    assert.equal(scenario(result).httpStatuses[1], 409);
    assert.equal(scenario(result).observedCounts[1], 2);
  });
});

test('detects accepting an event for tenant A signed by tenant B', async () => {
  await withReceiver({ unsafeAcceptOtherTenantKey: true }, async (config) => {
    const result = await runLab({ ...config, tenantScopedEventIds: true }, { secret, tenantBSecret });
    assert.equal(result.success, false);
    assert.equal(scenario(result).httpStatuses[2], 200);
    assert.equal(scenario(result).observedCounts[2], 3);
  });
});

test('wrong-tenant authentication is not misclassified as a cached-ID 409', async () => {
  await withReceiver({ unsafeClassifyTenantCollisionBeforeAuth: true }, async (config) => {
    const result = await runLab({ ...config, tenantScopedEventIds: true,
      rejectionStatuses: [400, 401, 403, 409] }, { secret, tenantBSecret });
    assert.equal(result.success, false);
    assert.equal(scenario(result).httpStatuses[2], 409);
    assert.equal(scenario(result).observedCounts[2], 3);
  });
});

test('detects rejecting a cross-tenant forgery only after an observed effect', async () => {
  await withReceiver({ unsafeCommitWrongTenantBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, tenantScopedEventIds: true }, { secret, tenantBSecret });
    assert.equal(result.success, false);
    assert.equal(scenario(result).httpStatuses[2], 401);
    assert.equal(scenario(result).observedCounts[2], 4);
  });
});

test('missing tenant isolation adapter fails closed', async () => {
  await withReceiver({ supportTenantScopes: false }, async (config) => {
    const result = await runLab({ ...config, tenantScopedEventIds: true }, { secret, tenantBSecret });
    assert.equal(result.success, false);
    assert.equal(scenario(result).httpStatuses[1], 401);
  });
});

test('tenant option and its distinct synthetic signing keys are validated before any request', async () => {
  await withReceiver({}, async (config) => {
    const noRequest = () => { throw new Error('unexpected HTTP request'); };
    for (const tenantScopedEventIds of [0, 1, 'true', null, {}, []]) {
      await assert.rejects(() => runLab({ ...config, tenantScopedEventIds },
        { secret, tenantBSecret, request: noRequest }), /tenantScopedEventIds/);
    }
    await assert.rejects(() => runLab({ ...config, tenantScopedEventIds: true },
      { secret, request: noRequest }), /Secret|tenantBSecret/);
    await assert.rejects(() => runLab({ ...config, tenantScopedEventIds: true },
      { secret, tenantBSecret: secret, request: noRequest }), /distinct|tenant/i);
  });
});

test('tenant isolation composes with independent concurrent duplicate checks', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, tenantScopedEventIds: true,
      concurrentDuplicateDeliveries: 4 }, { secret, tenantBSecret });
    assert.equal(result.success, true);
    assert.deepEqual(scenario(result).observedCounts, [3, 4, 4, 4, 4]);
  });
});

test('CLI includes tenant isolation verdict but never prints either secret or signature', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-tenant-scope-'));
    try {
      const configPath = join(directory, 'lab.json');
      await writeFile(configPath, JSON.stringify({ ...config, tenantScopedEventIds: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', configPath],
        { env: { ...process.env, WFL_SECRET: secret, WFL_TENANT_B_SECRET: tenantBSecret } });
      assert.equal(scenario(JSON.parse(stdout)).passed, true);
      for (const output of [stdout, stderr]) {
        assert.ok(!output.includes(secret));
        assert.ok(!output.includes(tenantBSecret));
        assert.ok(!output.includes('webhook-signature'));
      }
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
