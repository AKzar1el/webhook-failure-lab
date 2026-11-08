import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { runLab } from '../src/run.mjs';
import { startMock } from '../src/mock.mjs';

const execFileAsync = promisify(execFile);
const secret = 'whsec_' + randomBytes(32).toString('base64');

async function withReceiver(options, fn) {
  const receiver = await startMock({ secret, ...options });
  try { return await fn(receiver.config); }
  finally { await receiver.stop(); }
}

async function runCli(config, format = 'sarif') {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-sarif-'));
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify(config));
    try {
      const output = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', configPath, '--format', format],
        { env: { ...process.env, WFL_SECRET: secret } });
      return { code: 0, stdout: output.stdout, stderr: output.stderr };
    } catch (error) {
      return { code: error.code, stdout: error.stdout, stderr: error.stderr };
    }
  } finally {
    await rm(directory, { recursive: true });
  }
}

test('SARIF exposes executed scenario rules and zero findings for a passing local receiver', async () => {
  await withReceiver({}, async (config) => {
    const { toSarif } = await import('../src/sarif.mjs');
    const result = await runLab(config, { secret });
    const sarif = toSarif(result);
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].tool.driver.name, 'Webhook Failure Lab');
    assert.equal(sarif.runs[0].tool.driver.rules.length, 4);
    assert.deepEqual(sarif.runs[0].results, []);
    assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true);
    assert.match(sarif.runs[0].properties.caveat, /not independently proven/);
  });
});

test('SARIF reports a deliberately broken receiver with actionable sanitized evidence', async () => {
  await withReceiver({ unsafeAcceptDuplicateDataKey: true }, async (config) => {
    const { toSarif } = await import('../src/sarif.mjs');
    const result = await runLab({ ...config, rejectDuplicateJsonDataKey: true }, { secret });
    assert.equal(result.success, false);
    const sarif = toSarif(result);
    assert.equal(sarif.runs[0].tool.driver.rules.length, 5);
    assert.equal(sarif.runs[0].results.length, 1);
    const finding = sarif.runs[0].results[0];
    assert.equal(finding.ruleId, 'WFL_DUPLICATE_JSON_DATA_KEY_RETRY');
    assert.equal(finding.level, 'error');
    assert.match(finding.message.text, /httpStatuses/);
    assert.match(finding.message.text, /observedCounts/);
    assert.match(finding.message.text, /receiver-reported/i);
    assert.ok(!JSON.stringify(sarif).includes(secret));
    assert.ok(!JSON.stringify(sarif).includes('webhook-signature'));
  });
});

test('SARIF never includes arbitrary observer strings or unexpected report fields', async () => {
  await withReceiver({ unsafeAcceptDuplicateDataKey: true }, async (config) => {
    const { toSarif } = await import('../src/sarif.mjs');
    const result = await runLab({ ...config, rejectDuplicateJsonDataKey: true }, { secret });
    const failing = result.scenarios.at(-1);
    failing.observedResourceState = secret;
    failing.observedResourceStates = ['created', secret];
    failing.internalDebug = secret;
    const exported = JSON.stringify(toSarif(result));
    assert.ok(!exported.includes(secret));
    assert.ok(!exported.includes('internalDebug'));
    assert.match(exported, /httpStatuses/);
  });
});

test('CLI --format sarif emits parseable SARIF for a passing receiver', async () => {
  await withReceiver({}, async (config) => {
    const output = await runCli(config);
    assert.equal(output.code, 0, output.stderr);
    const sarif = JSON.parse(output.stdout);
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].results.length, 0);
    assert.equal(sarif.runs[0].tool.driver.rules.length, 4);
    assert.ok(!output.stdout.includes(secret));
  });
});

test('CLI --format sarif keeps exit 1 and an error finding for a broken receiver', async () => {
  await withReceiver({ unsafeAcceptDuplicateDataKey: true }, async (config) => {
    const output = await runCli({ ...config, rejectDuplicateJsonDataKey: true });
    assert.equal(output.code, 1, output.stderr);
    const sarif = JSON.parse(output.stdout);
    assert.deepEqual(sarif.runs[0].results.map((x) => x.ruleId),
      ['WFL_DUPLICATE_JSON_DATA_KEY_RETRY']);
    assert.ok(!output.stdout.includes(secret));
  });
});

test('CLI rejects unsupported output formats without posting a webhook', async () => {
  await withReceiver({}, async (config) => {
    const output = await runCli(config, 'html');
    assert.equal(output.code, 2);
    assert.match(output.stderr, /Usage:/);
    const state = await fetch(config.observer).then((response) => response.json());
    assert.equal(state.processedCount, 0);
  });
});

test('SARIF stays parseable and reports failed execution for a broken local observer', async () => {
  let observerRequests = 0;
  let webhookRequests = 0;
  const server = createServer((request, response) => {
    if (request.method === 'GET') observerRequests++;
    if (request.method === 'POST') webhookRequests++;
    response.writeHead(503, { 'content-type': 'text/plain' });
    response.end('synthetic local observer unavailable');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const output = await runCli({ endpoint: `${base}/webhook`, observer: `${base}/state` });
    assert.equal(output.code, 2);
    const sarif = JSON.parse(output.stdout);
    assert.equal(sarif.version, '2.1.0');
    const run = sarif.runs[0];
    assert.equal(run.invocations[0].executionSuccessful, false);
    assert.match(run.invocations[0].toolExecutionNotifications[0].message.text,
      /could not complete/i);
    assert.deepEqual(run.results, []);
    assert.equal(observerRequests, 1);
    assert.equal(webhookRequests, 0);
    assert.ok(!output.stdout.includes(base));
    assert.ok(!output.stdout.includes(secret));
  } finally {
    await new Promise((resolve, reject) => server.close((error) =>
      error ? reject(error) : resolve()));
  }
});

test('SARIF input failure omits untrusted configuration and does not deliver', async () => {
  await withReceiver({}, async (config) => {
    const output = await runCli({ ...config, timeoutMs: -1, debugSecret: secret });
    assert.equal(output.code, 2);
    const run = JSON.parse(output.stdout).runs[0];
    assert.equal(run.invocations[0].executionSuccessful, false);
    assert.equal(run.invocations[0].toolExecutionNotifications.length, 1);
    assert.deepEqual(run.results, []);
    assert.ok(!output.stdout.includes(secret));
    assert.ok(!output.stdout.includes(config.endpoint));
    const state = await fetch(config.observer).then((response) => response.json());
    assert.equal(state.processedCount, 0);
  });
});

test('default JSON mode preserves the existing exit-2 error channel', async () => {
  await withReceiver({}, async (config) => {
    const output = await runCli({ ...config, timeoutMs: -1 }, 'json');
    assert.equal(output.code, 2);
    assert.equal(output.stdout, '');
    assert.match(output.stderr, /Unable to verify/);
  });
});
