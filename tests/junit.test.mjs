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

async function withReceiver(options, callback) {
  const receiver = await startMock({ secret, ...options });
  try { return await callback(receiver.config); }
  finally { await receiver.stop(); }
}

async function runCli(config) {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-junit-'));
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify(config));
    try {
      const result = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', configPath, '--format', 'junit'],
        { env: { ...process.env, WFL_SECRET: secret } });
      return { code: 0, stdout: result.stdout, stderr: result.stderr };
    } catch (error) {
      return { code: error.code, stdout: error.stdout, stderr: error.stderr };
    }
  } finally {
    await rm(directory, { recursive: true });
  }
}

test('JUnit emits a completed suite of four passing local webhook contracts', async () => {
  await withReceiver({}, async (config) => {
    const { toJunit } = await import('../src/junit.mjs');
    const result = await runLab(config, { secret });
    const xml = toJunit(result);
    assert.match(xml, /^<\?xml version="1\.0" encoding="UTF-8"\?>/);
    assert.match(xml, /<testsuites tests="4" failures="0" errors="0">/);
    assert.equal((xml.match(/<testcase /g) || []).length, 4);
    assert.doesNotMatch(xml, /<failure\b|<error\b/);
    assert.ok(!xml.includes(secret));
    assert.ok(!xml.includes(config.endpoint));
  });
});

test('JUnit reports a real broken local receiver as a failed CI testcase, with only safe observations', async () => {
  await withReceiver({ unsafeAcceptDuplicateDataKey: true }, async (config) => {
    const output = await runCli({ ...config, rejectDuplicateJsonDataKey: true });
    assert.equal(output.code, 1, output.stderr);
    assert.match(output.stdout, /<testsuites tests="5" failures="1" errors="0">/);
    assert.match(output.stdout, /<testcase classname="WebhookFailureLab" name="duplicate_json_data_key_retry">/);
    assert.match(output.stdout, /<failure type="receiver-contract">/);
    assert.match(output.stdout, /observedCounts/);
    assert.ok(!output.stdout.includes(secret));
    assert.ok(!output.stdout.includes(config.endpoint));
    assert.ok(!output.stdout.includes('webhook-signature'));
  });
});

test('JUnit excludes untrusted scenario names and report strings', async () => {
  const { toJunit } = await import('../src/junit.mjs');
  const xml = toJunit({
    success: false,
    scenarios: [{
      scenario: '<script>' + secret + '</script>',
      passed: false,
      observedProcessedCount: 1,
      debug: secret,
      observedResourceState: secret,
    }],
  });
  assert.match(xml, /<testsuites tests="1" failures="1" errors="0">/);
  assert.ok(!xml.includes(secret));
  assert.ok(!xml.includes('<script>'));
  assert.ok(!xml.includes('debug'));
});

test('JUnit execution failure remains valid XML and does not assert a receiver failure', async () => {
  let observerRequests = 0;
  let webhookRequests = 0;
  const server = createServer((request, response) => {
    if (request.method === 'GET') observerRequests++;
    if (request.method === 'POST') webhookRequests++;
    response.writeHead(503);
    response.end('synthetic local failure');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const output = await runCli({ endpoint: `${base}/webhook`, observer: `${base}/state` });
    assert.equal(output.code, 2);
    assert.match(output.stdout, /^<\?xml version="1\.0"/);
    assert.match(output.stdout, /<testsuites tests="1" failures="0" errors="1">/);
    assert.match(output.stdout, /<error type="execution">/);
    assert.doesNotMatch(output.stdout, /<failure\b/);
    assert.equal(observerRequests, 1);
    assert.equal(webhookRequests, 0);
    assert.ok(!output.stdout.includes(base));
    assert.ok(!output.stdout.includes(secret));
  } finally {
    await new Promise((resolve, reject) => server.close((error) =>
      error ? reject(error) : resolve()));
  }
});

test('JUnit malformed config fails closed with an execution error and no delivery', async () => {
  await withReceiver({}, async (config) => {
    const output = await runCli({ ...config, timeoutMs: -1, debug: secret });
    assert.equal(output.code, 2);
    assert.match(output.stdout, /<testsuites tests="1" failures="0" errors="1">/);
    assert.ok(!output.stdout.includes(secret));
    const state = await fetch(config.observer).then((response) => response.json());
    assert.equal(state.processedCount, 0);
  });
});
