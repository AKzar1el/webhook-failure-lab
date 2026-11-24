import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { startMock } from '../src/mock.mjs';

const execFileAsync = promisify(execFile);

test('CLI accepts UTF-8 BOM-prefixed local JSON configuration', async () => {
  const secret = 'whsec_' + randomBytes(32).toString('base64');
  const receiver = await startMock({ secret });
  const directory = await mkdtemp(join(tmpdir(), 'wfl-bom-'));
  try {
    const configPath = join(directory, 'config.json');
    await writeFile(configPath, '\uFEFF' + JSON.stringify(receiver.config), 'utf8');
    const { stdout } = await execFileAsync(process.execPath,
      ['bin/wfl.mjs', 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret } });
    const report = JSON.parse(stdout);
    assert.equal(report.success, true);
    assert.equal(report.scenarios.length, 4);
  } finally {
    await receiver.stop();
    await rm(directory, { recursive: true });
  }
});

test('CLI rejects malformed UTF-8 configuration before sending webhooks', async () => {
  const secret = 'whsec_' + randomBytes(32).toString('base64');
  const receiver = await startMock({ secret });
  const directory = await mkdtemp(join(tmpdir(), 'wfl-invalid-utf8-'));
  try {
    const configPath = join(directory, 'config.json');
    const config = { ...receiver.config, endpoint: `${receiver.config.endpoint}?fixture=INVALID_BYTE` };
    const [prefix, suffix] = JSON.stringify(config).split('INVALID_BYTE');
    await writeFile(configPath, Buffer.concat([Buffer.from(prefix), Buffer.from([0xff]), Buffer.from(suffix)]));
    for (const format of ['json', 'junit', 'sarif']) {
      const outcome = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', configPath, '--format', format],
        { env: { ...process.env, WFL_SECRET: secret } })
        .then(() => 0, (error) => error.code);
      const state = await fetch(receiver.config.observer).then((response) => response.json());
      assert.deepEqual({ exitCode: outcome, processedCount: state.processedCount },
        { exitCode: 2, processedCount: 0 }, format);
    }
  } finally {
    await receiver.stop();
    await rm(directory, { recursive: true });
  }
});
