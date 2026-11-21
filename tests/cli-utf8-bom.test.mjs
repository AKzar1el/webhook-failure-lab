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