import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, writeFile, unlink, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startMock } from '../src/mock.mjs';

async function main(args) {
  if (args.length > 1 || (args.length === 1 && args[0] !== '--broken')) {
    console.error('Usage: node scripts/demo.mjs [--broken]');
    return 2;
  }

  const secret = `whsec_${randomBytes(32).toString('base64')}`;
  const receiver = await startMock({ secret, dedupe: args.length === 0 });
  let directory;
  let configWritten = false;
  try {
    directory = await mkdtemp(join(tmpdir(), 'wfl-demo-'));
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify(receiver.config), { flag: 'wx' });
    configWritten = true;
    const cli = fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url));
    const env = { WFL_SECRET: secret };
    if (process.platform === 'win32' && process.env.SystemRoot) {
      env.SystemRoot = process.env.SystemRoot;
    }
    return await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [cli, 'run', configPath], {
        env, stdio: ['ignore', 'inherit', 'inherit'], windowsHide: true,
      });
      child.once('error', reject);
      child.once('close', (code) => resolve([0, 1, 2].includes(code) ? code : 2));
    });
  } finally {
    try {
      await receiver.stop();
    } finally {
      if (directory) {
        if (configWritten) await unlink(join(directory, 'lab.json'));
        await rmdir(directory);
      }
    }
  }
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch {
  console.error('Demo execution failed: check local Node.js and loopback availability');
  process.exitCode = 2;
}
