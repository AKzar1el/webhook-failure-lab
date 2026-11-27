import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, writeFile, unlink, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startMock } from '../src/mock.mjs';

async function main(args) {
  let broken = false;
  let lostAck = false;
  let format;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--broken' && !broken) {
      broken = true;
    } else if (args[i] === '--lost-ack' && !lostAck) {
      lostAck = true;
    } else if (args[i] === '--format' && format === undefined &&
        ['json', 'sarif', 'junit'].includes(args[i + 1])) {
      format = args[++i];
    } else {
      console.error('Usage: node scripts/demo.mjs [--broken] [--lost-ack] [--format json|sarif|junit]');
      return 2;
    }
  }

  const secret = `whsec_${randomBytes(32).toString('base64')}`;
  const receiver = await startMock({ secret, dedupe: lostAck || !broken,
    unsafeForgetLostAckDedupe: lostAck && broken });
  let directory;
  let configWritten = false;
  try {
    directory = await mkdtemp(join(tmpdir(), 'wfl-demo-'));
    const configPath = join(directory, 'lab.json');
    const config = lostAck ? { ...receiver.config, lostAckAfterCommit: true } : receiver.config;
    await writeFile(configPath, JSON.stringify(config), { flag: 'wx' });
    configWritten = true;
    const cli = fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url));
    const env = { WFL_SECRET: secret };
    if (process.platform === 'win32' && process.env.SystemRoot) {
      env.SystemRoot = process.env.SystemRoot;
    }
    return await new Promise((resolve, reject) => {
      const cliArgs = [cli, 'run', configPath];
      if (format !== undefined) cliArgs.push('--format', format);
      const child = spawn(process.execPath, cliArgs, {
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
