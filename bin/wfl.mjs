#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { runLab } from '../src/run.mjs';

async function main() {
  if (process.argv[2] !== 'run' || !process.argv[3]) {
    console.error('Usage: webhook-failure-lab run local-config.json');
    return 2;
  }
  try {
    const config = JSON.parse(await readFile(process.argv[3], 'utf8'));
    const result = await runLab(config, { secret: process.env.WFL_SECRET,
      previousSecret: process.env.WFL_PREVIOUS_SECRET, retiredSecret: process.env.WFL_RETIRED_SECRET,
      tenantBSecret: process.env.WFL_TENANT_B_SECRET });
    console.log(JSON.stringify(result, null, 2));
    return result.success ? 0 : 1;
  } catch (error) {
    console.error(`Unable to verify: ${error.message}`);
    return 2;
  }
}
process.exitCode = await main();
