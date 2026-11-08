#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { runLab } from '../src/run.mjs';
import { toSarif, toSarifExecutionError } from '../src/sarif.mjs';

async function main() {
  const args = process.argv.slice(2);
  const format = args.length === 2 ? 'json'
    : args.length === 4 && args[2] === '--format' ? args[3] : null;
  if (args[0] !== 'run' || !args[1] || !['json', 'sarif'].includes(format)) {
    console.error('Usage: webhook-failure-lab run local-config.json [--format json|sarif]');
    return 2;
  }
  try {
    const config = JSON.parse(await readFile(args[1], 'utf8'));
    const result = await runLab(config, { secret: process.env.WFL_SECRET,
      previousSecret: process.env.WFL_PREVIOUS_SECRET, retiredSecret: process.env.WFL_RETIRED_SECRET,
      tenantBSecret: process.env.WFL_TENANT_B_SECRET });
    console.log(JSON.stringify(format === 'sarif' ? toSarif(result) : result, null, 2));
    return result.success ? 0 : 1;
  } catch (error) {
    if (format === 'sarif') {
      console.log(JSON.stringify(toSarifExecutionError(), null, 2));
      console.error('Unable to verify: check local configuration and receiver availability');
    } else {
      console.error(`Unable to verify: ${error.message}`);
    }
    return 2;
  }
}
process.exitCode = await main();
