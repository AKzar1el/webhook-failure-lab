import { randomBytes } from 'node:crypto';
import { runLab } from '../src/run.mjs';
import { startMock } from '../src/mock.mjs';

const secret = `whsec_${randomBytes(32).toString('base64')}`;
const server = await startMock({ secret });
try {
  const result = await runLab(server.config, { secret });
  console.log(JSON.stringify(result, null, 2));
  process.exitCode = result.success ? 0 : 1;
} finally {
  await server.stop();
}
