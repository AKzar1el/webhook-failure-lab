import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFile, fork } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { runLab } from '../src/run.mjs';
import { startMock } from '../src/mock.mjs';

const execFileAsync = promisify(execFile);
const secret = `whsec_${randomBytes(32).toString('base64')}`;
const previousSecret = `whsec_${randomBytes(32).toString('base64')}`;
const retiredSecret = `whsec_${randomBytes(32).toString('base64')}`;

async function withServer(options, fn) {
  const server = await startMock({ secret, ...options });
  try { return await fn(server.config); }
  finally { await server.stop(); }
}

function launchRestartReceiver(statePath, {
  forgetDedupe = false, crashLoseDedupe = false, crashLoseCount = false,
  ignoreCrashFault = false, startupDelayMs = 0, suppressReady = false,
  startupTimeoutMs = 10000,
} = {}) {
  return new Promise((resolve, reject) => {
    const child = fork(fileURLToPath(new URL('./fixtures/restart-receiver.mjs', import.meta.url)),
      [], { execArgv: [], stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
        env: { ...process.env, WFL_TEST_STATE_PATH: statePath, WFL_TEST_SECRET: secret,
          WFL_TEST_FORGET_DEDUPE: forgetDedupe ? '1' : '0',
          WFL_TEST_CRASH_LOSE_DEDUPE: crashLoseDedupe ? '1' : '0',
          WFL_TEST_CRASH_LOSE_COUNT: crashLoseCount ? '1' : '0',
          WFL_TEST_IGNORE_CRASH: ignoreCrashFault ? '1' : '0',
          WFL_TEST_STARTUP_DELAY_MS: String(startupDelayMs),
          WFL_TEST_SUPPRESS_READY: suppressReady ? '1' : '0' } });
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk.toString().slice(0, 1000); });
    const timer = setTimeout(() => finish(new Error('Local receiver startup timed out')),
      startupTimeoutMs);
    const onExit = (code) => finish(new Error(`Local receiver exited ${code}: ${stderr}`));
    const onError = (error) => finish(error);
    const onReady = (message) => {
      if (message?.type !== 'ready' || !message.config) {
        finish(new Error('Local receiver returned invalid readiness IPC'));
        return;
      }
      finish(null, { child, config: message.config });
    };
    function finish(error, result) {
      clearTimeout(timer);
      child.off('exit', onExit);
      child.off('error', onError);
      child.off('message', onReady);
      if (error) { child.kill(); reject(error); }
      else resolve(result);
    }
    child.once('exit', onExit);
    child.once('error', onError);
    child.once('message', onReady);
  });
}

async function stopRestartReceiver(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error('Receiver shutdown timeout')); }, 4000);
    child.once('exit', () => { clearTimeout(timer); resolve(); });
    child.send({ type: 'shutdown' }, (error) => {
      if (error) { clearTimeout(timer); reject(error); }
    });
  });
}

async function withRestartReceiver({ forgetDedupeOnRestart = false } = {}, fn) {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-restart-'));
  const statePath = join(directory, 'durable.json');
  let live;
  try {
    live = await launchRestartReceiver(statePath);
    const config = live.config;
    const restartReceiver = async () => {
      const previousPid = live.child.pid;
      await stopRestartReceiver(live.child);
      live = await launchRestartReceiver(statePath, { forgetDedupe: forgetDedupeOnRestart });
      assert.notEqual(live.child.pid, previousPid, 'Restart must use a different OS process');
      return live.config;
    };
    return await fn(config, restartReceiver);
  } finally {
    if (live) await stopRestartReceiver(live.child);
    await rm(directory, { recursive: true });
  }
}

async function withCrashReceiver({
  loseDedupeOnCrash = false, loseCountOnCrash = false, ignoreCrashFault = false,
} = {}, fn) {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-crash-'));
  const statePath = join(directory, 'durable.json');
  let live;
  try {
    live = await launchRestartReceiver(statePath, {
      crashLoseDedupe: loseDedupeOnCrash,
      crashLoseCount: loseCountOnCrash,
      ignoreCrashFault,
    });
    const config = live.config;
    const recoverReceiver = async () => {
      const oldChild = live.child;
      const oldPid = oldChild.pid;
      if (oldChild.exitCode === null && oldChild.signalCode === null) {
        await new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            oldChild.off('exit', onExit);
            reject(new Error('Expected real receiver crash before acknowledgement'));
          }, 3000);
          function onExit() { clearTimeout(timer); resolve(); }
          oldChild.once('exit', onExit);
        });
      }
      assert.equal(oldChild.exitCode, 47, 'Fixture must terminate abruptly with crash exit code');
      live = await launchRestartReceiver(statePath);
      assert.notEqual(live.child.pid, oldPid, 'Recovery must launch a new OS process');
      return live.config;
    };
    return await fn(config, recoverReceiver);
  } finally {
    if (live) await stopRestartReceiver(live.child);
    await rm(directory, { recursive: true, force: true });
  }
}

test('receiver startup tolerates a slow but healthy local child', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-slow-start-'));
  let live;
  try {
    const started = Date.now();
    live = await launchRestartReceiver(join(directory, 'durable.json'), { startupDelayMs: 4250 });
    assert.ok(Date.now() - started >= 4000, 'fixture must actually delay readiness');
    const result = await runLab(live.config, { secret });
    assert.equal(result.success, true);
  } finally {
    if (live) await stopRestartReceiver(live.child);
    await rm(directory, { recursive: true, force: true });
  }
});

test('receiver startup fails closed when a broken local child never signals ready', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-no-ready-'));
  try {
    await assert.rejects(
      () => launchRestartReceiver(join(directory, 'durable.json'), {
        suppressReady: true, startupTimeoutMs: 300,
      }),
      /Local receiver startup timed out/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('four scenarios pass with secure idempotent receiver', async () => {
  await withServer({}, async (config) => {
    const result = await runLab(config, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 4);
    assert.ok(result.scenarios.every((r) => r.passed));
  });
});
test('detects duplicate processing', async () => {
  await withServer({ dedupe: false }, async (config) => {
    const result = await runLab(config, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.some((r) => r.scenario === 'duplicate_delivery' && !r.passed));
  });
});
test('detects receiver accepting invalid signatures', async () => {
  await withServer({ verifySignatures: false }, async (config) => {
    const result = await runLab(config, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.some((r) => r.scenario === 'tampered_body' && !r.passed));
  });
});
test('rejects remote endpoints even when supplied via config', async () => {
  await assert.rejects(() => runLab({ endpoint: 'https://example.com/', observer: 'http://localhost:3000/state' }, { secret }));
});
test('rejects status misconfiguration', async () => {
  await withServer({}, async (config) => {
    await assert.rejects(() => runLab({ ...config, timeoutMs: 60000 }, { secret }));
    await assert.rejects(() => runLab({ ...config, rejectionStatuses: [] }, { secret }));
  });
});
test('detects receiver accepting stale signed timestamps', async () => {
  await withServer({ verifyFreshness: false }, async (config) => {
    const result = await runLab(config, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.some((r) => r.scenario === 'stale_timestamp' && !r.passed));
  });
});

test('opt-in concurrent duplicate deliveries preserve a single observable effect', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, concurrentDuplicateDeliveries: 4 }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const race = result.scenarios.find((r) => r.scenario === 'concurrent_duplicate_delivery');
    assert.equal(race.passed, true);
    assert.deepEqual(race.httpStatuses, [200, 200, 200, 200]);
    assert.equal(race.expectedProcessedCount, 2);
    assert.equal(race.observedProcessedCount, 2);
  });
});

test('concurrent duplicate check exposes non-atomic deduplication missed by sequential tests', async () => {
  await withServer({ unsafeConcurrentDedupe: true }, async (config) => {
    const result = await runLab({ ...config, concurrentDuplicateDeliveries: 4 }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((r) => r.passed));
    const race = result.scenarios.find((r) => r.scenario === 'concurrent_duplicate_delivery');
    assert.equal(race.passed, false);
    assert.equal(race.expectedProcessedCount, 2);
    assert.equal(race.observedProcessedCount, 5);
  });
});

test('concurrent duplicate delivery count must be an integer between two and eight', async () => {
  await withServer({}, async (config) => {
    for (const concurrentDuplicateDeliveries of [-1, 0, 1, 9, 2.5, '4', true]) {
      await assert.rejects(() => runLab({ ...config, concurrentDuplicateDeliveries }, { secret }),
        /concurrentDuplicateDeliveries/);
    }
  });
});

test('opt-in transient failure retries the same signed delivery once and commits only on success', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, retryAfterTransientFailure: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const retry = result.scenarios.find((r) => r.scenario === 'retry_after_transient_failure');
    assert.equal(retry.passed, true);
    assert.deepEqual(retry.httpStatuses, [503, 200]);
    assert.equal(retry.observedCountAfterFailure, 1);
    assert.equal(retry.observedProcessedCount, 2);
    assert.equal(retry.expectedProcessedCount, 2);
  });
});

test('retry check catches a receiver that marks a failed delivery as already processed', async () => {
  await withServer({ unsafeMarkFailedRetrySeen: true }, async (config) => {
    const result = await runLab({ ...config, retryAfterTransientFailure: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((r) => r.passed));
    const retry = result.scenarios.find((r) => r.scenario === 'retry_after_transient_failure');
    assert.equal(retry.passed, false);
    assert.deepEqual(retry.httpStatuses, [503, 200]);
    assert.equal(retry.observedCountAfterFailure, 1);
    assert.equal(retry.observedProcessedCount, 1);
    assert.equal(retry.expectedProcessedCount, 2);
  });
});

test('retry check rejects a receiver that ignores the explicit local fault injection', async () => {
  await withServer({ supportRetryFault: false }, async (config) => {
    const result = await runLab({ ...config, retryAfterTransientFailure: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((r) => r.passed));
    const retry = result.scenarios.find((r) => r.scenario === 'retry_after_transient_failure');
    assert.equal(retry.passed, false);
    assert.deepEqual(retry.httpStatuses, [200, 200]);
    assert.equal(retry.observedProcessedCount, 2);
  });
});

test('retry scenario requires a boolean opt-in before sending any request', async () => {
  await withServer({}, async (config) => {
    for (const retryAfterTransientFailure of [1, 0, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, retryAfterTransientFailure }, { secret }),
        /retryAfterTransientFailure/);
    }
  });
});

test('retry check composes with concurrent duplicates without reusing an event ID', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({
      ...config, concurrentDuplicateDeliveries: 4, retryAfterTransientFailure: true,
    }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    const retry = result.scenarios.at(-1);
    assert.equal(retry.scenario, 'retry_after_transient_failure');
    assert.equal(retry.expectedCountAfterFailure, 2);
    assert.equal(retry.observedCountAfterFailure, 2);
    assert.equal(retry.expectedProcessedCount, 3);
    assert.equal(retry.observedProcessedCount, 3);
  });
});

test('opt-in lost acknowledgement observes the committed effect and safe signed redelivery', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, lostAckAfterCommit: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const lostAck = result.scenarios.at(-1);
    assert.equal(lostAck.scenario, 'lost_ack_after_commit');
    assert.equal(lostAck.firstAttemptOutcome, 'transport_error');
    assert.equal(lostAck.observedCountAfterLostAck, 2);
    assert.equal(lostAck.observedProcessedCount, 2);
    assert.equal(lostAck.expectedProcessedCount, 2);
    assert.equal(lostAck.retryHttpStatus, 200);
  });
});

test('lost-ack regression detects replayed effects when the receiver forgets committed dedupe state', async () => {
  await withServer({ unsafeForgetLostAckDedupe: true }, async (config) => {
    const result = await runLab({ ...config, lostAckAfterCommit: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((r) => r.passed));
    const lostAck = result.scenarios.at(-1);
    assert.equal(lostAck.firstAttemptOutcome, 'transport_error');
    assert.equal(lostAck.observedCountAfterLostAck, 2);
    assert.equal(lostAck.expectedProcessedCount, 2);
    assert.equal(lostAck.observedProcessedCount, 3);
    assert.equal(lostAck.passed, false);
  });
});

test('lost-ack scenario refuses to pass when a receiver ignores the fault adapter', async () => {
  await withServer({ supportLostAckFault: false }, async (config) => {
    const result = await runLab({ ...config, lostAckAfterCommit: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((r) => r.passed));
    const lostAck = result.scenarios.at(-1);
    assert.equal(lostAck.firstAttemptOutcome, 'http_200');
    assert.equal(lostAck.observedCountAfterLostAck, 2);
    assert.equal(lostAck.observedProcessedCount, 2);
    assert.equal(lostAck.passed, false);
  });
});

test('lost-ack option rejects nonboolean values before any local request', async () => {
  await withServer({}, async (config) => {
    for (const lostAckAfterCommit of [1, 0, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, lostAckAfterCommit }, { secret }),
        /lostAckAfterCommit/);
    }
  });
});

test('lost-ack scenario composes with retry and concurrent checks using a fresh signed event', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({
      ...config, concurrentDuplicateDeliveries: 4, retryAfterTransientFailure: true,
      lostAckAfterCommit: true,
    }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    assert.equal(result.scenarios.at(-1).scenario, 'lost_ack_after_commit');
    assert.equal(result.scenarios.at(-1).expectedProcessedCount, 4);
    assert.equal(result.scenarios.at(-1).observedProcessedCount, 4);
  });
});

test('out-of-order activation is rejected before create and safely retried after create', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, outOfOrderStateTransitions: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const order = result.scenarios.at(-1);
    assert.equal(order.scenario, 'out_of_order_state_transition');
    assert.equal(order.passed, true);
    assert.deepEqual(order.httpStatuses, [409, 200, 200]);
    assert.deepEqual(order.observedResourceStates, ['missing', 'created', 'activated']);
    assert.deepEqual(order.observedCounts, [1, 2, 3]);
    assert.equal(order.expectedProcessedCount, 3);
  });
});

test('out-of-order test detects a receiver that applies activation before creation', async () => {
  await withServer({ unsafeApplyOutOfOrder: true }, async (config) => {
    const result = await runLab({ ...config, outOfOrderStateTransitions: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((r) => r.passed));
    const order = result.scenarios.at(-1);
    assert.equal(order.scenario, 'out_of_order_state_transition');
    assert.equal(order.passed, false);
    assert.equal(order.observedResourceStates[0], 'activated');
    assert.equal(order.observedCounts[0], 2);
  });
});

test('out-of-order test detects a receiver that deduplicates a rejected activation', async () => {
  await withServer({ unsafeMarkRejectedOrderSeen: true }, async (config) => {
    const result = await runLab({ ...config, outOfOrderStateTransitions: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((r) => r.passed));
    const order = result.scenarios.at(-1);
    assert.equal(order.scenario, 'out_of_order_state_transition');
    assert.deepEqual(order.httpStatuses, [409, 200, 200]);
    assert.deepEqual(order.observedResourceStates, ['missing', 'created', 'created']);
    assert.deepEqual(order.observedCounts, [1, 2, 2]);
  });
});

test('out-of-order check rejects a receiver without the required transition adapter', async () => {
  await withServer({ supportOrderTransitions: false }, async (config) => {
    const result = await runLab({ ...config, outOfOrderStateTransitions: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).scenario, 'out_of_order_state_transition');
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('out-of-order option rejects nonboolean values before sending any requests', async () => {
  await withServer({}, async (config) => {
    for (const outOfOrderStateTransitions of [1, 0, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, outOfOrderStateTransitions }, { secret }),
        /outOfOrderStateTransitions/);
    }
  });
});

test('out-of-order scenario composes with other optional checks without reusing event IDs', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({
      ...config, concurrentDuplicateDeliveries: 4, retryAfterTransientFailure: true,
      lostAckAfterCommit: true, outOfOrderStateTransitions: true,
    }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 8);
    const order = result.scenarios.at(-1);
    assert.equal(order.scenario, 'out_of_order_state_transition');
    assert.deepEqual(order.httpStatuses, [409, 200, 200]);
    assert.deepEqual(order.observedResourceStates, ['missing', 'created', 'activated']);
    assert.deepEqual(order.observedCounts, [4, 5, 6]);
  });
});

test('opt-in rotation accepts the previous signing key but rejects a retired one without an effect', async () => {
  await withServer({ previousSecret }, async (config) => {
    const result = await runLab({ ...config, secretRotation: true },
      { secret, previousSecret, retiredSecret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const rotation = result.scenarios.at(-1);
    assert.equal(rotation.scenario, 'secret_rotation_grace_and_retirement');
    assert.equal(rotation.passed, true);
    assert.deepEqual(rotation.httpStatuses, [200, 401]);
    assert.deepEqual(rotation.observedCounts, [2, 2]);
    assert.equal(rotation.expectedProcessedCount, 2);
    assert.ok(!JSON.stringify(result).includes(previousSecret.slice(6)));
    assert.ok(!JSON.stringify(result).includes(retiredSecret.slice(6)));
  });
});

test('rotation check catches an incorrectly rejected previous key in its grace window', async () => {
  await withServer({ previousSecret, unsafeRejectPreviousSecret: true }, async (config) => {
    const result = await runLab({ ...config, secretRotation: true },
      { secret, previousSecret, retiredSecret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const rotation = result.scenarios.at(-1);
    assert.deepEqual(rotation.httpStatuses, [401, 401]);
    assert.deepEqual(rotation.observedCounts, [1, 1]);
    assert.equal(rotation.expectedProcessedCount, 2);
  });
});

test('rotation check catches a receiver that still accepts the retired key', async () => {
  await withServer({ previousSecret, retiredSecret, unsafeAcceptRetiredSecret: true }, async (config) => {
    const result = await runLab({ ...config, secretRotation: true },
      { secret, previousSecret, retiredSecret });
    assert.equal(result.success, false);
    const rotation = result.scenarios.at(-1);
    assert.deepEqual(rotation.httpStatuses, [200, 200]);
    assert.deepEqual(rotation.observedCounts, [2, 3]);
    assert.equal(rotation.expectedProcessedCount, 2);
  });
});

test('rotation check catches a rejected retired key that secretly commits an effect', async () => {
  await withServer({ previousSecret, retiredSecret, unsafeProcessRetiredBeforeReject: true },
    async (config) => {
      const result = await runLab({ ...config, secretRotation: true },
        { secret, previousSecret, retiredSecret });
      assert.equal(result.success, false);
      const rotation = result.scenarios.at(-1);
      assert.deepEqual(rotation.httpStatuses, [200, 401]);
      assert.deepEqual(rotation.observedCounts, [2, 3]);
    });
});

test('rotation opt-in validates three distinct well-formed keys before any request', async () => {
  await withServer({ previousSecret }, async (config) => {
    for (const secretRotation of [1, 0, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, secretRotation },
        { secret, previousSecret, retiredSecret }), /secretRotation/);
    }
    for (const keys of [
      { previousSecret: undefined, retiredSecret },
      { previousSecret, retiredSecret: undefined },
      { previousSecret: secret, retiredSecret },
      { previousSecret, retiredSecret: previousSecret },
      { previousSecret: 'whsec_broken', retiredSecret },
    ]) {
      await assert.rejects(() => runLab({ ...config, secretRotation: true },
        { secret, ...keys }), /rotation|secret|key/i);
    }
  });
});

test('rotation composes with the other optional scenarios without sharing event IDs', async () => {
  await withServer({ previousSecret }, async (config) => {
    const result = await runLab({
      ...config, concurrentDuplicateDeliveries: 4, retryAfterTransientFailure: true,
      lostAckAfterCommit: true, outOfOrderStateTransitions: true, secretRotation: true,
    }, { secret, previousSecret, retiredSecret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 9);
    const rotation = result.scenarios.at(-1);
    assert.deepEqual(rotation.httpStatuses, [200, 401]);
    assert.deepEqual(rotation.observedCounts, [7, 7]);
    assert.equal(rotation.expectedProcessedCount, 7);
  });
});

test('CLI reads rotation keys from the environment and returns only non-secret results', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-rotation-'));
  const server = await startMock({ secret, previousSecret });
  try {
    const path = join(directory, 'lab.json');
    await writeFile(path, JSON.stringify({ ...server.config, secretRotation: true }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', path],
      { env: { ...process.env, WFL_SECRET: secret,
        WFL_PREVIOUS_SECRET: previousSecret, WFL_RETIRED_SECRET: retiredSecret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.equal(result.scenarios.at(-1).scenario, 'secret_rotation_grace_and_retirement');
    for (const signingSecret of [secret, previousSecret, retiredSecret]) {
      assert.ok(!stdout.includes(signingSecret));
      assert.ok(!stdout.includes(signingSecret.slice(6)));
    }
  } finally {
    await server.stop();
    await rm(directory, { recursive: true });
  }
});

test('opt-in restart proves dedupe state persists across a real receiver process replacement', async () => {
  await withRestartReceiver({}, async (config, restartReceiver) => {
    const result = await runLab({ ...config, restartAfterCommit: true },
      { secret, restartReceiver });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const restart = result.scenarios.at(-1);
    assert.equal(restart.scenario, 'restart_preserves_idempotency');
    assert.equal(restart.passed, true);
    assert.deepEqual(restart.httpStatuses, [200, 200]);
    assert.deepEqual(restart.observedCounts, [2, 2, 2]);
    assert.notEqual(restart.receiverInstanceIds[0], restart.receiverInstanceIds[1]);
    assert.equal(restart.expectedProcessedCount, 2);
  });
});

test('restart regression detects a receiver that forgets dedupe keys but retains effect count', async () => {
  await withRestartReceiver({ forgetDedupeOnRestart: true }, async (config, restartReceiver) => {
    const result = await runLab({ ...config, restartAfterCommit: true },
      { secret, restartReceiver });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const restart = result.scenarios.at(-1);
    assert.equal(restart.scenario, 'restart_preserves_idempotency');
    assert.deepEqual(restart.httpStatuses, [200, 200]);
    assert.deepEqual(restart.observedCounts, [2, 2, 3]);
    assert.equal(restart.expectedProcessedCount, 2);
    assert.equal(restart.passed, false);
  });
});

test('restart check rejects a no-op callback that never replaces the receiver instance', async () => {
  await withRestartReceiver({}, async (config) => {
    const result = await runLab({ ...config, restartAfterCommit: true },
      { secret, restartReceiver: async () => config });
    assert.equal(result.success, false);
    const restart = result.scenarios.at(-1);
    assert.deepEqual(restart.observedCounts, [2, 2, 2]);
    assert.equal(restart.receiverInstanceIds[0], restart.receiverInstanceIds[1]);
    assert.equal(restart.passed, false);
  });
});

test('restart option requires an explicit local process controller before sending requests', async () => {
  await withServer({}, async (config) => {
    for (const restartAfterCommit of [1, 0, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, restartAfterCommit }, { secret }),
        /restartAfterCommit/);
    }
    await assert.rejects(() => runLab({ ...config, restartAfterCommit: true }, { secret }),
      /restartReceiver/);
  });
});

test('restart controller may only return loopback HTTP endpoint and observer URLs', async () => {
  await withRestartReceiver({}, async (config) => {
    await assert.rejects(() => runLab({ ...config, restartAfterCommit: true },
      { secret, restartReceiver: async () => ({ endpoint: 'https://example.com/webhook',
        observer: config.observer }) }), /loopback/i);
  });
});

test('abrupt post-persist crash recovers a signed event without another observed effect', async () => {
  await withCrashReceiver({}, async (config, recoverReceiver) => {
    const result = await runLab({ ...config, crashAfterPersist: true }, { secret, recoverReceiver });
    assert.equal(result.success, true);
    const crash = result.scenarios.at(-1);
    assert.equal(crash.scenario, 'crash_after_persist_before_ack');
    assert.equal(crash.firstAttemptOutcome, 'transport_error');
    assert.deepEqual(crash.observedCounts, [1, 2, 2]);
    assert.equal(crash.retryHttpStatus, 200);
    assert.notEqual(crash.receiverInstanceIds[0], crash.receiverInstanceIds[1]);
    assert.equal(crash.expectedProcessedCount, 2);
  });
});

test('abrupt crash catches a committed count without durable dedupe state', async () => {
  await withCrashReceiver({ loseDedupeOnCrash: true }, async (config, recoverReceiver) => {
    const result = await runLab({ ...config, crashAfterPersist: true }, { secret, recoverReceiver });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const crash = result.scenarios.at(-1);
    assert.equal(crash.firstAttemptOutcome, 'transport_error');
    assert.deepEqual(crash.observedCounts, [1, 2, 3]);
    assert.equal(crash.expectedProcessedCount, 2);
    assert.equal(crash.passed, false);
  });
});

test('abrupt crash catches durable dedupe state with a lost effect count', async () => {
  await withCrashReceiver({ loseCountOnCrash: true }, async (config, recoverReceiver) => {
    const result = await runLab({ ...config, crashAfterPersist: true }, { secret, recoverReceiver });
    assert.equal(result.success, false);
    const crash = result.scenarios.at(-1);
    assert.deepEqual(crash.observedCounts, [1, 1, 1]);
    assert.equal(crash.expectedProcessedCount, 2);
    assert.equal(crash.passed, false);
  });
});

test('crash check rejects a local receiver that acknowledges instead of crashing', async () => {
  await withCrashReceiver({ ignoreCrashFault: true }, async (config) => {
    const result = await runLab({ ...config, crashAfterPersist: true },
      { secret, recoverReceiver: async () => config });
    assert.equal(result.success, false);
    const crash = result.scenarios.at(-1);
    assert.equal(crash.firstAttemptOutcome, 'http_200');
    assert.equal(crash.passed, false);
  });
});

test('crash scenario validates opt-in and recovery controller before any network request', async () => {
  await withServer({}, async (config) => {
    for (const crashAfterPersist of [1, 0, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, crashAfterPersist }, { secret }),
        /crashAfterPersist/);
    }
    await assert.rejects(() => runLab({ ...config, crashAfterPersist: true }, { secret }),
      /recoverReceiver/);
    await assert.rejects(() => runLab({
      ...config, restartAfterCommit: true, crashAfterPersist: true,
    }, { secret, restartReceiver: async () => config, recoverReceiver: async () => config }),
    /separate runs/);
  });
});

test('crash recovery controller cannot return a non-loopback destination', async () => {
  await withServer({}, async (config) => {
    await assert.rejects(() => runLab({ ...config, crashAfterPersist: true },
      { secret, recoverReceiver: async () => ({
        endpoint: 'https://example.com/webhook', observer: config.observer,
      }) }), /loopback/i);
  });
});

async function withRetentionReceiver(options, fn) {
  let receiverNow = Math.floor(Date.now() / 1000);
  const server = await startMock({ secret, clock: () => receiverNow,
    dedupeRetentionSeconds: 60, ...options });
  const advanceReceiverTime = async (seconds) => { receiverNow += seconds; };
  try {
    return await fn(server.config, { advanceReceiverTime, clock: () => receiverNow });
  } finally {
    await server.stop();
  }
}

test('opt-in retention check protects duplicates just before TTL and rejects stale replay after expiry', async () => {
  await withRetentionReceiver({}, async (config, callbacks) => {
    const result = await runLab({ ...config, retentionWindowSeconds: 60 },
      { secret, ...callbacks });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const retention = result.scenarios.at(-1);
    assert.equal(retention.scenario, 'retention_boundary_stale_replay');
    assert.deepEqual(retention.httpStatuses, [200, 200, 401]);
    assert.deepEqual(retention.observedCounts, [2, 2, 2]);
    assert.equal(retention.expectedProcessedCount, 2);
    assert.equal(retention.passed, true);
  });
});

test('retention check detects a broken receiver that evicts dedupe keys before the declared window', async () => {
  await withRetentionReceiver({ unsafePrematureRetentionEviction: true }, async (config, callbacks) => {
    const result = await runLab({ ...config, retentionWindowSeconds: 60 },
      { secret, ...callbacks });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const retention = result.scenarios.at(-1);
    assert.deepEqual(retention.httpStatuses, [200, 200, 401]);
    assert.deepEqual(retention.observedCounts, [2, 3, 3]);
    assert.equal(retention.expectedProcessedCount, 2);
  });
});

test('retention check detects a previously accepted event replayed with a stale signature', async () => {
  await withRetentionReceiver({ unsafeAcceptExpiredReplay: true }, async (config, callbacks) => {
    const result = await runLab({ ...config, retentionWindowSeconds: 60 },
      { secret, ...callbacks });
    assert.equal(result.success, false);
    const retention = result.scenarios.at(-1);
    assert.deepEqual(retention.httpStatuses, [200, 200, 200]);
    assert.deepEqual(retention.observedCounts, [2, 2, 3]);
    assert.equal(retention.expectedProcessedCount, 2);
  });
});

test('retention check rejects a time controller that never advances receiver time', async () => {
  await withRetentionReceiver({}, async (config, { clock }) => {
    const result = await runLab({ ...config, retentionWindowSeconds: 60 },
      { secret, clock, advanceReceiverTime: async () => {} });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('retention option and fake-time controller are validated before any requests', async () => {
  await withServer({}, async (config) => {
    for (const retentionWindowSeconds of [0, 1, 241, -1, 30.5, '60', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, retentionWindowSeconds },
        { secret, advanceReceiverTime: async () => {} }), /retentionWindowSeconds/);
    }
    await assert.rejects(() => runLab({ ...config, retentionWindowSeconds: 60 },
      { secret }), /advanceReceiverTime/);
  });
});

test('opt-in reused signed event ID rejects conflicting authenticated payload without another effect', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, conflictingEventIdPayload: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const conflict = result.scenarios.at(-1);
    assert.equal(conflict.scenario, 'signed_event_id_payload_conflict');
    assert.deepEqual(conflict.httpStatuses, [200, 200, 409]);
    assert.deepEqual(conflict.observedCounts, [2, 2, 2]);
    assert.equal(conflict.expectedProcessedCount, 2);
    assert.equal(conflict.passed, true);
  });
});

test('conflicting signed event ID detects receiver that silently acknowledges different content', async () => {
  await withServer({ unsafeAcknowledgeConflictingPayload: true }, async (config) => {
    const result = await runLab({ ...config, conflictingEventIdPayload: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const conflict = result.scenarios.at(-1);
    assert.deepEqual(conflict.httpStatuses, [200, 200, 200]);
    assert.deepEqual(conflict.observedCounts, [2, 2, 2]);
    assert.equal(conflict.passed, false);
  });
});

test('conflicting signed event ID detects rejected event that nonetheless commits an effect', async () => {
  await withServer({ unsafeCommitConflictingPayload: true }, async (config) => {
    const result = await runLab({ ...config, conflictingEventIdPayload: true }, { secret });
    assert.equal(result.success, false);
    const conflict = result.scenarios.at(-1);
    assert.deepEqual(conflict.httpStatuses, [200, 200, 409]);
    assert.deepEqual(conflict.observedCounts, [2, 2, 3]);
    assert.equal(conflict.expectedProcessedCount, 2);
    assert.equal(conflict.passed, false);
  });
});

test('conflicting event ID opt-in validates its configuration before sending requests', async () => {
  await withServer({}, async (config) => {
    for (const conflictingEventIdPayload of [1, 0, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, conflictingEventIdPayload }, { secret }),
        /conflictingEventIdPayload/);
    }
    const response = await fetch(config.observer);
    assert.equal((await response.json()).processedCount, 0);
  });
});

test('conflicting signed event ID scenario composes with simultaneous duplicates', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, concurrentDuplicateDeliveries: 4,
      conflictingEventIdPayload: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    assert.equal(result.scenarios.at(-1).scenario, 'signed_event_id_payload_conflict');
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [3, 3, 3]);
  });
});

test('CLI exposes opt-in signed event ID conflict check without leaking signing material', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-conflict-'));
  const server = await startMock({ secret });
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify({
      ...server.config, conflictingEventIdPayload: true,
    }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.equal(result.scenarios.at(-1).scenario, 'signed_event_id_payload_conflict');
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 409]);
    assert.ok(!stdout.includes(secret));
    assert.ok(!stdout.includes(secret.slice(6)));
  } finally {
    await server.stop();
    await rm(directory, { recursive: true });
  }
});

test('opt-in re-signed duplicate keeps one observed effect for the same event ID and body', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, resignedDuplicateDelivery: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const replay = result.scenarios.at(-1);
    assert.equal(replay.scenario, 'resigned_duplicate_delivery');
    assert.deepEqual(replay.httpStatuses, [200, 200]);
    assert.deepEqual(replay.observedCounts, [2, 2]);
    assert.equal(replay.expectedProcessedCount, 2);
  });
});

test('re-signed duplicate catches a receiver deduplicating by signature rather than event ID', async () => {
  await withServer({ unsafeDedupeBySignature: true }, async (config) => {
    const result = await runLab({ ...config, resignedDuplicateDelivery: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const replay = result.scenarios.at(-1);
    assert.equal(replay.scenario, 'resigned_duplicate_delivery');
    assert.deepEqual(replay.httpStatuses, [200, 200]);
    assert.deepEqual(replay.observedCounts, [2, 3]);
    assert.equal(replay.passed, false);
  });
});

test('re-signed duplicate catches receiver that rejects a new valid signature for a known ID', async () => {
  await withServer({ unsafeRejectResignedDuplicate: true }, async (config) => {
    const result = await runLab({ ...config, resignedDuplicateDelivery: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const replay = result.scenarios.at(-1);
    assert.deepEqual(replay.httpStatuses, [200, 409]);
    assert.deepEqual(replay.observedCounts, [2, 2]);
    assert.equal(replay.passed, false);
  });
});

test('re-signed duplicate opt-in rejects invalid values before sending any request', async () => {
  await withServer({}, async (config) => {
    for (const resignedDuplicateDelivery of [1, 0, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, resignedDuplicateDelivery }, { secret }),
        /resignedDuplicateDelivery/);
    }
    const observer = await fetch(config.observer);
    assert.equal((await observer.json()).processedCount, 0);
  });
});

test('re-signed retry composes with strict event-ID payload collision and concurrent duplication', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, resignedDuplicateDelivery: true,
      conflictingEventIdPayload: true, concurrentDuplicateDeliveries: 4 }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    assert.equal(result.scenarios.at(-1).scenario, 'resigned_duplicate_delivery');
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [4, 4]);
  });
});

test('CLI exposes re-signed duplicate check without serializing signing keys or signatures', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-resigned-'));
  const server = await startMock({ secret });
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify({ ...server.config, resignedDuplicateDelivery: true }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.equal(result.scenarios.at(-1).scenario, 'resigned_duplicate_delivery');
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2]);
    assert.ok(!stdout.includes(secret));
    assert.ok(!stdout.includes('webhook-signature'));
  } finally {
    await server.stop();
    await rm(directory, { recursive: true });
  }
});

test('opt-in future-dated signed delivery is rejected with no committed effect', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, rejectFutureSignedTimestamp: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const future = result.scenarios.at(-1);
    assert.equal(future.scenario, 'future_signed_timestamp');
    assert.equal(future.httpStatus, 401);
    assert.equal(future.observedProcessedCount, 1);
    assert.equal(future.expectedProcessedCount, 1);
    assert.equal(future.passed, true);
  });
});

test('future timestamp scenario catches receiver that only checks signatures and past expiry', async () => {
  await withServer({ unsafeAcceptFutureTimestamp: true }, async (config) => {
    const result = await runLab({ ...config, rejectFutureSignedTimestamp: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const future = result.scenarios.at(-1);
    assert.equal(future.scenario, 'future_signed_timestamp');
    assert.equal(future.httpStatus, 200);
    assert.equal(future.observedProcessedCount, 2);
    assert.equal(future.passed, false);
  });
});

test('future timestamp scenario catches rejection after a forbidden observed commit', async () => {
  await withServer({ unsafeCommitFutureBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectFutureSignedTimestamp: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const future = result.scenarios.at(-1);
    assert.equal(future.scenario, 'future_signed_timestamp');
    assert.equal(future.httpStatus, 401);
    assert.equal(future.observedProcessedCount, 2);
    assert.equal(future.passed, false);
  });
});

test('future timestamp opt-in validates boolean before making any requests', async () => {
  await withServer({}, async (config) => {
    for (const rejectFutureSignedTimestamp of [1, 0, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, rejectFutureSignedTimestamp }, { secret }),
        /rejectFutureSignedTimestamp/);
    }
    const observer = await fetch(config.observer);
    assert.equal((await observer.json()).processedCount, 0);
  });
});

test('future timestamp rejection composes with re-signed and concurrent duplicates', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, rejectFutureSignedTimestamp: true,
      resignedDuplicateDelivery: true, concurrentDuplicateDeliveries: 4 }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    assert.equal(result.scenarios.at(-1).scenario, 'future_signed_timestamp');
    assert.equal(result.scenarios.at(-1).observedProcessedCount, 3);
  });
});

test('CLI exposes future signed timestamp rejection without leaking synthetic keys', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-future-'));
  const server = await startMock({ secret });
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify({ ...server.config, rejectFutureSignedTimestamp: true }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.equal(result.scenarios.at(-1).scenario, 'future_signed_timestamp');
    assert.ok(!stdout.includes(secret));
    assert.ok(!stdout.includes('webhook-signature'));
  } finally {
    await server.stop();
    await rm(directory, { recursive: true });
  }
});

test('opt-in duplicate authentication rejects a modified HMAC for an already processed event ID', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, rejectTamperedDuplicateSignature: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const replay = result.scenarios.at(-1);
    assert.equal(replay.scenario, 'tampered_duplicate_signature');
    assert.deepEqual(replay.httpStatuses, [200, 401]);
    assert.deepEqual(replay.observedCounts, [2, 2]);
    assert.equal(replay.expectedProcessedCount, 2);
    assert.equal(replay.passed, true);
  });
});

test('duplicate authentication detects a receiver that checks dedupe before the HMAC', async () => {
  await withServer({ unsafeAcknowledgeTamperedDuplicate: true }, async (config) => {
    const result = await runLab({ ...config, rejectTamperedDuplicateSignature: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const replay = result.scenarios.at(-1);
    assert.deepEqual(replay.httpStatuses, [200, 200]);
    assert.deepEqual(replay.observedCounts, [2, 2]);
    assert.equal(replay.passed, false);
  });
});

test('duplicate authentication detects a rejected replay that still commits another effect', async () => {
  await withServer({ unsafeCommitTamperedDuplicateBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectTamperedDuplicateSignature: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const replay = result.scenarios.at(-1);
    assert.deepEqual(replay.httpStatuses, [200, 401]);
    assert.deepEqual(replay.observedCounts, [2, 3]);
    assert.equal(replay.passed, false);
  });
});

test('duplicate authentication opt-in validates boolean before any requests', async () => {
  await withServer({}, async (config) => {
    for (const rejectTamperedDuplicateSignature of [1, 0, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, rejectTamperedDuplicateSignature }, { secret }),
        /rejectTamperedDuplicateSignature/);
    }
    const observer = await fetch(config.observer);
    assert.equal((await observer.json()).processedCount, 0);
  });
});

test('duplicate authentication composes with re-signed and signed-payload collision checks', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, resignedDuplicateDelivery: true,
      conflictingEventIdPayload: true, rejectTamperedDuplicateSignature: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    assert.equal(result.scenarios.at(-1).scenario, 'tampered_duplicate_signature');
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [4, 4]);
  });
});

test('CLI exposes duplicate signature verification without leaking HMAC or secret', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-dup-auth-'));
  const server = await startMock({ secret });
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify({ ...server.config, rejectTamperedDuplicateSignature: true }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.equal(result.scenarios.at(-1).scenario, 'tampered_duplicate_signature');
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 401]);
    assert.ok(!stdout.includes(secret));
    assert.ok(!stdout.includes('webhook-signature'));
  } finally {
    await server.stop();
    await rm(directory, { recursive: true });
  }
});

test('concurrent distinct signed events each commit one observed effect', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, concurrentDistinctDeliveries: 4 }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const concurrent = result.scenarios.at(-1);
    assert.equal(concurrent.scenario, 'concurrent_distinct_delivery');
    assert.deepEqual(concurrent.httpStatuses, [200, 200, 200, 200]);
    assert.equal(concurrent.expectedProcessedCount, 5);
    assert.equal(concurrent.observedProcessedCount, 5);
  });
});

test('concurrent distinct check catches a receiver that coalesces unrelated signed IDs', async () => {
  await withServer({ unsafeCoalesceDistinctEvents: true }, async (config) => {
    const result = await runLab({ ...config, concurrentDistinctDeliveries: 4 }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const concurrent = result.scenarios.at(-1);
    assert.equal(concurrent.passed, false);
    assert.deepEqual(concurrent.httpStatuses, [200, 200, 200, 200]);
    assert.equal(concurrent.expectedProcessedCount, 5);
    assert.equal(concurrent.observedProcessedCount, 2);
  });
});

test('concurrent distinct check catches a receiver that rejects events while busy', async () => {
  await withServer({ unsafeRejectConcurrentDistinct: true }, async (config) => {
    const result = await runLab({ ...config, concurrentDistinctDeliveries: 4 }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const concurrent = result.scenarios.at(-1);
    assert.equal(concurrent.passed, false);
    assert.equal(concurrent.httpStatuses.filter((status) => status === 503).length, 3);
    assert.equal(concurrent.observedProcessedCount, 2);
  });
});

test('concurrent distinct count rejects unsupported values before sending any request', async () => {
  await withServer({}, async (config) => {
    for (const concurrentDistinctDeliveries of [0, 1, 9, 1.5, '4', true, null, []]) {
      await assert.rejects(() => runLab({ ...config, concurrentDistinctDeliveries }, { secret }),
        /concurrentDistinctDeliveries/);
    }
    const response = await fetch(config.observer);
    assert.equal((await response.json()).processedCount, 0);
  });
});

test('concurrent distinct check supports the minimum and maximum bounded fan-out', async () => {
  for (const concurrentDistinctDeliveries of [2, 8]) {
    await withServer({}, async (config) => {
      const result = await runLab({ ...config, concurrentDistinctDeliveries }, { secret });
      assert.equal(result.success, true);
      const concurrent = result.scenarios.at(-1);
      assert.equal(concurrent.httpStatuses.length, concurrentDistinctDeliveries);
      assert.equal(concurrent.observedProcessedCount, 1 + concurrentDistinctDeliveries);
      assert.equal(concurrent.expectedProcessedCount, 1 + concurrentDistinctDeliveries);
    });
  }
});

test('concurrent distinct check composes with duplicate races and transient retries', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, concurrentDuplicateDeliveries: 4,
      concurrentDistinctDeliveries: 4, retryAfterTransientFailure: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    const distinct = result.scenarios.find((report) => report.scenario === 'concurrent_distinct_delivery');
    assert.equal(distinct.expectedProcessedCount, 6);
    assert.equal(distinct.observedProcessedCount, 6);
    assert.equal(result.scenarios.at(-1).expectedProcessedCount, 7);
  });
});

test('CLI exposes concurrent distinct delivery coverage without emitting synthetic secrets', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-distinct-'));
  const server = await startMock({ secret });
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify({ ...server.config, concurrentDistinctDeliveries: 4 }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.equal(result.scenarios.at(-1).scenario, 'concurrent_distinct_delivery');
    assert.ok(!stdout.includes(secret));
    assert.ok(!stdout.includes('webhook-signature'));
  } finally {
    await server.stop();
    await rm(directory, { recursive: true });
  }
});

test('opt-in stale signed duplicate is rejected even while its event ID remains cached', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, rejectStaleDuplicateSignature: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const replay = result.scenarios.at(-1);
    assert.equal(replay.scenario, 'stale_cached_duplicate_signature');
    assert.deepEqual(replay.httpStatuses, [200, 401]);
    assert.deepEqual(replay.observedCounts, [2, 2]);
    assert.equal(replay.expectedProcessedCount, 2);
    assert.equal(replay.passed, true);
  });
});

test('stale cached duplicate check detects idempotency cache bypassing timestamp freshness', async () => {
  await withServer({ unsafeAcknowledgeStaleDuplicate: true }, async (config) => {
    const result = await runLab({ ...config, rejectStaleDuplicateSignature: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const replay = result.scenarios.at(-1);
    assert.deepEqual(replay.httpStatuses, [200, 200]);
    assert.deepEqual(replay.observedCounts, [2, 2]);
    assert.equal(replay.passed, false);
  });
});

test('stale cached duplicate check detects rejection that still records another effect', async () => {
  await withServer({ unsafeCommitStaleDuplicateBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectStaleDuplicateSignature: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const replay = result.scenarios.at(-1);
    assert.deepEqual(replay.httpStatuses, [200, 401]);
    assert.deepEqual(replay.observedCounts, [2, 3]);
    assert.equal(replay.passed, false);
  });
});

test('stale cached duplicate opt-in rejects nonboolean values before any requests', async () => {
  await withServer({}, async (config) => {
    for (const rejectStaleDuplicateSignature of [1, 0, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, rejectStaleDuplicateSignature }, { secret }),
        /rejectStaleDuplicateSignature/);
    }
    const state = await fetch(config.observer);
    assert.equal((await state.json()).processedCount, 0);
  });
});

test('stale cached duplicate freshness composes with tampered and re-signed duplicates', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, rejectStaleDuplicateSignature: true,
      rejectTamperedDuplicateSignature: true, resignedDuplicateDelivery: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    assert.equal(result.scenarios.at(-1).scenario, 'stale_cached_duplicate_signature');
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [4, 4]);
  });
});

test('CLI exposes stale cached duplicate rejection without leaking signing material', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-stale-duplicate-'));
  const server = await startMock({ secret });
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify({ ...server.config, rejectStaleDuplicateSignature: true }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.equal(result.scenarios.at(-1).scenario, 'stale_cached_duplicate_signature');
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 401]);
    assert.ok(!stdout.includes(secret));
    assert.ok(!stdout.includes('webhook-signature'));
  } finally {
    await server.stop();
    await rm(directory, { recursive: true });
  }
});

test('concurrent authenticated payload collision accepts only one body per event ID', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, concurrentConflictingEventIdPayload: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const collision = result.scenarios.at(-1);
    assert.equal(collision.scenario, 'concurrent_signed_event_id_collision');
    assert.deepEqual(collision.httpStatuses, [200, 409]);
    assert.equal(collision.observedProcessedCount, 2);
    assert.equal(collision.expectedProcessedCount, 2);
  });
});

test('concurrent collision catches non-atomic check then commit of both signed bodies', async () => {
  await withServer({ unsafeRacyConcurrentConflict: true }, async (config) => {
    const result = await runLab({ ...config, concurrentConflictingEventIdPayload: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const collision = result.scenarios.at(-1);
    assert.deepEqual(collision.httpStatuses, [200, 200]);
    assert.equal(collision.observedProcessedCount, 3);
    assert.equal(collision.expectedProcessedCount, 2);
    assert.equal(collision.passed, false);
  });
});

test('concurrent collision catches receivers that silently acknowledge conflicting content', async () => {
  await withServer({ unsafeAcknowledgeConflictingPayload: true }, async (config) => {
    const result = await runLab({ ...config, concurrentConflictingEventIdPayload: true }, { secret });
    assert.equal(result.success, false);
    const collision = result.scenarios.at(-1);
    assert.deepEqual(collision.httpStatuses, [200, 200]);
    assert.equal(collision.observedProcessedCount, 2);
    assert.equal(collision.passed, false);
  });
});

test('concurrent collision catches a receiver that rejects after committing', async () => {
  await withServer({ unsafeCommitConflictingPayload: true }, async (config) => {
    const result = await runLab({ ...config, concurrentConflictingEventIdPayload: true }, { secret });
    assert.equal(result.success, false);
    const collision = result.scenarios.at(-1);
    assert.deepEqual(collision.httpStatuses, [200, 409]);
    assert.equal(collision.observedProcessedCount, 3);
    assert.equal(collision.passed, false);
  });
});

test('concurrent collision option rejects nonboolean values before traffic', async () => {
  await withServer({}, async (config) => {
    for (const concurrentConflictingEventIdPayload of [0, 1, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, concurrentConflictingEventIdPayload },
        { secret }), /concurrentConflictingEventIdPayload/);
    }
    const state = await fetch(config.observer);
    assert.equal((await state.json()).processedCount, 0);
  });
});

test('concurrent collision composes with distinct and duplicate concurrency checks', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, concurrentConflictingEventIdPayload: true,
      concurrentDistinctDeliveries: 2, concurrentDuplicateDeliveries: 4 }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    assert.equal(result.scenarios.at(-1).scenario, 'concurrent_signed_event_id_collision');
    assert.equal(result.scenarios.at(-1).observedProcessedCount, 5);
  });
});

test('CLI exposes concurrent collision without exposing signing material', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-conflict-race-'));
  const server = await startMock({ secret });
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify({
      ...server.config, concurrentConflictingEventIdPayload: true,
    }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.equal(result.scenarios.at(-1).scenario, 'concurrent_signed_event_id_collision');
    assert.ok(!stdout.includes(secret));
    assert.ok(!stdout.includes('webhook-signature'));
  } finally {
    await server.stop();
    await rm(directory, { recursive: true });
  }
});

test('unauthenticated changed-body replay is rejected before signed ID collision handling', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, rejectUnauthenticatedCollision: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const replay = result.scenarios.at(-1);
    assert.equal(replay.scenario, 'unauthenticated_event_id_collision');
    assert.deepEqual(replay.httpStatuses, [200, 401]);
    assert.deepEqual(replay.observedCounts, [2, 2]);
    assert.equal(replay.expectedProcessedCount, 2);
  });
});

test('unauthenticated collision catches receivers inspecting stored payloads before HMAC', async () => {
  await withServer({ unsafeInspectCollisionBeforeAuth: true }, async (config) => {
    const result = await runLab({ ...config, rejectUnauthenticatedCollision: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 409]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2]);
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('unauthenticated collision detects rejection after committing an untrusted effect', async () => {
  await withServer({ unsafeCommitUnauthenticatedCollision: true }, async (config) => {
    const result = await runLab({ ...config, rejectUnauthenticatedCollision: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 401]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3]);
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('unauthenticated collision rejects 409 even when custom rejection statuses include it', async () => {
  await withServer({ unsafeInspectCollisionBeforeAuth: true }, async (config) => {
    const result = await runLab({ ...config, rejectUnauthenticatedCollision: true,
      rejectionStatuses: [400, 401, 403, 409] }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).httpStatuses[1], 409);
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('unauthenticated collision opt-in rejects malformed values before any traffic', async () => {
  await withServer({}, async (config) => {
    for (const rejectUnauthenticatedCollision of [0, 1, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, rejectUnauthenticatedCollision },
        { secret }), /rejectUnauthenticatedCollision/);
    }
    const state = await fetch(config.observer);
    assert.equal((await state.json()).processedCount, 0);
  });
});

test('unauthenticated collision composes with signed collision and duplicate authentication', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, conflictingEventIdPayload: true,
      rejectTamperedDuplicateSignature: true, rejectUnauthenticatedCollision: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    assert.equal(result.scenarios.at(-1).scenario, 'unauthenticated_event_id_collision');
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [4, 4]);
  });
});

test('CLI surfaces unauthenticated collision check without exposing HMAC or synthetic secret', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-unauth-collision-'));
  const server = await startMock({ secret });
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify({
      ...server.config, rejectUnauthenticatedCollision: true,
    }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.equal(result.scenarios.at(-1).scenario, 'unauthenticated_event_id_collision');
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 401]);
    assert.ok(!stdout.includes(secret));
    assert.ok(!stdout.includes('webhook-signature'));
  } finally {
    await server.stop();
    await rm(directory, { recursive: true });
  }
});

test('opt-in retired-key replay rejects a previously accepted ID without another effect', async () => {
  await withServer({ previousSecret, retiredSecret }, async (config) => {
    const result = await runLab({ ...config, rejectRetiredKeyDuplicate: true },
      { secret, previousSecret, retiredSecret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const replay = result.scenarios.at(-1);
    assert.equal(replay.scenario, 'retired_key_cached_duplicate');
    assert.deepEqual(replay.httpStatuses, [200, 401]);
    assert.deepEqual(replay.observedCounts, [2, 2]);
    assert.equal(replay.expectedProcessedCount, 2);
  });
});

test('retired-key replay catches a cache-first receiver that acknowledges revoked signatures', async () => {
  await withServer({ previousSecret, retiredSecret, unsafeAcknowledgeRetiredDuplicate: true },
    async (config) => {
      const result = await runLab({ ...config, rejectRetiredKeyDuplicate: true },
        { secret, previousSecret, retiredSecret });
      assert.equal(result.success, false);
      assert.ok(result.scenarios.slice(0, 4).every((item) => item.passed));
      const replay = result.scenarios.at(-1);
      assert.deepEqual(replay.httpStatuses, [200, 200]);
      assert.deepEqual(replay.observedCounts, [2, 2]);
    });
});

test('retired-key replay catches rejection after a hidden committed effect', async () => {
  await withServer({ previousSecret, retiredSecret, unsafeCommitRetiredDuplicateBeforeReject: true },
    async (config) => {
      const result = await runLab({ ...config, rejectRetiredKeyDuplicate: true },
        { secret, previousSecret, retiredSecret });
      assert.equal(result.success, false);
      const replay = result.scenarios.at(-1);
      assert.deepEqual(replay.httpStatuses, [200, 401]);
      assert.deepEqual(replay.observedCounts, [2, 3]);
      assert.equal(replay.expectedProcessedCount, 2);
    });
});

test('retired-key replay option validates key material and boolean before any request', async () => {
  await withServer({ previousSecret, retiredSecret }, async (config) => {
    for (const rejectRetiredKeyDuplicate of [0, 1, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, rejectRetiredKeyDuplicate },
        { secret, previousSecret, retiredSecret }), /rejectRetiredKeyDuplicate/);
    }
    for (const keys of [
      { previousSecret: undefined, retiredSecret },
      { previousSecret, retiredSecret: undefined },
      { previousSecret: secret, retiredSecret },
      { previousSecret, retiredSecret: previousSecret },
      { previousSecret, retiredSecret: 'whsec_invalid' },
    ]) {
      await assert.rejects(() => runLab({ ...config, rejectRetiredKeyDuplicate: true },
        { secret, ...keys }), /rotation|secret|key/i);
    }
  });
});

test('retired-key cached replay composes with rotation and signed duplicate scenarios', async () => {
  await withServer({ previousSecret, retiredSecret }, async (config) => {
    const result = await runLab({ ...config, secretRotation: true,
      rejectRetiredKeyDuplicate: true, rejectTamperedDuplicateSignature: true },
    { secret, previousSecret, retiredSecret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    const revoked = result.scenarios.find((item) => item.scenario === 'retired_key_cached_duplicate');
    assert.deepEqual(revoked.httpStatuses, [200, 401]);
    assert.deepEqual(revoked.observedCounts, [3, 3]);
    assert.equal(result.scenarios.at(-1).scenario, 'tampered_duplicate_signature');
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [4, 4]);
  });
});

test('CLI reports retired-key replay without exposing any of three synthetic secrets', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-retired-cached-'));
  const server = await startMock({ secret, previousSecret, retiredSecret });
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify({ ...server.config, rejectRetiredKeyDuplicate: true }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret, WFL_PREVIOUS_SECRET: previousSecret,
        WFL_RETIRED_SECRET: retiredSecret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.equal(result.scenarios.at(-1).scenario, 'retired_key_cached_duplicate');
    for (const signingSecret of [secret, previousSecret, retiredSecret]) {
      assert.ok(!stdout.includes(signingSecret));
      assert.ok(!stdout.includes(signingSecret.slice(6)));
    }
  } finally {
    await server.stop();
    await rm(directory, { recursive: true });
  }
});

test('opt-in multi-signature headers accept either valid token position and reject all-invalid', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, multiSignatureHeader: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'multi_signature_header');
    assert.deepEqual(probe.httpStatuses, [200, 200, 401]);
    assert.deepEqual(probe.observedCounts, [2, 2, 2]);
    assert.equal(probe.expectedProcessedCount, 2);
  });
});

test('multi-signature header catches receivers that verify only the first signature', async () => {
  await withServer({ unsafeFirstSignatureOnly: true }, async (config) => {
    const result = await runLab({ ...config, multiSignatureHeader: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((item) => item.passed));
    const probe = result.scenarios.at(-1);
    assert.deepEqual(probe.httpStatuses, [401, 200, 401]);
    assert.deepEqual(probe.observedCounts, [1, 2, 2]);
    assert.equal(probe.passed, false);
  });
});

test('multi-signature header catches receivers that accept two invalid signatures', async () => {
  await withServer({ unsafeAcceptInvalidMultiSignature: true }, async (config) => {
    const result = await runLab({ ...config, multiSignatureHeader: true }, { secret });
    assert.equal(result.success, false);
    const probe = result.scenarios.at(-1);
    assert.deepEqual(probe.httpStatuses, [200, 200, 200]);
    assert.deepEqual(probe.observedCounts, [2, 2, 3]);
    assert.equal(probe.passed, false);
  });
});

test('multi-signature header catches a rejected invalid signature that still commits', async () => {
  await withServer({ unsafeCommitInvalidMultiSignatureBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, multiSignatureHeader: true }, { secret });
    assert.equal(result.success, false);
    const probe = result.scenarios.at(-1);
    assert.deepEqual(probe.httpStatuses, [200, 200, 401]);
    assert.deepEqual(probe.observedCounts, [2, 2, 3]);
    assert.equal(probe.passed, false);
  });
});

test('multi-signature flag rejects malformed values before any traffic', async () => {
  await withServer({}, async (config) => {
    for (const multiSignatureHeader of [0, 1, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, multiSignatureHeader }, { secret }),
        /multiSignatureHeader/);
    }
    const response = await fetch(config.observer);
    assert.equal((await response.json()).processedCount, 0);
  });
});

test('multi-signature header composes with rotation and re-signed duplicate checks', async () => {
  await withServer({ previousSecret, retiredSecret }, async (config) => {
    const result = await runLab({ ...config, multiSignatureHeader: true,
      secretRotation: true, resignedDuplicateDelivery: true }, { secret, previousSecret, retiredSecret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    assert.equal(result.scenarios.at(-1).scenario, 'multi_signature_header');
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [4, 4, 4]);
  });
});

test('CLI exposes multi-signature header probe without leaking signing material', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-multisig-'));
  const server = await startMock({ secret });
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify({ ...server.config, multiSignatureHeader: true }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.equal(result.scenarios.at(-1).scenario, 'multi_signature_header');
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 401]);
    assert.ok(!stdout.includes(secret));
    assert.ok(!stdout.includes(secret.slice(6)));
    assert.ok(!stdout.includes('webhook-signature'));
  } finally {
    await server.stop();
    await rm(directory, { recursive: true });
  }
});

test('opt-in committed HTTP 503 retry preserves one effect across identical signed redelivery', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, retryAfterCommittedError: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'retry_after_committed_503');
    assert.equal(probe.passed, true);
    assert.deepEqual(probe.httpStatuses, [503, 200]);
    assert.deepEqual(probe.observedCounts, [2, 2]);
    assert.equal(probe.expectedProcessedCount, 2);
  });
});

test('committed HTTP 503 retry detects a lost idempotency record after first commit', async () => {
  await withServer({ unsafeForgetCommitted503Dedupe: true }, async (config) => {
    const result = await runLab({ ...config, retryAfterCommittedError: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((item) => item.passed));
    const probe = result.scenarios.at(-1);
    assert.equal(probe.passed, false);
    assert.deepEqual(probe.httpStatuses, [503, 200]);
    assert.deepEqual(probe.observedCounts, [2, 3]);
  });
});

test('committed HTTP 503 retry detects a receiver that failed before committing', async () => {
  await withServer({ unsafeRejectCommitted503BeforeProcess: true }, async (config) => {
    const result = await runLab({ ...config, retryAfterCommittedError: true }, { secret });
    assert.equal(result.success, false);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.passed, false);
    assert.deepEqual(probe.httpStatuses, [503, 200]);
    assert.deepEqual(probe.observedCounts, [1, 2]);
  });
});

test('committed HTTP 503 retry fails when test-only fault injection is ignored', async () => {
  await withServer({ supportCommitted503Fault: false }, async (config) => {
    const result = await runLab({ ...config, retryAfterCommittedError: true }, { secret });
    assert.equal(result.success, false);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.passed, false);
    assert.deepEqual(probe.httpStatuses, [200, 200]);
    assert.deepEqual(probe.observedCounts, [2, 2]);
  });
});

test('committed HTTP 503 retry requires boolean opt-in before loopback traffic', async () => {
  await withServer({}, async (config) => {
    for (const retryAfterCommittedError of [0, 1, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, retryAfterCommittedError }, { secret }),
        /retryAfterCommittedError/);
    }
    assert.equal((await (await fetch(config.observer)).json()).processedCount, 0);
  });
});

test('committed HTTP 503 retry composes with rejected-before-processing and lost-ack retries', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, retryAfterTransientFailure: true,
      lostAckAfterCommit: true, retryAfterCommittedError: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'retry_after_committed_503');
    assert.deepEqual(probe.observedCounts, [4, 4]);
  });
});

test('CLI reports committed HTTP 503 retry without signing material', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-committed503-'));
  const server = await startMock({ secret });
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify({ ...server.config, retryAfterCommittedError: true }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [503, 200]);
    assert.ok(!stdout.includes(secret));
    assert.ok(!stdout.includes(secret.slice(6)));
    assert.ok(!stdout.includes('webhook-signature'));
  } finally {
    await server.stop();
    await rm(directory, { recursive: true });
  }
});

test('delayed creation replay after activation preserves terminal resource state and effect count', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, delayedCreationReplayAfterActivation: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'delayed_creation_replay_after_activation');
    assert.deepEqual(probe.httpStatuses, [200, 200, 200]);
    assert.deepEqual(probe.observedCounts, [2, 3, 3]);
    assert.deepEqual(probe.observedResourceStates, ['created', 'activated', 'activated']);
    assert.equal(probe.expectedProcessedCount, 3);
  });
});

test('delayed creation replay detects a duplicate that regresses an activated resource', async () => {
  await withServer({ unsafeReapplyDelayedCreation: true }, async (config) => {
    const result = await runLab({ ...config, delayedCreationReplayAfterActivation: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((item) => item.passed));
    const probe = result.scenarios.at(-1);
    assert.deepEqual(probe.httpStatuses, [200, 200, 200]);
    assert.deepEqual(probe.observedCounts, [2, 3, 4]);
    assert.deepEqual(probe.observedResourceStates, ['created', 'activated', 'created']);
  });
});

test('delayed creation replay detects a receiver that rejects a previously accepted creation', async () => {
  await withServer({ unsafeRejectDelayedCreation: true }, async (config) => {
    const result = await runLab({ ...config, delayedCreationReplayAfterActivation: true }, { secret });
    assert.equal(result.success, false);
    const probe = result.scenarios.at(-1);
    assert.deepEqual(probe.httpStatuses, [200, 200, 409]);
    assert.deepEqual(probe.observedCounts, [2, 3, 3]);
    assert.deepEqual(probe.observedResourceStates, ['created', 'activated', 'activated']);
  });
});

test('delayed creation replay catches hidden effects even if final state remains activated', async () => {
  await withServer({ unsafeCountDelayedCreationReplay: true }, async (config) => {
    const result = await runLab({ ...config, delayedCreationReplayAfterActivation: true }, { secret });
    assert.equal(result.success, false);
    const probe = result.scenarios.at(-1);
    assert.deepEqual(probe.httpStatuses, [200, 200, 200]);
    assert.deepEqual(probe.observedCounts, [2, 3, 4]);
    assert.deepEqual(probe.observedResourceStates, ['created', 'activated', 'activated']);
  });
});

test('delayed creation replay rejects a receiver without a local resource-state adapter', async () => {
  await withServer({ supportOrderTransitions: false }, async (config) => {
    const result = await runLab({ ...config, delayedCreationReplayAfterActivation: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).scenario, 'delayed_creation_replay_after_activation');
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('delayed creation replay option rejects nonboolean values before loopback traffic', async () => {
  await withServer({}, async (config) => {
    for (const delayedCreationReplayAfterActivation of [0, 1, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, delayedCreationReplayAfterActivation }, { secret }),
        /delayedCreationReplayAfterActivation/);
    }
    assert.equal((await (await fetch(config.observer)).json()).processedCount, 0);
  });
});

test('delayed creation replay composes with out-of-order and committed HTTP 503 checks', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, retryAfterCommittedError: true,
      outOfOrderStateTransitions: true, delayedCreationReplayAfterActivation: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'delayed_creation_replay_after_activation');
    assert.deepEqual(probe.observedCounts, [5, 6, 6]);
    assert.deepEqual(probe.observedResourceStates, ['created', 'activated', 'activated']);
  });
});

test('CLI reports delayed creation replay without exposing signing material', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-delayed-creation-'));
  const server = await startMock({ secret });
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify({
      ...server.config, delayedCreationReplayAfterActivation: true,
    }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.equal(result.scenarios.at(-1).scenario, 'delayed_creation_replay_after_activation');
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 200]);
    assert.ok(!stdout.includes(secret));
    assert.ok(!stdout.includes(secret.slice(6)));
    assert.ok(!stdout.includes('webhook-signature'));
  } finally {
    await server.stop();
    await rm(directory, { recursive: true });
  }
});
