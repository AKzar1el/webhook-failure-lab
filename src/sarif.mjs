// SARIF 2.1.0 export of completed local receiver-contract checks.
// Emit only allowlisted numeric and synthetic-state observations; never payloads or keys.
import { evidenceFor } from './report-evidence.mjs';

const caveat = 'processedCount is a user-provided observer, not independently proven business-side-effect correctness';

// Only runLab's fixed scenario names may appear in externally shared SARIF.
// Keep this list aligned with src/run.mjs, including conditional crash variants.
const knownScenarioIds = new Set(`
  aborted_chunked_upload_retry async_ack_dedupe case_sensitive_event_ids
  chunked_utf8_signed_replay client_timeout_after_commit client_timeout_before_commit
  concurrent_distinct_delivery concurrent_duplicate_delivery concurrent_resigned_duplicate_delivery
  concurrent_signed_event_id_collision crash_after_persist_before_ack
  crash_after_persist_parallel_retries crash_before_commit_retry
  crash_before_commit_parallel_retries delayed_creation_replay_after_activation
  distinct_events_same_resource distinct_ids_identical_signed_body duplicate_delivery
  duplicate_json_data_key_retry duplicate_nested_resource_id_retry
  duplicate_wire_content_encoding_retry duplicate_wire_content_type_retry
  duplicate_wire_event_id_retry duplicate_wire_signature_retry duplicate_wire_timestamp_retry
  future_cached_duplicate_signature future_signed_timestamp invalid_signed_event_schema_retry
  invalid_utf8_signed_retry json_charset_content_type keep_alive_connection_isolation
  lost_ack_after_commit malformed_gzip_retry malformed_signed_payload_retry
  missing_event_id_retry missing_signature_retry missing_timestamp_retry mixed_case_header_replay
  multi_signature_header noncanonical_signed_timestamp out_of_order_state_transition
  oversized_gzip_retry oversized_signed_payload_retry partial_body_upload_abort_retry
  prototype_property_event_ids raw_json_signature_bytes resigned_duplicate_delivery
  restart_preserves_idempotency retention_boundary_stale_replay retired_key_cached_duplicate
  retry_after_committed_503 retry_after_rate_limit retry_after_rejected_signature
  retry_after_transient_failure secret_rotation_grace_and_retirement
  signed_event_id_payload_conflict stale_cached_duplicate_signature stale_timestamp
  tampered_body tampered_duplicate_signature tampered_webhook_id_header
  tenant_scoped_signed_event_ids unauthenticated_event_id_collision unsigned_cached_duplicate
  unsupported_content_encoding_retry unsupported_signature_version_retry valid_delivery
  versioned_out_of_order_update wrong_content_type_retry wrong_http_method_retry
`.trim().split(/\s+/));

function safeScenario(value) {
  return knownScenarioIds.has(value) ? value : 'redacted_invalid_scenario';
}

function ruleId(scenario) {
  return 'WFL_' + scenario.replace(/[^a-zA-Z0-9]+/g, '_').toUpperCase();
}

export function toSarif(result) {
  if (!result || !Array.isArray(result.scenarios) ||
      typeof result.success !== 'boolean' ||
      result.scenarios.some((item) => typeof item?.scenario !== 'string' ||
        typeof item.passed !== 'boolean')) {
    throw new TypeError('SARIF export requires a completed webhook lab result');
  }

  const scenarios = [...new Set(result.scenarios.map((item) => safeScenario(item.scenario)))];
  const rules = scenarios.map((scenario) => ({
    id: ruleId(scenario),
    shortDescription: { text: `Webhook receiver contract: ${scenario}` },
  }));
  const results = result.scenarios.filter((report) => !report.passed).map((report) => ({
    ruleId: ruleId(safeScenario(report.scenario)),
    level: 'error',
    message: { text: `Local webhook receiver failed ${safeScenario(report.scenario)}. ` +
      `Observed receiver-reported values: ${JSON.stringify(evidenceFor(report))}. ` +
      'The observer does not prove external exactly-once business effects.' },
  }));

  return {
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'Webhook Failure Lab', rules } },
      invocations: [{ executionSuccessful: true }],
      results,
      properties: {
        coverage: scenarios,
        caveat,
      },
    }],
  };
}

// A run that stopped before completing cannot claim any receiver contract results.
// Do not interpolate exception text: it may contain local URLs or secret-bearing input.
export function toSarifExecutionError() {
  return {
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'Webhook Failure Lab', rules: [] } },
      invocations: [{
        executionSuccessful: false,
        toolExecutionNotifications: [{
          level: 'error',
          message: { text: 'Webhook Failure Lab could not complete. Check local configuration and receiver availability; no contract outcome was established.' },
        }],
      }],
      results: [],
      properties: {
        coverage: [],
        caveat: 'The run did not complete; no receiver side-effect guarantee or scenario result is asserted.',
      },
    }],
  };
}
