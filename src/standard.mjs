import { createHmac, timingSafeEqual } from 'node:crypto';

// Only HMAC v1 for Standard Webhooks. Never use a real production signing key.
export function keyFromSecret(secret) {
  if (typeof secret !== 'string' || !secret.startsWith('whsec_')) {
    throw new TypeError('Secret must use the Standard Webhooks whsec_ base64 format');
  }
  const encoded = secret.slice(6);
  const key = Buffer.from(encoded, 'base64');
  if (key.length < 24 || key.length > 64 || key.toString('base64') !== encoded) {
    throw new TypeError('Signing key must contain 24-64 base64-encoded bytes');
  }
  return key;
}

export function sign({ secret, id, timestamp, body }) {
  if (!id || !/^[A-Za-z0-9_-]+$/.test(id) || !Number.isSafeInteger(timestamp) || typeof body !== 'string') {
    throw new TypeError('Invalid signed webhook metadata or raw body');
  }
  const digest = createHmac('sha256', keyFromSecret(secret))
    .update(`${id}.${timestamp}.${body}`, 'utf8')
    .digest('base64');
  return `v1,${digest}`;
}

export function verify({ secret, id, timestamp, body, signature, now = Math.floor(Date.now() / 1000), tolerance = 300 }) {
  if (!Number.isSafeInteger(Number(timestamp)) || Math.abs(now - Number(timestamp)) > tolerance || typeof signature !== 'string') {
    return false;
  }
  let expected;
  try {
    expected = sign({ secret, id, timestamp: Number(timestamp), body });
  } catch {
    return false;
  }
  const trusted = Buffer.from(expected, 'utf8');
  // A Standard Webhooks header can carry multiple space-separated v1 signatures
  // during signing-key rotation. Compare each candidate, not the entire header.
  return signature.trim().split(/\s+/).some((candidate) => {
    const actual = Buffer.from(candidate, 'utf8');
    return actual.length === trusted.length && timingSafeEqual(actual, trusted);
  });
}
