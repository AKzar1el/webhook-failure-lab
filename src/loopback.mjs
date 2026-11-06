export function requireLoopbackUrl(raw, label = 'endpoint') {
  let url;
  try { url = new URL(raw); } catch { throw new TypeError(`${label} must be an absolute URL`); }
  const approved = new Set(['localhost', '127.0.0.1', '[::1]']);
  if (url.protocol !== 'http:' || !approved.has(url.hostname) || url.username || url.password || url.hash) {
    throw new TypeError(`${label} must be a plain-HTTP loopback URL without credentials or fragments`);
  }
  return url.href;
}
