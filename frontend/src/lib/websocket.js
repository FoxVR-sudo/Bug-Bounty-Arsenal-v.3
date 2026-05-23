const stripTrailingSlash = (value) => String(value || '').replace(/\/+$/, '');

export function isWsEnabled() {
  // Default to enabled and let the UI fall back to polling if the socket fails.
  // CRA env vars are baked in at build time, so a missing build arg should not
  // silently disable live updates in otherwise-correct deployments.
  return String(process.env.REACT_APP_ENABLE_WS || 'true').toLowerCase() !== 'false';
}

export function getWsBaseUrl() {
  // Prefer API URL env var; fallback to current origin.
  const apiUrl = stripTrailingSlash(process.env.REACT_APP_API_URL || '');

  if (apiUrl) {
    // If API url ends with /api, strip it.
    const withoutApi = apiUrl.replace(/\/api$/, '');
    const ws = withoutApi.replace(/^https:/, 'wss:').replace(/^http:/, 'ws:');
    return ws;
  }

  const origin = window.location.origin;
  return origin.replace(/^https:/, 'wss:').replace(/^http:/, 'ws:');
}

export function buildScanWsUrl(scanId, token) {
  const base = stripTrailingSlash(getWsBaseUrl());
  const qs = token ? `?token=${encodeURIComponent(token)}` : '';
  return `${base}/ws/scan/${encodeURIComponent(String(scanId))}/${qs}`;
}
