export function isNonEmpty(value) {
  return String(value || '').trim().length > 0;
}

export function isEmail(value) {
  const v = String(value || '').trim();
  if (!v) return false;
  // Pragmatic email check (not RFC-perfect, but good UX)
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

export function minLength(value, n) {
  return String(value || '').length >= n;
}

export function onlyDigits(value) {
  return /^\d+$/.test(String(value || '').trim());
}
