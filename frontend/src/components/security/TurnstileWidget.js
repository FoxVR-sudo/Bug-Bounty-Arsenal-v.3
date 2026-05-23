import React, { useEffect, useMemo, useRef, useState } from 'react';

const TURNSTILE_SCRIPT_SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';

function loadTurnstileScript() {
  if (typeof document === 'undefined') return Promise.reject(new Error('No document'));

  // If script already present, resolve immediately.
  const existing = document.querySelector(`script[src="${TURNSTILE_SCRIPT_SRC}"]`);
  if (existing) return Promise.resolve();

  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = TURNSTILE_SCRIPT_SRC;
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error('Failed to load Turnstile script'));
    document.head.appendChild(script);
  });
}

export function isTurnstileEnabled() {
  const enabled = String(process.env.REACT_APP_TURNSTILE_ENABLED || '').toLowerCase() === 'true';
  const siteKey = String(process.env.REACT_APP_TURNSTILE_SITE_KEY || '').trim();
  return enabled && !!siteKey;
}

export default function TurnstileWidget({
  onToken,
  onError,
  onExpire,
  className,
  action,
}) {
  const enabled = useMemo(() => isTurnstileEnabled(), []);
  const siteKey = String(process.env.REACT_APP_TURNSTILE_SITE_KEY || '').trim();

  const containerRef = useRef(null);
  const widgetIdRef = useRef(null);
  const [ready, setReady] = useState(false);

  // Use refs for callbacks so inline arrow functions in parent don't cause re-renders
  const onTokenRef = useRef(onToken);
  const onErrorRef = useRef(onError);
  const onExpireRef = useRef(onExpire);
  useEffect(() => { onTokenRef.current = onToken; }, [onToken]);
  useEffect(() => { onErrorRef.current = onError; }, [onError]);
  useEffect(() => { onExpireRef.current = onExpire; }, [onExpire]);

  useEffect(() => {
    if (!enabled) return;

    let cancelled = false;

    loadTurnstileScript()
      .then(() => {
        if (cancelled) return;
        setReady(true);
      })
      .catch((e) => {
        if (cancelled) return;
        setReady(false);
        if (onErrorRef.current) onErrorRef.current(e);
      });

    return () => {
      cancelled = true;
    };
  }, [enabled]);

  useEffect(() => {
    if (!enabled) return;
    if (!ready) return;
    if (!containerRef.current) return;

    const turnstile = window.turnstile;
    if (!turnstile || typeof turnstile.render !== 'function') {
      if (onErrorRef.current) onErrorRef.current(new Error('Turnstile not available'));
      return;
    }

    // Render once.
    if (widgetIdRef.current !== null) return;

    try {
      widgetIdRef.current = turnstile.render(containerRef.current, {
        sitekey: siteKey,
        action: action || 'signup',
        callback: (token) => {
          if (onTokenRef.current) onTokenRef.current(token);
        },
        'expired-callback': () => {
          if (onExpireRef.current) onExpireRef.current();
          if (onTokenRef.current) onTokenRef.current('');
        },
        'error-callback': () => {
          if (onErrorRef.current) onErrorRef.current(new Error('Turnstile error'));
          if (onTokenRef.current) onTokenRef.current('');
        },
      });
    } catch (e) {
      if (onErrorRef.current) onErrorRef.current(e);
    }

    return () => {
      try {
        if (widgetIdRef.current !== null && window.turnstile && typeof window.turnstile.remove === 'function') {
          window.turnstile.remove(widgetIdRef.current);
        }
      } catch (_) {
        // no-op
      }
      widgetIdRef.current = null;
    };
  }, [enabled, ready, siteKey, action]);

  if (!enabled) return null;

  return (
    <div className={className}>
      <div ref={containerRef} />
      {!ready && (
        <div className="text-sm text-gray-500 dark:text-gray-300 mt-2">
          Loading CAPTCHA…
        </div>
      )}
    </div>
  );
}
