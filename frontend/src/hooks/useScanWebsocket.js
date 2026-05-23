import { useEffect, useMemo, useRef, useState } from 'react';
import { buildScanWsUrl } from '../lib/websocket';

export default function useScanWebsocket(scanId, { enabled = true } = {}) {
  const [connected, setConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState(null);
  const socketRef = useRef(null);
  const parseErrorCountRef = useRef(0);

  const url = useMemo(() => {
    if (!scanId) return null;
    const token = localStorage.getItem('token');
    return buildScanWsUrl(scanId, token);
  }, [scanId]);

  useEffect(() => {
    if (!enabled || !url) return;

    let closedByEffect = false;

    try {
      const ws = new WebSocket(url);
      socketRef.current = ws;

      ws.onopen = () => {
        if (closedByEffect) return;
        setConnected(true);
        // request status explicitly (consumer supports it)
        ws.send(JSON.stringify({ type: 'get_status' }));
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          setLastEvent(payload);
        } catch (_) {
          parseErrorCountRef.current += 1;
          if (parseErrorCountRef.current === 1) {
            const raw = typeof event?.data === 'string' ? event.data.slice(0, 500) : '';
            // eslint-disable-next-line no-console
            console.warn('WS message JSON parse failed (first occurrence)', { raw });
          }
          setLastEvent({ type: 'ws_parse_error' });
        }
      };

      ws.onerror = () => {
        if (closedByEffect) return;
        setConnected(false);
      };

      ws.onclose = () => {
        if (closedByEffect) return;
        setConnected(false);
      };

      return () => {
        closedByEffect = true;
        setConnected(false);
        try {
          ws.close();
        } catch (_) {
          // ignore
        }
      };
    } catch (_) {
      setConnected(false);
      return undefined;
    }
  }, [enabled, url]);

  return { connected, lastEvent };
}
