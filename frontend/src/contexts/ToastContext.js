import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';

const ToastContext = createContext(null);

function toastStyles(type) {
  if (type === 'success') {
    return 'border-green-200 bg-green-50 text-green-800 dark:border-green-800 dark:bg-green-900/30 dark:text-green-100';
  }
  if (type === 'error') {
    return 'border-red-200 bg-red-50 text-red-800 dark:border-red-800 dark:bg-red-900/30 dark:text-red-100';
  }
  return 'border-gray-200 bg-white text-gray-900 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100';
}

export const ToastProvider = ({ children }) => {
  const [toasts, setToasts] = useState([]);

  const dismiss = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const push = useCallback((type, message, options = {}) => {
    const id = options.id || `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const durationMs = typeof options.durationMs === 'number' ? options.durationMs : 4000;

    setToasts((prev) => [...prev, { id, type, message }]);

    if (durationMs > 0) {
      window.setTimeout(() => dismiss(id), durationMs);
    }

    return id;
  }, [dismiss]);

  const api = useMemo(
    () => ({
      success: (message, options) => push('success', message, options),
      error: (message, options) => push('error', message, options),
      info: (message, options) => push('info', message, options),
      dismiss,
    }),
    [dismiss, push]
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="fixed right-4 top-4 z-50 flex w-[calc(100vw-2rem)] max-w-md flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`ui-card border p-3 shadow-lg ${toastStyles(t.type)}`}
            role="status"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="text-sm font-medium leading-snug">{t.message}</div>
              <button
                type="button"
                onClick={() => dismiss(t.id)}
                className="ui-btn ui-btn-ghost px-2 py-0.5 text-xs"
                aria-label="Dismiss"
              >
                ✕
              </button>
            </div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

export const useToast = () => {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    return {
      success: () => {},
      error: () => {},
      info: () => {},
      dismiss: () => {},
    };
  }
  return ctx;
};
