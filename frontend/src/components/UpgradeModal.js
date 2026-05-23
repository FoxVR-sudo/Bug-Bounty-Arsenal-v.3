import React, { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { FiAlertTriangle, FiArrowRight } from 'react-icons/fi';
import useModalA11y from '../hooks/useModalA11y';

export default function UpgradeModal({
  open,
  title,
  message,
  bullets,
  onClose,
  ctaHref = '/support',
  ctaLabel = 'Open Support',
}) {
  const dialogRef = useModalA11y(open, { onClose });
  const titleId = useMemo(() => `upgrade-modal-title-${Math.random().toString(36).slice(2)}`, []);
  const descId = useMemo(() => `upgrade-modal-desc-${Math.random().toString(36).slice(2)}`, []);

  if (!open) return null;

  const list = Array.isArray(bullets) ? bullets : [];

  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose?.();
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        tabIndex={-1}
        className="ui-card rounded-2xl max-w-lg w-full p-8 text-center bg-white/95 dark:bg-gray-900/80 backdrop-blur-xl border border-gray-200/50 dark:border-gray-700/50 shadow-2xl"
      >
        <div className="mb-6">
          <div className="mx-auto w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mb-4">
            <FiAlertTriangle className="text-red-600" size={32} />
          </div>
          <h3 id={titleId} className="text-2xl font-bold mb-2 text-gray-900 dark:text-white">
            {title}
          </h3>
          <p id={descId} className="text-sm text-gray-600 dark:text-gray-300">
            {message || 'This action is unavailable right now.'}
          </p>
        </div>

        {list.length > 0 ? (
          <div className="rounded-lg p-4 mb-6 border bg-blue-50 dark:bg-blue-900/10 border-blue-200 dark:border-blue-800/40">
            <p className="text-sm font-semibold mb-2 text-blue-900 dark:text-blue-200">What to do next:</p>
            <ul className="text-sm text-left space-y-1 text-blue-800 dark:text-blue-200/90">
              {list.map((item) => (
                <li key={item}>✓ {item}</li>
              ))}
            </ul>
          </div>
        ) : null}

        <div className="flex gap-3">
          <button type="button" onClick={onClose} className="ui-btn ui-btn-secondary flex-1 justify-center">
            Close
          </button>
          <Link to={ctaHref} className="ui-btn ui-btn-primary flex-1 justify-center flex items-center gap-2">
            <FiArrowRight /> {ctaLabel}
          </Link>
        </div>
      </div>
    </div>
  );
}
