import React from 'react';
import { Link } from 'react-router-dom';
import { FiAlertCircle } from 'react-icons/fi';

const DEFAULT_TEXT =
  'I confirm I have explicit authorization to scan this target and understand I am responsible for complying with all applicable laws and program rules.';

const ScanConsentGate = ({
  id = 'scan-consent',
  checked,
  onChange,
  disabled = false,
  title = 'Legal warning',
  text = DEFAULT_TEXT,
  showLinks = true,
}) => {
  return (
    <div className="ui-card p-4 bg-yellow-50 dark:bg-yellow-900/10 border border-yellow-200 dark:border-yellow-800/40">
      <div className="flex items-start gap-3">
        <FiAlertCircle className="text-yellow-700 dark:text-yellow-200 mt-0.5 flex-shrink-0" size={18} />
        <div className="flex-1">
          <div className="font-semibold text-yellow-900 dark:text-yellow-100 text-sm">{title}</div>
          <div className="mt-2 flex items-start gap-2">
            <input
              id={id}
              type="checkbox"
              checked={!!checked}
              onChange={(e) => onChange?.(e.target.checked)}
              disabled={disabled}
              className="mt-1 w-4 h-4 text-primary border-gray-300 rounded focus:ring-primary"
            />
            <label htmlFor={id} className="text-sm text-yellow-900 dark:text-yellow-100">
              {text}
              {showLinks && (
                <span className="block mt-2 text-xs text-yellow-800/90 dark:text-yellow-200/90">
                  Links: <Link className="underline hover:no-underline" to="/terms">Terms</Link>,{' '}
                  <Link className="underline hover:no-underline" to="/privacy">Privacy</Link>,{' '}
                  <Link className="underline hover:no-underline" to="/disclaimer">Disclaimer</Link>,{' '}
                  <Link className="underline hover:no-underline" to="/aup">AUP</Link>
                </span>
              )}
            </label>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanConsentGate;
