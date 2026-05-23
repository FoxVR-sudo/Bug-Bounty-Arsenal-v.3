import React, { useState } from 'react';
import { FiChevronDown, FiChevronUp } from 'react-icons/fi';

const clampNumber = (value, fallback) => {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
};

const DEFAULTS = {
  timeout: 15,
  concurrency: 10,
  per_host_rate: 1.0,
  scan_mode: 'normal',
  run_all_selected_detectors: false,
};

export default function ScanOptionsPanel({
  value,
  onChange,
  disabled = false,
  defaultOpen = false,
  title = 'Scan options',
  showTimeout = true,
  showConcurrency = false,
  showPerHostRate = false,
  showScanMode = true,
  showRunAllSelectedDetectors = true,
}) {
  const [open, setOpen] = useState(defaultOpen);
  const options = { ...DEFAULTS, ...(value || {}) };

  const patch = (next) => {
    if (typeof onChange === 'function') onChange({ ...options, ...next });
  };

  return (
    <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/40">
      <button
        type="button"
        className="w-full flex items-center justify-between px-3 py-2 text-left"
        onClick={() => setOpen((v) => !v)}
        disabled={disabled}
      >
        <span className="text-sm font-semibold text-gray-900 dark:text-white">{title}</span>
        {open ? (
          <FiChevronUp className="w-4 h-4 text-gray-500" />
        ) : (
          <FiChevronDown className="w-4 h-4 text-gray-500" />
        )}
      </button>

      {open && (
        <div className="px-3 pb-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {showTimeout && (
              <div>
                <label className="block text-xs font-medium mb-1 text-gray-700 dark:text-gray-200">
                  Timeout (seconds)
                </label>
                <input
                  type="number"
                  min="5"
                  max="600"
                  value={options.timeout}
                  onChange={(e) => patch({ timeout: clampNumber(e.target.value, DEFAULTS.timeout) })}
                  className="ui-input"
                  disabled={disabled}
                />
              </div>
            )}

            {showConcurrency && (
              <div>
                <label className="block text-xs font-medium mb-1 text-gray-700 dark:text-gray-200">
                  Concurrency
                </label>
                <input
                  type="number"
                  min="1"
                  max="200"
                  value={options.concurrency}
                  onChange={(e) => patch({ concurrency: clampNumber(e.target.value, DEFAULTS.concurrency) })}
                  className="ui-input"
                  disabled={disabled}
                />
              </div>
            )}

            {showPerHostRate && (
              <div>
                <label className="block text-xs font-medium mb-1 text-gray-700 dark:text-gray-200">
                  Per-host rate (req/sec)
                </label>
                <input
                  type="number"
                  min="0.1"
                  max="50"
                  step="0.1"
                  value={options.per_host_rate}
                  onChange={(e) => patch({ per_host_rate: clampNumber(e.target.value, DEFAULTS.per_host_rate) })}
                  className="ui-input"
                  disabled={disabled}
                />
              </div>
            )}

            {showScanMode && (
              <div>
                <label className="block text-xs font-medium mb-1 text-gray-700 dark:text-gray-200">
                  Scan mode
                </label>
                <select
                  value={options.scan_mode}
                  onChange={(e) => patch({ scan_mode: e.target.value })}
                  className="ui-select"
                  disabled={disabled}
                >
                  <option value="normal">Normal</option>
                  <option value="safe">Safe</option>
                </select>
              </div>
            )}
          </div>

          {showRunAllSelectedDetectors && (
            <label className="mt-3 flex items-start gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={!!options.run_all_selected_detectors}
                onChange={(e) => patch({ run_all_selected_detectors: e.target.checked })}
                className="mt-1"
                disabled={disabled}
              />
              <span className="text-xs text-gray-700 dark:text-gray-200">
                Run all selected detectors (do not skip due to scan mode). Plan/tier restrictions still apply.
              </span>
            </label>
          )}

          <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
            Tip: start with default values unless you know the target can handle higher load.
          </p>
        </div>
      )}
    </div>
  );
}
