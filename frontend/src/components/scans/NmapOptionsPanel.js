import React from 'react';
import { FiTerminal } from 'react-icons/fi';

const PRESETS = [
  {
    value: 'quick',
    label: 'Quick',
    description: 'Top 100 ports, no service detection (-T4 --top-ports 100)',
  },
  {
    value: 'service',
    label: 'Service Detection',
    description: 'Top 1000 ports + version detection (-sV -T4 --top-ports 1000)',
    recommended: true,
  },
  {
    value: 'scripts',
    label: 'Default Scripts',
    description: 'Service detection + default NSE scripts (-sV -sC -T4 --top-ports 1000)',
  },
  {
    value: 'vuln',
    label: 'Vulnerability Scan',
    description: 'Service detection + vuln scripts (-sV --script=vuln -T4 --top-ports 1000)',
  },
  {
    value: 'full',
    label: 'Full Port Scan',
    description: 'All 65535 ports + service detection (-sV -sC -T4 -p-) — slow!',
  },
  {
    value: 'custom',
    label: 'Custom',
    description: 'Use only the flags you enter below',
  },
];

export default function NmapOptionsPanel({ value = {}, onChange, disabled = false }) {
  const preset = value.nmap_preset || 'service';
  const custom = value.nmap_custom || '';

  const patch = (next) => {
    if (typeof onChange === 'function') onChange({ ...value, ...next });
  };

  return (
    <div className="rounded-lg border border-indigo-200 dark:border-indigo-800 bg-indigo-50 dark:bg-indigo-900/20 p-3 mt-3">
      <div className="flex items-center gap-2 mb-3">
        <FiTerminal className="text-indigo-500 flex-shrink-0" />
        <span className="text-sm font-semibold text-gray-900 dark:text-white">Nmap Scan Options</span>
      </div>

      {/* Preset selector */}
      <div className="space-y-2 mb-3">
        {PRESETS.map((p) => (
          <label
            key={p.value}
            className={`flex items-start gap-2 p-2 rounded-lg cursor-pointer transition border ${
              preset === p.value
                ? 'border-indigo-400 bg-indigo-100 dark:bg-indigo-900/40'
                : 'border-transparent hover:bg-gray-100 dark:hover:bg-gray-800/40'
            }`}
          >
            <input
              type="radio"
              name="nmap_preset"
              value={p.value}
              checked={preset === p.value}
              onChange={() => patch({ nmap_preset: p.value })}
              disabled={disabled}
              className="mt-0.5 flex-shrink-0"
            />
            <div>
              <span className="text-sm font-medium text-gray-900 dark:text-white">
                {p.label}
                {p.recommended && (
                  <span className="ml-2 text-xs bg-indigo-600 text-white px-1.5 py-0.5 rounded">
                    recommended
                  </span>
                )}
              </span>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5 font-mono">{p.description}</p>
            </div>
          </label>
        ))}
      </div>

      {/* Extra / custom flags field */}
      <div>
        <label className="block text-xs font-medium text-gray-700 dark:text-gray-200 mb-1">
          {preset === 'custom' ? 'Custom flags (full command)' : 'Additional flags (appended after preset)'}
        </label>
        <input
          type="text"
          value={custom}
          onChange={(e) => patch({ nmap_custom: e.target.value })}
          placeholder={preset === 'custom' ? '-p 80,443,8080 -sV --script=http-title' : '--script=banner -p 22,21'}
          className="ui-input font-mono text-xs"
          disabled={disabled}
        />
        <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
          Flags like -oN, -oG, -S, --send-eth are ignored for security reasons.
        </p>
      </div>
    </div>
  );
}
