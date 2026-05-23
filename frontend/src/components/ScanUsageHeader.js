import React from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from 'react-query';
import { usageService } from '../services/api';

const formatInfinity = (limit) => (limit === -1 ? '∞' : String(limit ?? '—'));

const toNumber = (value) => (typeof value === 'number' && Number.isFinite(value) ? value : 0);

export default function ScanUsageHeader({ className = '' }) {
  const { data } = useQuery(['usage-current'], () => usageService.getCurrent().then((r) => r.data), {
    retry: 0,
  });

  const dailyLimitRaw = data?.daily_scan_limit;
  const monthlyLimitRaw = data?.monthly_scan_limit;

  const usedToday = toNumber(data?.scans_used_today);
  const usedMonth = toNumber(data?.scans_used_this_month);

  const dailyRemaining = dailyLimitRaw === -1 ? '∞' : Math.max(0, toNumber(dailyLimitRaw) - usedToday);
  const monthlyRemaining = monthlyLimitRaw === -1 ? '∞' : Math.max(0, toNumber(monthlyLimitRaw) - usedMonth);

  const dailyLimit = formatInfinity(dailyLimitRaw);
  const monthlyLimit = formatInfinity(monthlyLimitRaw);

  return (
    <div
      className={`p-3 lg:p-4 rounded-lg border bg-gray-50 dark:bg-gray-900/40 border-gray-200 dark:border-gray-700 ${className}`.trim()}
    >
      <div className="flex items-center justify-between gap-3 mb-3">
        <div className="text-sm font-semibold text-gray-900 dark:text-white">Usage</div>
        <Link to="/support" className="ui-btn ui-btn-ghost text-xs px-2 py-1">
          Support
        </Link>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 lg:gap-4">
        <div>
          <span className="text-xs lg:text-sm text-gray-600 dark:text-gray-300">Daily Scans:</span>
          <div className="flex items-baseline gap-2">
            <span className="text-xl lg:text-2xl font-bold text-primary">{dailyRemaining}</span>
            <span className="text-xs lg:text-sm text-gray-500 dark:text-gray-400">/ {dailyLimit}</span>
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">Used today: {usedToday}</div>
        </div>

        <div>
          <span className="text-xs lg:text-sm text-gray-600 dark:text-gray-300">Monthly:</span>
          <div className="flex items-baseline gap-2">
            <span className="text-xl lg:text-2xl font-bold text-primary">{monthlyRemaining}</span>
            <span className="text-xs lg:text-sm text-gray-500 dark:text-gray-400">/ {monthlyLimit}</span>
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">Used this month: {usedMonth}</div>
        </div>

        <div>
          <span className="text-xs lg:text-sm text-gray-600 dark:text-gray-300">Concurrent:</span>
          <div className="flex items-baseline gap-2">
            <span className="text-xl lg:text-2xl font-bold text-primary">{data?.concurrent_scans ?? '—'}</span>
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">Max parallel scans</div>
        </div>
      </div>
    </div>
  );
}