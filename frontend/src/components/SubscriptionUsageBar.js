import React from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from 'react-query';
import { subscriptionService } from '../services/api';

function formatLimit(limit) {
  if (limit === -1) return 'Unlimited';
  if (typeof limit === 'number') return String(limit);
  return '—';
}

function formatUsed(value) {
  if (typeof value === 'number') return String(value);
  return '0';
}

export default function SubscriptionUsageBar({ className = '' }) {
  const { data } = useQuery(['subscription-current'], () => subscriptionService.getCurrent().then((r) => r.data), {
    retry: 0,
  });

  const dailyLimit = data?.daily_scan_limit;
  const monthlyLimit = data?.monthly_scan_limit;

  return (
    <div className={`ui-card p-4 border border-gray-200 dark:border-gray-700 ${className}`.trim()}>
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm font-semibold text-gray-900 dark:text-white">Usage</div>
        <Link to="/subscription" className="ui-btn ui-btn-ghost text-xs px-2 py-1">
          Manage
        </Link>
      </div>
      <div className="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="rounded-lg border border-blue-200 dark:border-blue-800/40 bg-blue-50 dark:bg-blue-900/10 p-3">
          <div className="text-xs font-semibold text-blue-800 dark:text-blue-200">Scans Today</div>
          <div className="mt-1 text-sm font-bold text-blue-900 dark:text-blue-100">
            {formatUsed(data?.scans_used_today)} / {formatLimit(dailyLimit)}
          </div>
        </div>
        <div className="rounded-lg border border-purple-200 dark:border-purple-800/40 bg-purple-50 dark:bg-purple-900/10 p-3">
          <div className="text-xs font-semibold text-purple-800 dark:text-purple-200">Scans This Month</div>
          <div className="mt-1 text-sm font-bold text-purple-900 dark:text-purple-100">
            {formatUsed(data?.scans_used_this_month)} / {formatLimit(monthlyLimit)}
          </div>
        </div>
        <div className="rounded-lg border border-green-200 dark:border-green-800/40 bg-green-50 dark:bg-green-900/10 p-3">
          <div className="text-xs font-semibold text-green-800 dark:text-green-200">Concurrent Scans</div>
          <div className="mt-1 text-sm font-bold text-green-900 dark:text-green-100">{data?.concurrent_scans ?? '—'}</div>
        </div>
      </div>
    </div>
  );
}
