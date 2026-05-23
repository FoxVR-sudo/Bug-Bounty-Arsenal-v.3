import React from 'react';
import { useQuery } from 'react-query';
import { statsService } from '../services/api';
import { FiTrendingUp, FiAlertTriangle, FiActivity, FiTarget } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import LoadingState from '../components/states/LoadingState';
import ErrorState from '../components/states/ErrorState';
import { useTheme } from '../contexts/ThemeContext';
import {
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';

const COLORS = ['#EF4444', '#F59E0B', '#10B981', '#3B82F6', '#8B5CF6'];

const Analytics = () => {
  const { isDark } = useTheme();
  const {
    data: stats,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery('analytics', () => statsService.getOverview().then(res => res.data));

  // Mock data for charts - replace with real API data
  const vulnerabilityByType = [
    { name: 'XSS', count: stats?.vuln_by_type?.xss || 0 },
    { name: 'SQL Injection', count: stats?.vuln_by_type?.sql || 0 },
    { name: 'SSRF', count: stats?.vuln_by_type?.ssrf || 0 },
    { name: 'Auth Bypass', count: stats?.vuln_by_type?.auth || 0 },
    { name: 'Others', count: stats?.vuln_by_type?.others || 0 },
  ];

  const scanTrend = Array.isArray(stats?.scan_trend)
    ? stats.scan_trend
    : [
        { date: 'Mon', scans: 0 },
        { date: 'Tue', scans: 0 },
        { date: 'Wed', scans: 0 },
        { date: 'Thu', scans: 0 },
        { date: 'Fri', scans: 0 },
        { date: 'Sat', scans: 0 },
        { date: 'Sun', scans: 0 },
      ];

  const severityData = [
    { name: 'Critical', value: stats?.severity?.critical || 0 },
    { name: 'High', value: stats?.severity?.high || 0 },
    { name: 'Medium', value: stats?.severity?.medium || 0 },
    { name: 'Low', value: stats?.severity?.low || 0 },
  ];

  return (
    <DashboardLayout>
      <div className="ui-page">
        <div className="mb-8">
          <h1 className="ui-title">Analytics</h1>
          <p className="ui-subtitle mt-2">Detailed insights into your security scans</p>
        </div>

        {isLoading && (
          <LoadingState title="Loading analytics" subtitle="Crunching the numbers…" minHeightClassName="min-h-[30vh]" />
        )}

        {!isLoading && isError && (
          <ErrorState
            title="Couldn’t load analytics"
            message={error?.message || 'Please try again.'}
            action={
              <button onClick={() => refetch()} className="ui-btn ui-btn-primary">
                Retry
              </button>
            }
            minHeightClassName="min-h-[30vh]"
          />
        )}

        {!isLoading && !isError && (
          <>

          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <StatCard
              title="Total Vulnerabilities"
              value={stats?.total_vulnerabilities || 0}
              icon={<FiAlertTriangle />}
              color="red"
              trend="+12%"
            />
            <StatCard
              title="Critical Issues"
              value={stats?.severity?.critical || 0}
              icon={<FiTarget />}
              color="orange"
              trend="+5%"
            />
            <StatCard
              title="Scans This Week"
              value={stats?.scans_this_week || 0}
              icon={<FiActivity />}
              color="blue"
              trend="+18%"
            />
            <StatCard
              title="Avg Scan Time"
              value={stats?.avg_scan_time || '2.5m'}
              icon={<FiTrendingUp />}
              color="green"
              trend="-8%"
            />
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
            {/* Vulnerability by Type */}
            <div className="ui-card p-6">
              <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">Vulnerabilities by Type</h2>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={vulnerabilityByType}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" tick={{ fill: isDark ? '#D1D5DB' : '#6B7280' }} />
                  <YAxis tick={{ fill: isDark ? '#D1D5DB' : '#6B7280' }} />
                  <Tooltip />
                  <Bar dataKey="count" fill="#6366F1" />
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Severity Distribution */}
            <div className="ui-card p-6">
              <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">Severity Distribution</h2>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Scan Trend */}
          <div className="ui-card p-6">
            <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">Weekly Scan Activity</h2>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={scanTrend}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" tick={{ fill: isDark ? '#D1D5DB' : '#6B7280' }} />
                <YAxis tick={{ fill: isDark ? '#D1D5DB' : '#6B7280' }} />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="scans" stroke="#6366F1" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          </>
        )}
      </div>
    </DashboardLayout>
  );
};

const StatCard = ({ title, value, icon, color, trend }) => {
  const colors = {
    red: 'bg-red-500/10 text-red-500',
    orange: 'bg-orange-500/10 text-orange-500',
    blue: 'bg-blue-500/10 text-blue-500',
    green: 'bg-green-500/10 text-green-500',
  };

  return (
    <div className="ui-card p-6">
      <div className="flex items-center justify-between">
        <div className={`p-3 rounded-lg ${colors[color]}`}>
          {React.cloneElement(icon, { size: 24 })}
        </div>
        {trend && (
          <span className={`text-sm font-semibold ${trend.startsWith('+') ? 'text-green-600' : 'text-red-600'}`}>
            {trend}
          </span>
        )}
      </div>
      <h3 className="text-gray-500 dark:text-gray-300 text-sm mt-4">{title}</h3>
      <p className="text-3xl font-bold mt-2 text-gray-900 dark:text-white">{value}</p>
    </div>
  );
};

export default Analytics;
