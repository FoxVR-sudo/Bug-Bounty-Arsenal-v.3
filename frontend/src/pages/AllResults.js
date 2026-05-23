import React, { useMemo, useState } from 'react';
import { useQuery } from 'react-query';
import { Link } from 'react-router-dom';
import { scanService, userService } from '../services/api';
import { FiEye, FiDownload, FiClock, FiCheckCircle, FiAlertCircle } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import LoadingState from '../components/states/LoadingState';
import ErrorState from '../components/states/ErrorState';
import EmptyState from '../components/states/EmptyState';
import PaginationControls from '../components/PaginationControls';
import { format } from 'date-fns';

const AllResults = () => {
  const [page, setPage] = useState(1);

  const {
    data: scansData,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery(
    ['all-scans', page],
    () => scanService.getAll({ page, page_size: 20 }).then((res) => res.data),
    {
      // Auto-refresh while any scan is pending/running.
      refetchInterval: (data) => {
        const items = Array.isArray(data?.results) ? data.results : [];
        const hasActive = items.some((s) => s?.status === 'pending' || s?.status === 'running');
        return hasActive ? 4000 : false;
      },
      keepPreviousData: true,
    }
  );

  const { data: me } = useQuery('me', () => userService.getMe().then((res) => res.data));

  const scans = useMemo(() => {
    if (!scansData) return [];
    if (Array.isArray(scansData.results)) return scansData.results;
    if (Array.isArray(scansData)) return scansData;
    return [];
  }, [scansData]);

  const isPrivilegedUser = Boolean(
    me?.is_superuser || me?.is_admin || me?.is_staff
  );

  const totalPages = typeof scansData?.count === 'number' ? Math.max(1, Math.ceil(scansData.count / 20)) : undefined;

  const getStatusBadge = (status) => {
    const badges = {
      completed: 'bg-green-100 text-green-800',
      running: 'bg-blue-100 text-blue-800',
      failed: 'bg-red-100 text-red-800',
      pending: 'bg-yellow-100 text-yellow-800'
    };
    return badges[status] || badges.pending;
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <FiCheckCircle className="text-green-500" />;
      case 'running':
        return <FiClock className="text-blue-500" />;
      case 'failed':
        return <FiAlertCircle className="text-red-500" />;
      default:
        return <FiClock className="text-gray-500" />;
    }
  };

  return (
    <DashboardLayout>
      <div className="ui-page">
        <div className="mb-8">
          <h1 className="ui-title">
            {isPrivilegedUser ? 'All User Scan Results' : 'All Scan Results'}
          </h1>
          <p className="ui-subtitle mt-2">
            {isPrivilegedUser
              ? 'Admin view across all registered users.'
              : 'View and manage all your security scans'}
          </p>
        </div>

        {isLoading && (
          <LoadingState
            title="Loading scans"
            subtitle={
              isPrivilegedUser
                ? 'Fetching scan history across all registered users…'
                : 'Fetching your recent scan history…'
            }
          />
        )}

        {!isLoading && isError && (
          <ErrorState
            title="Couldn’t load scans"
            message={error?.message || 'Please try again.'}
            action={
              <button onClick={() => refetch()} className="ui-btn ui-btn-primary">
                Retry
              </button>
            }
          />
        )}

        {!isLoading && !isError && (!scans || scans.length === 0) && (
          <EmptyState
            title="No scans yet"
            message={
              isPrivilegedUser
                ? 'No scans have been created by any registered user yet.'
                : 'Start your first scan to see results here.'
            }
            action={
              <Link to="/dashboard" className="ui-btn ui-btn-primary">
                Start a scan
              </Link>
            }
          />
        )}

        {!isLoading && !isError && scans && scans.length > 0 && (
          <div className="ui-card overflow-hidden">
            <div className="ui-table-wrap">
              <table className="min-w-[900px] w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead className="bg-gray-50 dark:bg-gray-800/50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Target
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Scan Type
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Vulnerabilities
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Date
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-transparent divide-y divide-gray-200 dark:divide-gray-700">
                  {scans?.map((scan) => (
                    <tr key={scan.id} className="hover:bg-gray-50 dark:hover:bg-gray-900/30">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          {getStatusIcon(scan.status)}
                          <span
                            className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${getStatusBadge(scan.status)}`}
                          >
                            {scan.status}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="text-sm text-gray-900 dark:text-gray-100 max-w-xs truncate">{scan.target}</div>
                        {isPrivilegedUser && (
                          <div className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                            Owner: {scan.user_email || 'Unknown user'}
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-sm text-gray-700 dark:text-gray-200 capitalize">{scan.scan_type}</span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {(scan.vulnerabilities_found || 0) > 0 ? (
                          <span className="text-red-600 font-semibold">{scan.vulnerabilities_found}</span>
                        ) : (
                          <span className="text-green-600">0</span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                        {scan.created_at ? format(new Date(scan.created_at), 'MMM dd, yyyy HH:mm') : '—'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <div className="flex gap-2">
                          <Link
                            to={`/scan/details/${scan.id}`}
                            className="text-primary hover:text-primary-600 flex items-center gap-1"
                          >
                            <FiEye /> View
                          </Link>
                          {scan.status === 'completed' && (
                            <button
                              onClick={async () => {
                                try {
                                  const res = await scanService.downloadJSON(scan.id);
                                  const url = window.URL.createObjectURL(new Blob([res.data]));
                                  const a = document.createElement('a');
                                  a.href = url;
                                  a.download = `scan-${scan.id}-report.json`;
                                  document.body.appendChild(a);
                                  a.click();
                                  a.remove();
                                  window.URL.revokeObjectURL(url);
                                } catch (_) {
                                  // ignore
                                }
                              }}
                              className="text-green-600 hover:text-green-800 flex items-center gap-1"
                            >
                              <FiDownload /> Export
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-700">
              <PaginationControls
                page={page}
                totalPages={totalPages}
                hasPrev={page > 1 && !isLoading}
                hasNext={!!scansData?.next && !isLoading}
                onPrev={() => setPage((p) => Math.max(1, p - 1))}
                onNext={() => setPage((p) => p + 1)}
              />
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default AllResults;
