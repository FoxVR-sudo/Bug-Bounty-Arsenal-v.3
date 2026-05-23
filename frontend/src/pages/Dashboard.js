import React, { useMemo, useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from 'react-query';
import { scanService, statsService, subscriptionService, userService } from '../services/api';
import { FiPlus, FiDownload, FiEye, FiActivity, FiCheckCircle, FiClock, FiAlertTriangle, FiSmartphone } from 'react-icons/fi';
import { format } from 'date-fns';
import DashboardLayout from '../components/DashboardLayout';
import CategoryScanForm from '../components/CategoryScanForm';
import { useToast } from '../contexts/ToastContext';
import LoadingState from '../components/states/LoadingState';
import ErrorState from '../components/states/ErrorState';
import EmptyState from '../components/states/EmptyState';
import useModalA11y from '../hooks/useModalA11y';
import DonationModal, { isDonationSnoozed } from '../components/DonationModal';

const Dashboard = () => {
  const toast = useToast();
  const [showNewScan, setShowNewScan] = useState(false);
  const [showDonation, setShowDonation] = useState(false);
  const [subscription, setSubscription] = useState(null);
  const [userInfo, setUserInfo] = useState(null);
  const [scanSearch, setScanSearch] = useState('');
  const [debouncedScanSearch, setDebouncedScanSearch] = useState('');
  const [scanStatus, setScanStatus] = useState('');
  const [scanType, setScanType] = useState('');
  const [scanPage, setScanPage] = useState(1);

  const newScanDialogRef = useModalA11y(showNewScan, {
    onClose: () => setShowNewScan(false),
  });
  const newScanTitleIdRef = useRef(`new-scan-title-${Math.random().toString(36).slice(2)}`);
  const newScanDescIdRef = useRef(`new-scan-desc-${Math.random().toString(36).slice(2)}`);

  useEffect(() => {
    const handle = setTimeout(() => setDebouncedScanSearch(scanSearch.trim()), 300);
    return () => clearTimeout(handle);
  }, [scanSearch]);

  useEffect(() => {
    // Reset pagination when filters change
    setScanPage(1);
  }, [debouncedScanSearch, scanStatus, scanType]);

  // Fetch scans (paginated + searchable to avoid rendering huge lists)
  const {
    data: scansData,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery(
    ['scans', scanPage, debouncedScanSearch, scanStatus, scanType],
    () => {
      const params = {
        page: scanPage,
        page_size: 20,
      };
      if (debouncedScanSearch) params.search = debouncedScanSearch;
      if (scanStatus) params.status = scanStatus;
      if (scanType) params.scan_type = scanType;
      return scanService.getAll(params).then((res) => res.data);
    },
    { keepPreviousData: true }
  );

  const scans = useMemo(() => {
    if (!scansData) return [];
    if (Array.isArray(scansData)) return scansData;
    if (Array.isArray(scansData.results)) return scansData.results;
    return [];
  }, [scansData]);

  const isPrivilegedUser = Boolean(
    userInfo?.is_superuser || userInfo?.is_admin || userInfo?.is_staff
  );

  const formatScanTypeLabel = (scan) => {
    // Prefer backend-provided friendly name
    if (scan?.display_type) return scan.display_type;

    // New category-based name
    if (scan?.scan_category) {
      const raw = String(scan.scan_category);
      return raw
        .replace(/_/g, ' ')
        .replace(/\b\w/g, (c) => c.toUpperCase());
    }

    // Legacy scan_type
    const legacy = scan?.scan_type;
    const legacyMap = {
      reconnaissance: 'Reconnaissance',
      web_security: 'Web Security',
      vulnerability: 'Vulnerability Scan',
      api_security: 'API Security',
      mobile: 'Mobile Security',
    };
    return legacyMap[legacy] || legacy || 'General';
  };

  // Fetch stats
  const { data: stats } = useQuery('stats', () =>
    statsService.getOverview().then((res) => res.data)
  );

  // Fetch subscription info
  useEffect(() => {
    fetchSubscription();
    fetchUserInfo();

    // Re-fetch userInfo when geo location is saved (after ipapi.co lookup)
    const handleGeoSaved = () => fetchUserInfo();
    window.addEventListener('geoSaved', handleGeoSaved);
    const pollStateRef = { failCount: 0, backoffUntil: 0, warned: false };
    
    // Listen for window focus to refresh data when returning to tab
    const handleFocus = () => {
      const subscriptionUpdated = localStorage.getItem('subscription_updated');
      if (subscriptionUpdated === 'true') {
        localStorage.removeItem('subscription_updated');
        console.log('Window focused - refreshing subscription data...');
        fetchSubscription();
        fetchUserInfo();
        refetch(); // Refetch scans
      }
    };
    
    // Listen for storage changes from other tabs/windows
    const handleStorageChange = (e) => {
      if (e.key === 'subscription_updated' && e.newValue === 'true') {
        localStorage.removeItem('subscription_updated');
        console.log('Storage event - refreshing subscription data...');
        fetchSubscription();
        fetchUserInfo();
        refetch();
      }
    };
    
    // Auto-refresh subscription data every 30 seconds to update scan counters
    const refreshInterval = setInterval(() => {
      // Avoid noisy polling when tab is not visible
      if (document.visibilityState !== 'visible') return;

      const now = Date.now();
      if (now < pollStateRef.backoffUntil) return;

      fetchSubscription({ _pollState: pollStateRef, isPoll: true });
    }, 60000); // 60 seconds
    
    window.addEventListener('focus', handleFocus);
    window.addEventListener('storage', handleStorageChange);
    
    // Cleanup
    return () => {
      window.removeEventListener('focus', handleFocus);
      window.removeEventListener('storage', handleStorageChange);
      window.removeEventListener('geoSaved', handleGeoSaved);
      clearInterval(refreshInterval);
    };
  }, [refetch]);

  const fetchUserInfo = async () => {
    try {
      const response = await userService.getMe();
      setUserInfo(response.data);
    } catch (err) {
      console.error('Failed to fetch user info:', err);
    }
  };

  const fetchSubscription = async (opts = {}) => {
    const { _pollState, isPoll } = opts || {};
    try {
      const response = await subscriptionService.getCurrent();
      setSubscription(response.data);

      if (_pollState) {
        _pollState.failCount = 0;
        _pollState.backoffUntil = 0;
        _pollState.warned = false;
      }
    } catch (err) {
      const status = err?.response?.status;

      if (_pollState && typeof status === 'number' && status >= 500) {
        _pollState.failCount += 1;
        // After a few consecutive 5xx errors, pause polling to avoid spamming the server/logs.
        if (_pollState.failCount >= 3) {
          _pollState.backoffUntil = Date.now() + 5 * 60 * 1000;
          if (!_pollState.warned) {
            console.warn('Subscription endpoint is failing (5xx); pausing refresh for 5 minutes.');
            _pollState.warned = true;
          }
        }
      }

      // Only log full error details for non-poll calls to reduce console noise.
      if (!isPoll) {
        console.error('Failed to fetch subscription:', err);
      }
    }
  };

  const handleScanCreated = () => {
    setShowNewScan(false);
    refetch();
    if (!isDonationSnoozed()) {
      setShowDonation(true);
    }
  };

  return (
    <DashboardLayout>
      <div className="ui-page">
        {/* User Info Card - Tree Format */}
        {userInfo && (
          <div className="ui-card p-6 mb-8 shadow-xl backdrop-blur-lg bg-white/90 hover:bg-white dark:bg-gray-900/40 dark:hover:bg-gray-900/50 border border-gray-200/50 dark:border-gray-700/50 hover:shadow-2xl transition-all duration-300">
            <div className="flex items-center justify-between">
              <div className="font-mono text-sm space-y-1">
                <div className="flex items-center">
                  <span className="text-gray-600 dark:text-gray-400 w-32">├─ username:</span>
                  <span className="font-semibold text-gray-900 dark:text-white">
                    {(userInfo.full_name && userInfo.full_name.trim()) ? userInfo.full_name : userInfo.email.split('@')[0].toUpperCase()}
                  </span>
                </div>
                <div className="flex items-center">
                  <span className="text-gray-600 dark:text-gray-400 w-32">├─ email:</span>
                  <span className="font-semibold text-gray-900 dark:text-white">{userInfo.email}</span>
                </div>
                {userInfo.phone && userInfo.phone.trim() && (
                  <div className="flex items-center">
                    <span className="text-gray-600 dark:text-gray-400 w-32">├─ phone:</span>
                    <span className="font-semibold text-gray-900 dark:text-white">{userInfo.phone}</span>
                  </div>
                )}
                {userInfo.company_name && userInfo.company_name.trim() && (
                  <div className="flex items-center">
                    <span className="text-gray-600 dark:text-gray-400 w-32">├─ company:</span>
                    <span className="font-semibold text-gray-900 dark:text-white">{userInfo.company_name}</span>
                  </div>
                )}
                {(userInfo.address || userInfo.company_country) && (
                  <div className="flex items-center">
                    <span className="text-gray-600 dark:text-gray-400 w-32">├─ location:</span>
                    <span className="font-semibold text-gray-900 dark:text-white">
                      {[userInfo.address, userInfo.company_country].filter(Boolean).join(', ')}
                    </span>
                  </div>
                )}
                <div className="flex items-center">
                  <span className="text-gray-600 dark:text-gray-400 w-32">└─ IP:</span>
                  <span className="font-semibold text-gray-900 dark:text-white">{userInfo.client_ip || 'N/A'}</span>
                </div>
              </div>
              
            </div>
          </div>
        )}

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <StatCard
            title="Total Scans"
            value={stats?.total_scans || 0}
            icon={<FiActivity />}
            color="blue"
          />
          <StatCard
            title="Active"
            value={stats?.running || 0}
            icon={<FiClock />}
            color="yellow"
          />
          <StatCard
            title="Completed"
            value={stats?.completed || 0}
            icon={<FiCheckCircle />}
            color="green"
          />
          <StatCard
            title="Vulnerabilities"
            value={stats?.total_vulnerabilities || 0}
            icon={<FiAlertTriangle />}
            color="red"
          />
        </div>

        {/* Recent Scans */}
        <div className="flex justify-between items-start mb-6 gap-4">
          <div>
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
              {isPrivilegedUser ? 'All User Scans' : 'Recent Scans'}
            </h2>
            {isPrivilegedUser && (
              <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">
                Admin view: showing scans created by all registered users.
              </p>
            )}
          </div>
          {subscription && subscription.daily_scan_limit !== null && subscription.scans_used_today >= subscription.daily_scan_limit ? (
            <div className="flex items-center gap-3">
              <span className="text-sm font-medium text-gray-600 dark:text-gray-400">
                Daily limit reached
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowNewScan(true)}
                className="ui-btn ui-btn-primary px-6 py-3 gap-2"
              >
                <FiPlus /> New Scan
              </button>
              <Link
                to="/scan/mobile"
                className="ui-btn ui-btn-secondary px-4 py-3 gap-2 flex items-center"
                title="Scan Android APK or iOS IPA"
              >
                <FiSmartphone /> Mobile Scan
              </Link>
            </div>
          )}
        </div>

        <div className="ui-card p-4 mb-6 flex flex-col md:flex-row md:items-center gap-3">
          <div className="flex-1">
            <label className="block text-sm font-semibold text-gray-700 dark:text-gray-200 mb-1">
              Search scans
            </label>
            <input
              value={scanSearch}
              onChange={(e) => setScanSearch(e.target.value)}
              placeholder="Search by target (domain, URL, IP)…"
              className="ui-input w-full"
            />
          </div>
          <div className="w-full md:w-56">
            <label className="block text-sm font-semibold text-gray-700 dark:text-gray-200 mb-1">
              Status
            </label>
            <select
              value={scanStatus}
              onChange={(e) => setScanStatus(e.target.value)}
              className="ui-input w-full"
            >
              <option value="">All</option>
              <option value="pending">Pending</option>
              <option value="running">Running</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="stopped">Stopped</option>
            </select>
          </div>
          <div className="w-full md:w-56">
            <label className="block text-sm font-semibold text-gray-700 dark:text-gray-200 mb-1">
              Scan type
            </label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="ui-input w-full"
            >
              <option value="">All</option>
              <option value="reconnaissance">Reconnaissance</option>
              <option value="web_security">Web Security</option>
              <option value="vulnerability">Vulnerability Scan</option>
              <option value="api_security">API Security</option>
              <option value="mobile">Mobile Security</option>
            </select>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-sm text-gray-600 dark:text-gray-300 whitespace-nowrap">
              Showing {scans.length} scan{scans.length === 1 ? '' : 's'}
              {typeof scansData?.count === 'number' ? ` of ${scansData.count}` : ''}
              {isPrivilegedUser ? ' across all users' : ''}
            </div>
            {(scanSearch.trim() || scanStatus || scanType) && (
              <button
                onClick={() => {
                  setScanSearch('');
                  setScanStatus('');
                  setScanType('');
                }}
                className="ui-btn ui-btn-secondary"
              >
                Clear
              </button>
            )}
            <Link to="/results" className="ui-btn ui-btn-secondary">
              View all
            </Link>
          </div>
        </div>

        {/* V3.0: New Scan Modal with Category Selection */}
        {showNewScan && (
          <div
            className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
            onMouseDown={(e) => {
              if (e.target === e.currentTarget) setShowNewScan(false);
            }}
          >
              <div
                ref={newScanDialogRef}
                role="dialog"
                aria-modal="true"
                aria-labelledby={newScanTitleIdRef.current}
                aria-describedby={newScanDescIdRef.current}
                tabIndex={-1}
                className="ui-card rounded-2xl shadow-2xl border max-w-4xl w-full max-h-[90vh] overflow-y-auto bg-white/95 dark:bg-gray-900/80 backdrop-blur-xl border-gray-200/50 dark:border-gray-700/50"
              >
                <div className="sticky top-0 border-b p-6 flex items-center justify-between bg-white/95 dark:bg-gray-900/90 border-gray-200/50 dark:border-gray-700/50">
                  <h3 id={newScanTitleIdRef.current} className="text-2xl font-bold text-gray-900 dark:text-white">Create New Scan</h3>
                  <button
                    onClick={() => setShowNewScan(false)}
                    type="button"
                    aria-label="Close dialog"
                    className="text-2xl font-bold transition text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
                  >
                    ×
                  </button>
                </div>
                <p id={newScanDescIdRef.current} className="sr-only">
                  Select a scan category and configure targets.
                </p>
                <div className="p-6">
                  <CategoryScanForm onScanCreated={handleScanCreated} />
                </div>
              </div>
          </div>
        )}

        {/* Donation Modal */}
        {showDonation && (
          <DonationModal onClose={() => setShowDonation(false)} />
        )}

        {/* Scans Table */}
        {isLoading && (
          <LoadingState
            title="Loading scans"
            subtitle={
              isPrivilegedUser
                ? 'Fetching scans across all registered users…'
                : 'Fetching your recent scans…'
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
                : 'Create your first scan to see results here.'
            }
            action={
              <button onClick={() => setShowNewScan(true)} className="ui-btn ui-btn-primary">
                Create Your First Scan
              </button>
            }
          />
        )}

        {!isLoading && !isError && scans && scans.length > 0 && (
          <div className="ui-card shadow-xl overflow-hidden transition-all duration-300 backdrop-blur-lg bg-white/90 dark:bg-gray-900/40 border border-gray-200/50 dark:border-gray-700/50">
            <div className="ui-table-wrap">
              <table className="min-w-[900px] w-full">
                <thead className="bg-gray-100/80 border-b border-gray-200 dark:bg-gray-950/30 dark:border-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-white">Target</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-white">Type</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-white">Status</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-white">Findings</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-white">Created</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-white">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {scans.map((scan) => (
                    <tr key={scan.id} className="transition-all duration-200 hover:bg-gray-50 dark:hover:bg-gray-900/30">
                      <td className="px-6 py-4">
                        <div className="text-sm font-medium text-gray-900 dark:text-white">{scan.target}</div>
                        {isPrivilegedUser && (
                          <div className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                            Owner: {scan.user_email || 'Unknown user'}
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-sm text-gray-600 dark:text-gray-300">{formatScanTypeLabel(scan)}</span>
                      </td>
                      <td className="px-6 py-4">
                        <StatusBadge status={scan.status} />
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          {scan.vulnerabilities_found > 0 ? (
                            <>
                              <FiAlertTriangle className="text-red-400" />
                              <span className="text-sm font-semibold text-red-400">{scan.vulnerabilities_found}</span>
                            </>
                          ) : (
                            <span className="text-sm text-gray-500 dark:text-gray-400">0</span>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-300">
                        {format(new Date(scan.created_at), 'MMM dd, yyyy HH:mm')}
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex gap-2">
                          <Link
                            to={`/scan/details/${scan.id}`}
                            className="p-2 rounded transition text-blue-600 hover:bg-blue-50 dark:text-blue-400 dark:hover:bg-blue-900/30"
                            title="View Details"
                          >
                            <FiEye />
                          </Link>
                          {scan.status === 'completed' && (
                            <button
                              onClick={async () => {
                                try {
                                  const res = await scanService.downloadJSON(scan.id);
                                  const url = window.URL.createObjectURL(new Blob([res.data]));
                                  const link = document.createElement('a');
                                  link.href = url;
                                  link.setAttribute('download', `scan-${scan.id}-report.json`);
                                  document.body.appendChild(link);
                                  link.click();
                                  link.remove();
                                } catch (error) {
                                  const status = error?.response?.status;
                                  if (status === 413) {
                                    toast.error('Export too large. Try exporting JSON from Scan Details or narrow the scan.');
                                  } else if (status === 503) {
                                    toast.error('Exports temporarily unavailable. Please try again shortly.');
                                  } else if (status === 429) {
                                    toast.error('Too many export requests. Please wait and try again.');
                                  } else {
                                    toast.error('Failed to download report');
                                  }
                                }
                              }}
                              className="p-2 rounded transition text-green-600 hover:bg-green-50 dark:text-green-400 dark:hover:bg-green-900/20"
                              title="Download Report"
                            >
                              <FiDownload />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div className="flex items-center justify-between px-6 py-4 border-t border-gray-200 dark:border-gray-700">
                <div className="text-sm text-gray-600 dark:text-gray-300">
                  Page {scanPage}
                  {typeof scansData?.count === 'number' ? ` of ${Math.max(1, Math.ceil(scansData.count / 20))}` : ''}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setScanPage((p) => Math.max(1, p - 1))}
                    disabled={scanPage <= 1 || isLoading}
                    className="ui-btn ui-btn-secondary"
                  >
                    Prev
                  </button>
                  <button
                    onClick={() => setScanPage((p) => p + 1)}
                    disabled={!scansData?.next || isLoading}
                    className="ui-btn ui-btn-secondary"
                  >
                    Next
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

const StatCard = ({ title, value, icon, color }) => {
  const colors = {
    blue: 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-200',
    yellow: 'bg-yellow-100 text-yellow-600 dark:bg-yellow-900/30 dark:text-yellow-200',
    green: 'bg-green-100 text-green-600 dark:bg-green-900/20 dark:text-green-200',
    red: 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-200',
  };

  return (
    <div className="ui-card p-6 shadow-xl backdrop-blur-lg bg-white/90 hover:bg-white dark:bg-gray-900/40 dark:hover:bg-gray-900/50 border border-gray-200/50 dark:border-gray-700/50 hover:shadow-2xl transition-all duration-300">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm mb-1 text-gray-600 dark:text-gray-400">{title}</p>
          <p className="text-3xl font-bold text-gray-900 dark:text-white">{value}</p>
        </div>
        <div className={`p-4 rounded-lg ${colors[color]}`}>{icon}</div>
      </div>
    </div>
  );
};

const StatusBadge = ({ status }) => {
  const styles = {
    pending: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-200',
    running: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-200',
    completed: 'bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-200',
    failed: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-200',
  };
  const s = status || 'pending';
  return (
    <span className={`px-3 py-1 rounded-full text-xs font-semibold ${styles[s] || styles.pending}`}>
      {s.charAt(0).toUpperCase() + s.slice(1)}
    </span>
  );
};

export default Dashboard;