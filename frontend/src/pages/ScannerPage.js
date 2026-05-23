import React, { useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from 'react-query';
import { scanService } from '../services/api';
import { FiPlay, FiSettings, FiAlertCircle, FiCheckCircle, FiClock } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import ScanConsentGate from '../components/ScanConsentGate';
import SubscriptionUsageHeader from '../components/SubscriptionUsageHeader';
import UpgradeModal from '../components/UpgradeModal';
import { useToast } from '../contexts/ToastContext';
import LoadingState from '../components/states/LoadingState';
import ErrorState from '../components/states/ErrorState';
import EmptyState from '../components/states/EmptyState';
import FieldError from '../components/forms/FieldError';
import PaginationControls from '../components/PaginationControls';
import { isNonEmpty } from '../lib/validation';

const scannerInfo = {
  xss: {
    name: 'XSS Scanner',
    description: 'Cross-Site Scripting (XSS) vulnerability detection. Tests for reflected, stored, and DOM-based XSS vulnerabilities.',
    whatItScans: [
      'Input fields and forms',
      'URL parameters',
      'HTTP headers',
      'Cookie values',
      'DOM manipulation points'
    ],
    riskLevel: 'High'
  },
  sql: {
    name: 'SQL Injection Scanner',
    description: 'Detects SQL injection vulnerabilities by testing various injection patterns and database error responses.',
    whatItScans: [
      'Query parameters',
      'Form inputs',
      'Authentication fields',
      'Search functionality',
      'Database error messages'
    ],
    riskLevel: 'Critical'
  },
  ssrf: {
    name: 'SSRF Scanner',
    description: 'Server-Side Request Forgery detection. Tests for unauthorized internal network access and port scanning.',
    whatItScans: [
      'URL parameters',
      'File upload functionality',
      'Webhook endpoints',
      'API integrations',
      'Import/export features'
    ],
    riskLevel: 'High'
  },
  lfi: {
    name: 'LFI Scanner',
    description: 'Local File Inclusion vulnerability scanner. Tests for unauthorized file system access.',
    whatItScans: [
      'File path parameters',
      'Include/require statements',
      'Template loading',
      'Configuration file access',
      'Log file exposure'
    ],
    riskLevel: 'High'
  },
  auth: {
    name: 'Auth Bypass Scanner',
    description: 'Tests for authentication and authorization bypass vulnerabilities.',
    whatItScans: [
      'Login mechanisms',
      'Session management',
      'Password reset flows',
      'Role-based access control',
      'API authentication'
    ],
    riskLevel: 'Critical'
  },
  jwt: {
    name: 'JWT Scanner',
    description: 'JSON Web Token security scanner. Tests for JWT vulnerabilities and misconfigurations.',
    whatItScans: [
      'JWT signature validation',
      'Algorithm confusion',
      'Token expiration',
      'Claim manipulation',
      'Key confusion attacks'
    ],
    riskLevel: 'High'
  },
  cors: {
    name: 'CORS Scanner',
    description: 'Cross-Origin Resource Sharing misconfiguration detection.',
    whatItScans: [
      'CORS headers',
      'Origin reflection',
      'Credential exposure',
      'Wildcard usage',
      'Pre-flight requests'
    ],
    riskLevel: 'Medium'
  },
  csrf: {
    name: 'CSRF Scanner',
    description: 'Cross-Site Request Forgery vulnerability detection.',
    whatItScans: [
      'Form submissions',
      'State-changing requests',
      'CSRF token validation',
      'SameSite cookie attributes',
      'Referer header checks'
    ],
    riskLevel: 'Medium'
  },
  xxe: {
    name: 'XXE Scanner',
    description: 'XML External Entity injection vulnerability scanner.',
    whatItScans: [
      'XML parsers',
      'File upload (XML)',
      'SOAP endpoints',
      'RSS/Atom feeds',
      'Configuration files'
    ],
    riskLevel: 'High'
  },
  idor: {
    name: 'IDOR Scanner',
    description: 'Insecure Direct Object Reference detection.',
    whatItScans: [
      'API endpoints',
      'Object IDs',
      'User resources',
      'File access',
      'Database records'
    ],
    riskLevel: 'High'
  },
  graphql: {
    name: 'GraphQL Scanner',
    description: 'GraphQL API security scanner.',
    whatItScans: [
      'Introspection queries',
      'Query depth limits',
      'Rate limiting',
      'Field suggestions',
      'Mutation security'
    ],
    riskLevel: 'Medium'
  },
  api: {
    name: 'API Security Scanner',
    description: 'Comprehensive API security testing.',
    whatItScans: [
      'REST endpoints',
      'Authentication',
      'Rate limiting',
      'Input validation',
      'Error handling'
    ],
    riskLevel: 'High'
  }
};

const ScannerPage = () => {
  const { type } = useParams();
  const [target, setTarget] = useState('');
  const [acceptDisclaimer, setAcceptDisclaimer] = useState(false);
  const [touched, setTouched] = useState({ target: false, consent: false });
  const [submitting, setSubmitting] = useState(false);
  const toast = useToast();
  const [upgradeModal, setUpgradeModal] = useState(null);
  const [recentPage, setRecentPage] = useState(1);
  const [options, setOptions] = useState({
    depth: 'medium',
    timeout: 30,
    followRedirects: true,
  });

  const info = scannerInfo[type] || {};

  // Map scanner type to backend scan_type
  const getScanType = (scannerType) => {
    const typeMap = {
      'xss': 'web_security',
      'sql': 'web_security',
      'ssrf': 'web_security',
      'lfi': 'web_security',
      'auth': 'web_security',
      'jwt': 'web_security',
      'cors': 'web_security',
      'csrf': 'web_security',
      'xxe': 'web_security',
      'idor': 'web_security',
      'graphql': 'api_security',
      'api': 'api_security'
    };
    return typeMap[scannerType] || 'web_security';
  };

  // Map scanner type to detector name
  const getDetectorName = (scannerType) => {
    const detectorMap = {
      'xss': 'xss_pattern_detector',
      'sql': 'sql_pattern_detector',
      'ssrf': 'ssrf_detector',
      'lfi': 'lfi_detector',
      'auth': 'auth_bypass_detector',
      'jwt': 'jwt_detector',
      'cors': 'cors_detector',
      'csrf': 'csrf_detector',
      'xxe': 'xxe_detector',
      'idor': 'idor_detector',
      'graphql': 'graphql_detector',
      'api': 'api_security_detector'
    };
    return detectorMap[scannerType];
  };

  const backendScanType = getScanType(type);
  const detectorName = getDetectorName(type);

  useEffect(() => {
    setRecentPage(1);
  }, [type]);

  const isValidHttpUrl = (value) => {
    try {
      const url = new URL(value);
      return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
      return false;
    }
  };

  const targetError = useMemo(() => {
    if (!isNonEmpty(target)) return 'Target URL is required.';
    if (!isValidHttpUrl(target)) return 'Enter a valid http(s) URL.';
    return null;
  }, [target]);

  const consentError = useMemo(() => {
    if (acceptDisclaimer) return null;
    return 'You must confirm you have authorization to scan this target.';
  }, [acceptDisclaimer]);

  const detectorError = useMemo(() => {
    if (detectorName) return null;
    return 'This scanner is not configured with a detector.';
  }, [detectorName]);

  const hasFormErrors = useMemo(() => {
    return !!targetError || !!consentError || !!detectorError;
  }, [targetError, consentError, detectorError]);

  // Fetch recent scans for this scanner type
  const {
    data: recentScansData,
    isLoading: recentLoading,
    isError: recentIsError,
    error: recentError,
    refetch,
  } = useQuery(
    ['scans', type, recentPage],
    () => scanService.getAll({ scan_type: backendScanType, page: recentPage, page_size: 20 }).then((res) => res.data),
    {
      // Keep the "Recent Scans" card up-to-date while a scan is pending/running.
      refetchInterval: (data) => {
        const items = Array.isArray(data?.results) ? data.results : [];
        const hasActive = items.some((s) => s?.status === 'pending' || s?.status === 'running');
        return hasActive ? 2000 : false;
      },
      keepPreviousData: true,
    }
  );

  const recentScans = useMemo(() => {
    if (!recentScansData) return [];
    if (Array.isArray(recentScansData.results)) return recentScansData.results;
    if (Array.isArray(recentScansData)) return recentScansData;
    return [];
  }, [recentScansData]);

  const recentTotalPages =
    typeof recentScansData?.count === 'number' ? Math.max(1, Math.ceil(recentScansData.count / 20)) : undefined;

  const handleScan = async (e) => {
    e.preventDefault();

    if (targetError || consentError || detectorError) {
      setTouched({ target: true, consent: true });
      return;
    }

    try {
      setSubmitting(true);
      const scanData = {
        target,
        scan_type: backendScanType,
        consent: true,
        detectors: [detectorName],
        options: {
          timeout: options.timeout,
          depth: options.depth,
          follow_redirects: options.followRedirects,
        },
      };
      
      await scanService.create(scanData);
      setTarget('');
      setAcceptDisclaimer(false);
      setTouched({ target: false, consent: false });
      refetch();
      toast.success('Scan started successfully');
    } catch (error) {
      const status = error?.response?.status;
      const message =
        error?.response?.data?.error ||
        error?.response?.data?.detail ||
        error?.message ||
        'Failed to start scan';

      if (status === 402) {
        setUpgradeModal({
          title: 'Scan limit reached',
          message,
          bullets: ['Higher daily/monthly limits', 'Advanced scanners', 'Priority support'],
        });
        return;
      }

      if (status === 403) {
        setUpgradeModal({
          title: 'Upgrade required',
          message,
          bullets: ['Higher limits', 'More detectors', 'Teams & integrations'],
        });
        return;
      }

      if (status === 503) {
        toast.error('Scanning temporarily unavailable. Please try again shortly.');
      } else if (status === 429) {
        toast.error('Too many requests. Please wait and try again.');
      } else {
        toast.error(message);
      }
    } finally {
      setSubmitting(false);
    }
  };

  const getRiskColor = (risk) => {
    const colors = {
      Critical: 'bg-red-500/10 text-red-600 dark:text-red-400 ring-1 ring-red-500/20',
      High: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 ring-1 ring-orange-500/20',
      Medium: 'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 ring-1 ring-yellow-500/20',
      Low: 'bg-blue-500/10 text-blue-700 dark:text-blue-400 ring-1 ring-blue-500/20'
    };
    return colors[risk] || colors.Medium;
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <FiCheckCircle className="text-green-500" />;
      case 'running':
        return <FiClock className="text-blue-500 animate-spin" />;
      case 'failed':
        return <FiAlertCircle className="text-red-500" />;
      default:
        return <FiClock className="text-gray-500" />;
    }
  };

  return (
    <DashboardLayout>
      <div className="ui-page">
        {/* Header */}
        <div className="mb-8">
          <h1 className="ui-title mb-2">{info.name}</h1>
          <p className="ui-subtitle">{info.description}</p>
          <div className="mt-4">
            <span className={`inline-block px-3 py-1 rounded-full text-sm font-semibold ${getRiskColor(info.riskLevel)}`}>
              {info.riskLevel} Risk
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Column - Scanner Info */}
          <div className="lg:col-span-2 space-y-6">
            {/* What it Scans */}
            <div className="ui-card p-6">
              <h2 className="text-xl font-semibold mb-4 flex items-center gap-2 text-gray-900 dark:text-white">
                <FiSettings className="text-primary" />
                What This Scanner Checks
              </h2>
              <ul className="space-y-2">
                {info.whatItScans?.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <FiCheckCircle className="text-green-500 mt-1 flex-shrink-0" />
                    <span className="text-gray-700 dark:text-gray-200">{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* New Scan Form */}
            <div className="ui-card p-6">
              <h2 className="text-xl font-semibold mb-4 flex items-center gap-2 text-gray-900 dark:text-white">
                <FiPlay className="text-primary" />
                Start New Scan
              </h2>
              <SubscriptionUsageHeader className="mb-4" />
              <form onSubmit={handleScan} className="space-y-4" noValidate>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-200 mb-2">
                    Target URL
                  </label>
                  <input
                    type="url"
                    value={target}
                    onChange={(e) => {
                      setTarget(e.target.value);
                      if (!touched.target) setTouched((t) => ({ ...t, target: true }));
                    }}
                    onBlur={() => setTouched((t) => ({ ...t, target: true }))}
                    placeholder="https://example.com"
                    className={`ui-input ${touched.target && targetError ? 'ui-input-error' : ''}`}
                    aria-invalid={touched.target && !!targetError}
                    aria-describedby="scanner-target-error"
                  />
                  <div id="scanner-target-error">
                    <FieldError message={touched.target ? targetError : null} />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-200 mb-2">
                      Scan Depth
                    </label>
                    <select
                      value={options.depth}
                      onChange={(e) => setOptions({ ...options, depth: e.target.value })}
                      className="ui-select"
                    >
                      <option value="light">Light</option>
                      <option value="medium">Medium</option>
                      <option value="deep">Deep</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-200 mb-2">
                      Timeout (seconds)
                    </label>
                    <input
                      type="number"
                      value={options.timeout}
                      onChange={(e) => setOptions({ ...options, timeout: parseInt(e.target.value) })}
                      className="ui-input"
                      min="10"
                      max="300"
                    />
                  </div>
                </div>

                <div className="flex items-center">
                  <input
                    type="checkbox"
                    checked={options.followRedirects}
                    onChange={(e) => setOptions({ ...options, followRedirects: e.target.checked })}
                    className="w-4 h-4 text-primary border-gray-300 rounded focus:ring-primary"
                  />
                  <label className="ml-2 text-sm text-gray-700 dark:text-gray-200">
                    Follow Redirects
                  </label>
                </div>

                <ScanConsentGate
                  checked={acceptDisclaimer}
                  onChange={(checked) => {
                    setAcceptDisclaimer(checked);
                    if (!touched.consent) setTouched((t) => ({ ...t, consent: true }));
                  }}
                />
                <FieldError message={touched.consent ? consentError : null} />

                <FieldError message={detectorError} />

                <button
                  type="submit"
                  disabled={submitting || hasFormErrors}
                  className={`ui-btn ui-btn-primary w-full justify-center disabled:opacity-60 disabled:cursor-not-allowed ${
                    hasFormErrors ? 'bg-gray-400 hover:bg-gray-400' : ''
                  }`}
                >
                  <FiPlay />
                  {submitting ? 'Starting…' : 'Start Scan'}
                </button>
              </form>

              <UpgradeModal
                open={!!upgradeModal}
                title={upgradeModal?.title}
                message={upgradeModal?.message}
                bullets={upgradeModal?.bullets}
                onClose={() => setUpgradeModal(null)}
              />
            </div>
          </div>

          {/* Right Column - Recent Scans */}
          <div className="lg:col-span-1">
            <div className="ui-card p-6">
              <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">Recent Scans</h2>

              {recentLoading ? (
                <LoadingState title="Loading scans" subtitle="Fetching recent activity…" />
              ) : recentIsError ? (
                <ErrorState
                  title="Couldn’t load scans"
                  subtitle={
                    recentError?.response?.data?.error ||
                    recentError?.message ||
                    'Please try again.'
                  }
                  action={
                    <button onClick={() => refetch()} className="ui-btn ui-btn-primary">
                      Retry
                    </button>
                  }
                />
              ) : !recentScans || recentScans.length === 0 ? (
                <EmptyState title="No scans yet" subtitle="Start your first scan to see it here." />
              ) : (
                <div className="space-y-3">
                  {recentScans.map((scan) => (
                    <div key={scan.id} className="border border-gray-200 dark:border-gray-700 rounded-lg p-3 hover:border-primary transition">
                      <div className="flex items-start justify-between mb-2">
                        {getStatusIcon(scan.status)}
                        <span className="text-xs text-gray-500 dark:text-gray-400">
                          {new Date(scan.created_at).toLocaleDateString()}
                        </span>
                      </div>
                      <p className="text-sm text-gray-700 dark:text-gray-200 truncate mb-1">{scan.target}</p>
                      <div className="flex justify-between items-center text-xs">
                        <span className="text-gray-500 dark:text-gray-400">{scan.status}</span>
                        {(scan.vulnerabilities_found || 0) > 0 && (
                          <span className="text-red-600 font-semibold">
                            {scan.vulnerabilities_found} issues
                          </span>
                        )}
                      </div>
                    </div>
                  ))}

                  <PaginationControls
                    className="pt-2"
                    page={recentPage}
                    totalPages={recentTotalPages}
                    hasPrev={recentPage > 1 && !recentLoading}
                    hasNext={!!recentScansData?.next && !recentLoading}
                    onPrev={() => setRecentPage((p) => Math.max(1, p - 1))}
                    onNext={() => setRecentPage((p) => p + 1)}
                  />
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default ScannerPage;
