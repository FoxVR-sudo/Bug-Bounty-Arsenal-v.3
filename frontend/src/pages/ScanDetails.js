import React, { useEffect, useMemo, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useQueryClient } from 'react-query';
import { scanService, vulnerabilityService } from '../services/api';
import { FiArrowLeft, FiDownload, FiAlertTriangle, FiCheckCircle, FiInfo, FiShield } from 'react-icons/fi';
import { format } from 'date-fns';
import DashboardLayout from '../components/DashboardLayout';
import { useToast } from '../contexts/ToastContext';
import LoadingState from '../components/states/LoadingState';
import ErrorState from '../components/states/ErrorState';
import EmptyState from '../components/states/EmptyState';
import PaginationControls from '../components/PaginationControls';
import useScanWebsocket from '../hooks/useScanWebsocket';
import { isWsEnabled } from '../lib/websocket';

const coerceJsonObject = (value) => {
  if (!value) return null;
  if (typeof value === 'object') return value;
  if (typeof value === 'string') {
    try {
      return JSON.parse(value);
    } catch (_) {
      return null;
    }
  }
  return null;
};

const summarizeExecuted = (executed) => {
  const byDetector = new Map();
  (executed || []).forEach((entry) => {
    const detector = entry?.detector || entry;
    if (!detector) return;
    const url = entry?.url;
    const set = byDetector.get(detector) || new Set();
    if (url) set.add(url);
    byDetector.set(detector, set);
  });
  return Array.from(byDetector.entries())
    .map(([detector, urls]) => ({ detector, urlsCount: urls.size }))
    .sort((a, b) => a.detector.localeCompare(b.detector));
};

const summarizeSkipped = (skipped) => {
  const byDetector = new Map();
  (skipped || []).forEach((entry) => {
    const detector = entry?.detector;
    if (!detector) return;
    const url = entry?.url;
    let reason = entry?.reason;
    if (reason === 'Requires verified email (dangerous detector)') {
      reason = 'Requires verified domain (dangerous detector)';
    }
    const prev = byDetector.get(detector) || { urls: new Set(), reasons: new Set() };
    if (url) prev.urls.add(url);
    if (reason) prev.reasons.add(reason);
    byDetector.set(detector, prev);
  });
  return Array.from(byDetector.entries())
    .map(([detector, data]) => ({
      detector,
      urlsCount: data.urls.size,
      reasons: Array.from(data.reasons.values()).slice(0, 5),
    }))
    .sort((a, b) => a.detector.localeCompare(b.detector));
};

const toOneLine = (text) => {
  if (!text) return '';
  return String(text).replace(/\r/g, '\n').split('\n').join(' ').replace(/\s+/g, ' ').trim();
};

const stripTraceback = (text) => {
  const oneLine = toOneLine(text);
  const idx = oneLine.toLowerCase().indexOf('traceback');
  return idx >= 0 ? oneLine.slice(0, idx).trim() : oneLine;
};

const formatScanTypeLabel = (scan) => {
  if (scan?.display_type) return scan.display_type;
  if (scan?.scan_category) return scan.scan_category;

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

const buildReachabilityInsights = ({ scanView, rawResults, vulnerabilities }) => {
  const meta = rawResults?.metadata || {};
  const skippedUnresolved = Array.isArray(meta.skipped_unresolved) ? meta.skipped_unresolved : [];
  const skippedUnreachable = Array.isArray(meta.skipped_unreachable) ? meta.skipped_unreachable : [];
  const usedPublicDns = !!meta.used_public_dns;
  const resolvedViaPublicDns = Array.isArray(meta.resolved_via_public_dns) ? meta.resolved_via_public_dns : [];

  const scanErrors = (vulnerabilities || []).filter((v) => {
    const title = String(v?.title || '').toLowerCase();
    return title === 'scan error' || title.includes('scan error');
  });

  const hasSkips = skippedUnresolved.length > 0 || skippedUnreachable.length > 0;
  const hasFailure = String(scanView?.status || '').toLowerCase() === 'failed';

  const rawError = rawResults?.error || rawResults?.error_short || '';
  const stepError = String(scanView?.current_step || '').startsWith('Error:') ? scanView.current_step : '';
  const baseError = stripTraceback(rawResults?.error_short || rawError || stepError);

  const errorSignals = {
    dns: /dns|name or service not known|nodename nor servname|getaddrinfo|no such host|nxdomain/i.test(baseError),
    timeout: /timeout|timed out/i.test(baseError),
    refused: /refused|econnrefused/i.test(baseError),
    tls: /ssl|tls|certificate|handshake/i.test(baseError),
  };

  const recommendations = [];
  if (skippedUnresolved.length > 0 || errorSignals.dns) {
    recommendations.push('DNS resolution failed for some targets — double-check the hostname, try a different DNS/network, or use a direct IP.');
  }
  if (skippedUnreachable.length > 0 || errorSignals.timeout) {
    recommendations.push('Some targets did not respond (timeouts) — verify the host is up/reachable and consider increasing timeout.');
  }
  if (errorSignals.refused) {
    recommendations.push('Connection refused — the port/service may be closed or blocked by a firewall/WAF.');
  }
  if (errorSignals.tls) {
    recommendations.push('TLS/SSL issues detected — confirm https/http scheme and certificate configuration.');
  }
  if (recommendations.length === 0 && (hasFailure || hasSkips || scanErrors.length > 0)) {
    recommendations.push('Some requests could not be completed. Check target reachability and try again.');
  }

  const details = [];
  if (usedPublicDns) {
    details.push({
      label: 'Public DNS fallback',
      value: resolvedViaPublicDns.length > 0 ? `used (resolved ${resolvedViaPublicDns.length})` : 'used',
    });
  }
  if (skippedUnresolved.length > 0) {
    details.push({ label: 'Unresolved (DNS)', value: skippedUnresolved.slice(0, 6).join(', ') + (skippedUnresolved.length > 6 ? '…' : '') });
  }
  if (skippedUnreachable.length > 0) {
    details.push({ label: 'Unreachable', value: skippedUnreachable.slice(0, 6).join(', ') + (skippedUnreachable.length > 6 ? '…' : '') });
  }
  if (scanErrors.length > 0) {
    const examples = scanErrors
      .map((v) => stripTraceback(v?.description || ''))
      .filter(Boolean)
      .slice(0, 2);
    if (examples.length > 0) {
      details.push({ label: 'Scan errors', value: examples.join(' | ') + (scanErrors.length > 2 ? ' …' : '') });
    }
  }

  const showPanel = hasFailure || hasSkips || scanErrors.length > 0;

  return {
    showPanel,
    hasFailure,
    title: hasFailure ? 'Scan failed' : 'Some targets were skipped',
    subtitle: baseError || null,
    recommendations,
    details,
  };
};

const ScanDetails = () => {
  const { id } = useParams();
  const toast = useToast();
  const [cancelling, setCancelling] = useState(false);
  const [liveScan, setLiveScan] = useState(null);
  const [downloadingFormat, setDownloadingFormat] = useState(null);
  const [filterQuery, setFilterQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterDetector, setFilterDetector] = useState('all');
  const [filterVerifiedOnly, setFilterVerifiedOnly] = useState(false);
  const [vulnPage, setVulnPage] = useState(1);
  const [showPreScanSubdomains, setShowPreScanSubdomains] = useState(false);
  const queryClient = useQueryClient();

  const { connected: wsConnected, lastEvent } = useScanWebsocket(id, { enabled: isWsEnabled() });

  // Fetch scan details
  const { data: scan, isLoading: scanLoading, error: scanError, refetch: refetchScan } = useQuery(
    ['scan', id],
    () => scanService.getById(id).then((res) => res.data),
    {
      refetchInterval: (data) => {
        const status = data?.status;
        return status === 'running' || status === 'pending' ? 2000 : false;
      },
    }
  );

  useEffect(() => {
    if (scan) setLiveScan(scan);
  }, [scan]);

  useEffect(() => {
    if (!lastEvent) return;
    const payload = lastEvent?.data;
    if (!payload) return;

    if (lastEvent.type === 'scan_status' || lastEvent.type === 'scan_update' || lastEvent.type === 'scan_complete') {
      setLiveScan((prev) => ({ ...(prev || {}), ...payload }));
    }

    if (lastEvent.type === 'scan_error') {
      setLiveScan((prev) => ({ ...(prev || {}), ...payload }));
    }
  }, [lastEvent]);

  useEffect(() => {
    setVulnPage(1);
  }, [id, filterQuery, filterSeverity, filterDetector, filterVerifiedOnly]);

  // Fetch vulnerabilities
  const { data: vulnsData, isLoading: vulnsLoading } = useQuery(
    ['vulnerabilities', id, vulnPage, filterQuery, filterSeverity, filterDetector, filterVerifiedOnly],
    () => {
      const params = { page: vulnPage };
      const search = filterQuery.trim();
      if (search) params.search = search;
      if (filterSeverity !== 'all') params.severity = filterSeverity;
      if (filterDetector !== 'all') params.detector = filterDetector;
      if (filterVerifiedOnly) params.verified_only = true;
      return scanService.getVulnerabilities(id, params).then((res) => res.data);
    },
    {
      enabled: !!scan,
      refetchInterval: () => {
        const status = (liveScan || scan)?.status;
        return status === 'running' || status === 'pending' ? 5000 : false;
      },
      keepPreviousData: true,
    }
  );

  const scanView = liveScan || scan;
  const rawResults = coerceJsonObject(scanView?.raw_results);
  const vulnerabilities = useMemo(() => vulnsData?.results || [], [vulnsData]);
  const allScanVulnerabilities = useMemo(() => {
    if (Array.isArray(scanView?.vulnerabilities) && scanView.vulnerabilities.length > 0) {
      return scanView.vulnerabilities;
    }
    return vulnerabilities;
  }, [scanView, vulnerabilities]);
  const vulnTotalPages =
    typeof vulnsData?.count === 'number' ? Math.max(1, Math.ceil(vulnsData.count / 20)) : undefined;

  const saveBlob = ({ blob, filename }) => {
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  };

  const canExport = String(scanView?.status || '').toLowerCase() === 'completed';

  const handleDownload = async (format) => {
    if (!canExport) {
      toast.info('Exports are available after the scan completes.');
      return;
    }
    try {
      setDownloadingFormat(format);
      let res;
      if (format === 'pdf') {
        res = await scanService.downloadPDF(id);
      } else if (format === 'csv') {
        res = await scanService.downloadCSV(id);
      } else {
        res = await scanService.downloadJSON(id);
        format = 'json';
      }
      saveBlob({ blob: new Blob([res.data]), filename: `scan-${id}-report.${format}` });
    } catch (error) {
      const status = error?.response?.status;
      if (status === 413) {
        toast.error('Export too large. Try JSON, narrow the scan scope, or split by category.');
      } else if (status === 503) {
        toast.error('Exports temporarily unavailable. Please try again shortly.');
      } else if (status === 429) {
        toast.error('Too many export requests. Please wait and try again.');
      } else if (status === 404) {
        toast.error('Report not found. If the scan just finished, wait a moment and try again.');
      } else if (status === 402 || status === 403) {
        toast.error('Your plan does not allow this export. Please upgrade to continue.');
      } else {
        toast.error(error?.message ? `Failed to download report: ${error.message}` : 'Failed to download report');
      }
    } finally {
      setDownloadingFormat(null);
    }
  };

  const handleCancel = async () => {
    if (!scanView) return;
    const status = scanView.status;
    if (status !== 'running' && status !== 'pending') {
      toast.info('This scan is already finished.');
      return;
    }

    try {
      setCancelling(true);
      await scanService.cancel(id);
      toast.success('Scan stop requested');
      refetchScan();
    } catch (error) {
      const message =
        error?.response?.data?.detail ||
        error?.response?.data?.error ||
        error?.message ||
        'Failed to stop scan';
      toast.error(message);
    } finally {
      setCancelling(false);
    }
  };

  const detectorsInFindings = useMemo(() => {
    const detectors = new Set();
    allScanVulnerabilities.forEach((v) => {
      if (v?.detector) detectors.add(v.detector);
    });
    return Array.from(detectors.values()).sort((a, b) => String(a).localeCompare(String(b)));
  }, [allScanVulnerabilities]);

  const hasActiveVulnerabilityFilters = Boolean(
    filterQuery.trim() || filterSeverity !== 'all' || filterDetector !== 'all' || filterVerifiedOnly
  );
  const filteredVulnerabilities = vulnerabilities;
  const filteredVulnerabilityCount = typeof vulnsData?.count === 'number'
    ? vulnsData.count
    : filteredVulnerabilities.length;

  // Use backend-stored severity_counts (covers ALL vulnerabilities, not just current page)
  const severityCounts = {
    critical: scanView?.severity_counts?.critical ?? 0,
    high: scanView?.severity_counts?.high ?? 0,
    medium: scanView?.severity_counts?.medium ?? 0,
    low: scanView?.severity_counts?.low ?? 0,
    info: scanView?.severity_counts?.info ?? 0,
  };
  const totalVulnCount = Number.isFinite(Number(scanView?.vulnerabilities_found))
    ? Number(scanView?.vulnerabilities_found || 0)
    : Object.values(severityCounts).reduce((a, b) => a + b, 0);

  const statusPill = (() => {
    const s = String(scanView?.status || '').toLowerCase();
    const base = 'px-3 py-1 rounded-full text-xs font-semibold';
    if (s === 'completed') return { cls: `${base} bg-green-500/10 text-green-600 dark:text-green-400`, label: 'completed' };
    if (s === 'failed') return { cls: `${base} bg-red-500/10 text-red-600 dark:text-red-400`, label: 'failed' };
    if (s === 'stopped' || s === 'cancelled' || s === 'canceled') return { cls: `${base} bg-gray-500/10 text-gray-700 dark:text-gray-300`, label: s };
    if (s === 'running') return { cls: `${base} bg-blue-500/10 text-blue-700 dark:text-blue-300`, label: 'running' };
    return { cls: `${base} bg-yellow-500/10 text-yellow-700 dark:text-yellow-300`, label: s || 'pending' };
  })();

  const progressValue = Math.max(0, Math.min(100, Number(scanView?.progress || 0)));
  const currentStep = scanView?.current_step || '';
  const etaText = (() => {
    const s = Number(scanView?.eta_seconds);
    if (!Number.isFinite(s) || s <= 0) return null;
    const mins = Math.floor(s / 60);
    const secs = Math.floor(s % 60);
    if (mins <= 0) return `${secs}s`;
    return `${mins}m ${secs}s`;
  })();
  const reachability = buildReachabilityInsights({ scanView, rawResults, vulnerabilities });

  if (scanLoading || vulnsLoading) {
    return (
      <DashboardLayout>
        <LoadingState title="Loading scan details…" />
      </DashboardLayout>
    );
  }

  if (scanError || !scan) {
    return (
      <DashboardLayout>
        <ErrorState
          title="Scan not found"
          message="The scan you're looking for doesn't exist or you don't have access."
          action={
            <Link to="/dashboard" className="ui-btn ui-btn-primary inline-flex">
              Back to Dashboard
            </Link>
          }
        />
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="ui-page">
        <div className="mb-6 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link to="/dashboard" className="ui-btn ui-btn-ghost" title="Back to Dashboard">
              <FiArrowLeft size={18} />
            </Link>
            <h1 className="ui-title">Scan Details</h1>
          </div>

          {(scanView?.status === 'running' || scanView?.status === 'pending') && (
            <button
              type="button"
              onClick={handleCancel}
              disabled={cancelling}
              className="ui-btn bg-white text-red-600 border border-red-200 hover:bg-red-50 disabled:opacity-50 dark:bg-gray-900 dark:border-red-800/40 dark:hover:bg-red-900/20"
            >
              {cancelling ? 'Stopping…' : 'Stop Scan'}
            </button>
          )}
        </div>

        {(scanView?.status === 'running' || scanView?.status === 'pending') && (
          <div className="ui-card p-6 mb-8 border border-blue-200 dark:border-blue-800/40 bg-blue-50/60 dark:bg-blue-900/10">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <span className={statusPill.cls}>{statusPill.label}</span>
                  <span className="text-xs text-gray-500 dark:text-gray-400">
                    {wsConnected ? 'Live updates connected' : 'Live updates unavailable — polling'}
                  </span>
                </div>
                {currentStep ? (
                  <div className="text-sm text-gray-700 dark:text-gray-200">
                    <span className="font-semibold">Current step:</span> {currentStep}
                  </div>
                ) : (
                  <div className="text-sm text-gray-600 dark:text-gray-300">Preparing scan…</div>
                )}

                {(scanView?.current_detector || scanView?.current_url || etaText) && (
                  <div className="mt-2 grid grid-cols-1 gap-1 text-xs text-gray-600 dark:text-gray-300">
                    {scanView?.current_detector && (
                      <div>
                        <span className="font-semibold">Detector:</span> {scanView.current_detector}
                      </div>
                    )}
                    {scanView?.current_url && (
                      <div className="truncate">
                        <span className="font-semibold">URL:</span> {scanView.current_url}
                      </div>
                    )}
                    {etaText && (
                      <div>
                        <span className="font-semibold">ETA:</span> {etaText}
                      </div>
                    )}
                  </div>
                )}
              </div>
              <div className="text-right">
                <div className="text-2xl font-bold text-blue-700 dark:text-blue-300">{progressValue}%</div>
                <div className="text-xs text-gray-500 dark:text-gray-400">progress</div>
              </div>
            </div>

            <div className="mt-4">
              <div className="h-3 rounded-full overflow-hidden bg-blue-100 dark:bg-gray-800">
                <div
                  className="h-full bg-gradient-to-r from-blue-500 to-purple-500 transition-all duration-500"
                  style={{ width: `${progressValue}%` }}
                />
              </div>
            </div>
          </div>
        )}

        {/* Scan Info Card */}
        <div className="ui-card p-6 mb-8">
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Scan Information</h2>
              <div className="space-y-3">
                <InfoRow label="Target" value={scanView.target} />
                <InfoRow label="Scan Type" value={formatScanTypeLabel(scanView)} />
                <InfoRow
                  label="Status"
                  value={
                    <span className={statusPill.cls}>{statusPill.label}</span>
                  }
                />
                <InfoRow
                  label="Created"
                  value={format(new Date(scanView.created_at), 'MMM dd, yyyy HH:mm:ss')}
                />
                {scanView.completed_at && (
                  <InfoRow
                    label="Completed"
                    value={format(new Date(scanView.completed_at), 'MMM dd, yyyy HH:mm:ss')}
                  />
                )}
                <InfoRow label="Duration" value={`${scanView.duration?.toFixed?.(2) || scanView.duration || 0}s`} />
              </div>
            </div>
            <div>
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Severity Distribution
                {totalVulnCount > 0 && (
                  <span className="ml-2 text-sm font-normal text-gray-500 dark:text-gray-400">({totalVulnCount} total)</span>
                )}
              </h2>
              <div className="space-y-3">
                <SeverityBar label="Critical" count={severityCounts.critical} color="red" />
                <SeverityBar label="High" count={severityCounts.high} color="orange" />
                <SeverityBar label="Medium" count={severityCounts.medium} color="yellow" />
                <SeverityBar label="Low" count={severityCounts.low} color="blue" />
                <SeverityBar label="Info" count={severityCounts.info} color="gray" />
              </div>
            </div>
          </div>

          {/* Export Buttons */}
          <div className="mt-6 pt-6 border-t border-gray-200 dark:border-gray-700 flex gap-3 flex-wrap">
            <button
              onClick={() => handleDownload('json')}
              disabled={!canExport || !!downloadingFormat}
              title={!canExport ? 'Available after completion' : 'Download JSON report'}
              className="ui-btn ui-btn-primary disabled:opacity-50"
            >
              <FiDownload /> {downloadingFormat === 'json' ? 'Downloading…' : 'Download JSON'}
            </button>
            <button
              onClick={() => handleDownload('pdf')}
              disabled={!canExport || !!downloadingFormat}
              title={!canExport ? 'Available after completion' : 'Download PDF report'}
              className="ui-btn ui-btn-secondary disabled:opacity-50"
            >
              <FiDownload /> {downloadingFormat === 'pdf' ? 'Downloading…' : 'Download PDF'}
            </button>
            <button
              onClick={() => handleDownload('csv')}
              disabled={!canExport || !!downloadingFormat}
              title={!canExport ? 'Available after completion' : 'Download CSV report'}
              className="ui-btn bg-green-600 text-white hover:bg-green-700 disabled:opacity-50"
            >
              <FiDownload /> {downloadingFormat === 'csv' ? 'Downloading…' : 'Download CSV'}
            </button>

            {!canExport && (
              <div className="text-xs text-gray-500 dark:text-gray-400 self-center">
                Exports are enabled when the scan status is <span className="font-semibold">completed</span>.
              </div>
            )}
          </div>
        </div>

        {reachability.showPanel && (
          <div className="ui-card p-6 mb-8 border border-amber-200 dark:border-amber-800/40 bg-amber-50/60 dark:bg-amber-900/10">
            <div className="flex items-start gap-3">
              <FiAlertTriangle className="text-amber-600 mt-0.5" />
              <div className="flex-1">
                <div className="text-sm font-semibold text-gray-900 dark:text-white">{reachability.title}</div>
                {reachability.subtitle && (
                  <div className="text-xs text-gray-600 dark:text-gray-300 mt-1">{reachability.subtitle}</div>
                )}
                {reachability.recommendations?.length > 0 && (
                  <ul className="mt-3 text-sm text-gray-700 dark:text-gray-200 space-y-1">
                    {reachability.recommendations.slice(0, 3).map((r) => (
                      <li key={r}>• {r}</li>
                    ))}
                  </ul>
                )}
                {reachability.details?.length > 0 && (
                  <div className="mt-4 grid md:grid-cols-2 gap-3">
                    {reachability.details.map((d) => (
                      <div key={d.label} className="text-xs text-gray-700 dark:text-gray-200">
                        <span className="font-semibold">{d.label}:</span> {d.value}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {(() => {
          const metaWarnings = Array.isArray(rawResults?.metadata?.warnings) ? rawResults.metadata.warnings : [];
          const preScanWarnings = Array.isArray(rawResults?.pre_scan?.warnings) ? rawResults.pre_scan.warnings : [];
          const detectorErrors = Array.isArray(rawResults?.metadata?.detectors?.errors)
            ? rawResults.metadata.detectors.errors
            : [];
          const fatalError = rawResults?.metadata?.fatal_error || null;

          const totalCount = metaWarnings.length + preScanWarnings.length + detectorErrors.length + (fatalError ? 1 : 0);
          if (!totalCount) return null;

          return (
            <div className="ui-card p-6 mb-8 border border-red-200 dark:border-red-800/40 bg-red-50/60 dark:bg-red-900/10">
              <div className="flex items-start gap-3">
                <FiAlertTriangle className="text-red-600 mt-0.5" />
                <div className="flex-1">
                  <div className="text-sm font-semibold text-gray-900 dark:text-white">Warnings / Degraded execution</div>
                  <div className="text-xs text-gray-700 dark:text-gray-200 mt-1">
                    {totalCount} item{totalCount === 1 ? '' : 's'} reported during execution
                  </div>

                  {fatalError && (
                    <div className="mt-3 text-sm text-gray-800 dark:text-gray-100">
                      <span className="font-semibold">Fatal:</span> {fatalError.type}: {String(fatalError.error || '').slice(0, 240)}
                    </div>
                  )}

                  {(metaWarnings.length > 0 || preScanWarnings.length > 0 || detectorErrors.length > 0) && (
                    <ul className="mt-3 text-xs text-gray-700 dark:text-gray-200 space-y-1 max-h-40 overflow-auto">
                      {preScanWarnings.slice(0, 5).map((w, idx) => (
                        <li key={`psw-${idx}`} className="break-words">
                          <span className="font-semibold">pre-scan</span>: {String(w?.type || 'warning')}{w?.error ? ` — ${String(w.error).slice(0, 240)}` : ''}
                        </li>
                      ))}
                      {metaWarnings.slice(0, 5).map((w, idx) => (
                        <li key={`mw-${idx}`} className="break-words">
                          <span className="font-semibold">scan</span>: {String(w?.type || 'warning')}{w?.error ? ` — ${String(w.error).slice(0, 240)}` : ''}
                        </li>
                      ))}
                      {detectorErrors.slice(0, 5).map((e, idx) => (
                        <li key={`de-${idx}`} className="break-words">
                          <span className="font-semibold">detector</span>: {String(e?.detector || 'unknown')} ({String(e?.phase || 'run')}) — {String(e?.error_type || 'Error')}: {String(e?.error || '').slice(0, 240)}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </div>
          );
        })()}

        {vulnerabilities.length === 0 && (
          <div className="mb-8">
            <EmptyState
              title={scanView.status === 'failed' ? 'Scan failed' : 'No findings yet'}
              message={
                scanView.status === 'running' || scanView.status === 'pending'
                  ? 'This scan is still running. Findings will appear here as they are discovered.'
                  : scanView.status === 'failed'
                    ? 'This scan did not complete successfully. See the message above for next steps.'
                    : 'No vulnerabilities were found for this scan.'
              }
            />
          </div>
        )}

        {rawResults?.pre_scan && (
          <div className="ui-card p-6 mb-8">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Vuln pre-scan</h2>
            <div className="text-sm text-gray-700 dark:text-gray-200 space-y-2">
              {rawResults.pre_scan.domain && (
                <div>
                  <span className="font-semibold">Domain:</span> {rawResults.pre_scan.domain}
                </div>
              )}
              {rawResults.pre_scan.requested && (
                <div>
                  <span className="font-semibold">Requested:</span>{' '}
                  {rawResults.pre_scan.requested.subfinder ? 'subfinder ' : ''}
                  {rawResults.pre_scan.requested.amass ? 'amass ' : ''}
                </div>
              )}

              {rawResults.pre_scan.tools && (
                <div className="grid md:grid-cols-2 gap-3">
                  {Object.entries(rawResults.pre_scan.tools).map(([tool, info]) => (
                    <div key={tool} className="border border-gray-200 dark:border-gray-700 rounded-lg p-3">
                      <div className="flex justify-between gap-3">
                        <div className="font-semibold text-gray-900 dark:text-white">{tool}</div>
                        <div className="text-xs text-gray-600 dark:text-gray-300">
                          {info?.ok ? 'ok' : 'failed'}
                        </div>
                      </div>
                      <div className="text-xs text-gray-600 dark:text-gray-300 mt-1">
                        <span className="font-semibold">Found:</span> {info?.count ?? 0}
                        {info?.error ? (
                          <span className="ml-2"><span className="font-semibold">Error:</span> {String(info.error)}</span>
                        ) : null}
                      </div>
                      {info?.stderr ? (
                        <div className="text-[11px] text-gray-500 dark:text-gray-400 mt-1 break-words">
                          {String(info.stderr).slice(0, 240)}
                        </div>
                      ) : null}
                    </div>
                  ))}
                </div>
              )}

              {Array.isArray(rawResults.pre_scan.subdomains) && (
                <div>
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <span className="font-semibold">Subdomains:</span> {rawResults.pre_scan.subdomains.length}
                    </div>
                    {rawResults.pre_scan.subdomains.length > 0 && (
                      <button
                        type="button"
                        className="text-xs text-primary hover:underline"
                        onClick={() => setShowPreScanSubdomains((v) => !v)}
                      >
                        {showPreScanSubdomains ? 'Hide list' : 'Show list'}
                      </button>
                    )}
                  </div>

                  {showPreScanSubdomains && rawResults.pre_scan.subdomains.length > 0 && (
                    <ul className="mt-2 text-xs text-gray-700 dark:text-gray-200 space-y-1 max-h-56 overflow-auto">
                      {rawResults.pre_scan.subdomains.slice(0, 200).map((sd) => (
                        <li key={sd} className="truncate" title={sd}>{sd}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* Nmap results — open ports found during pre-scan */}
              {(() => {
                const nmapVulns = (vulnerabilities || []).filter((v) => v?.detector === 'nmap_detector');
                const nmapTotal = scanView?.severity_counts
                  ? null // can't isolate nmap from total counts
                  : nmapVulns.length;
                if (nmapVulns.length === 0) return null;
                return (
                  <div className="mt-4">
                    <div className="font-semibold text-gray-900 dark:text-white mb-2">
                      Nmap — Open Ports ({nmapVulns.length}{nmapTotal === null && vulnsData?.count > 20 ? '+' : ''})
                    </div>
                    <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-700">
                      <table className="w-full text-xs border-collapse">
                        <thead>
                          <tr className="bg-gray-100 dark:bg-gray-800">
                            <th className="text-left px-3 py-2 font-semibold text-gray-700 dark:text-gray-200 border-b border-r border-gray-200 dark:border-gray-700 w-20">Port</th>
                            <th className="text-left px-3 py-2 font-semibold text-gray-700 dark:text-gray-200 border-b border-r border-gray-200 dark:border-gray-700">Service</th>
                            <th className="text-left px-3 py-2 font-semibold text-gray-700 dark:text-gray-200 border-b border-r border-gray-200 dark:border-gray-700 w-24">Severity</th>
                            <th className="text-left px-3 py-2 font-semibold text-gray-700 dark:text-gray-200 border-b border-gray-200 dark:border-gray-700">Host</th>
                          </tr>
                        </thead>
                        <tbody>
                          {nmapVulns.map((v) => {
                            const sevColors = {
                              critical: 'text-red-600 dark:text-red-400',
                              high: 'text-orange-600 dark:text-orange-400',
                              medium: 'text-yellow-600 dark:text-yellow-400',
                              low: 'text-blue-600 dark:text-blue-400',
                              info: 'text-gray-500 dark:text-gray-400',
                            };
                            const portMatch = String(v?.title || '').match(/port (\d+\/\w+|\d+)/);
                            const port = portMatch ? portMatch[1] : '?';
                            const svcMatch = String(v?.title || '').match(/\(([^)]+)\)/);
                            const svc = svcMatch ? svcMatch[1] : (v?.description ? String(v.description).split('\n')[0].replace(/^Service:\s*/i, '') : '—');
                            const host = (() => { try { return new URL(v?.url || '').hostname || v?.url || '—'; } catch { return v?.url || '—'; } })();
                            return (
                              <tr key={v.id} className="border-t border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                                <td className="px-3 py-2 font-mono font-semibold text-gray-900 dark:text-white border-r border-gray-200 dark:border-gray-700">{port}</td>
                                <td className="px-3 py-2 text-gray-700 dark:text-gray-200 border-r border-gray-200 dark:border-gray-700">{svc}</td>
                                <td className={`px-3 py-2 font-semibold border-r border-gray-200 dark:border-gray-700 ${sevColors[v?.severity] || sevColors.info}`}>
                                  {v?.severity || 'info'}
                                </td>
                                <td className="px-3 py-2 text-gray-500 dark:text-gray-400 font-mono text-[11px] truncate max-w-[200px]" title={host}>{host}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                );
              })()}
            </div>
          </div>
        )}

        {/* Detectors (honest execution) */}
        <div className="ui-card p-6 mb-8">
          <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Detectors</h2>
          {(() => {
            const detectorsMeta = rawResults?.metadata?.detectors;
            if (!detectorsMeta) {
              return <p className="text-gray-600 dark:text-gray-300 text-sm">No detector execution metadata available yet.</p>;
            }

            const executedSummary = summarizeExecuted(detectorsMeta.executed);
            const skippedSummary = summarizeSkipped(detectorsMeta.skipped);
            const unknown = detectorsMeta.unknown || [];
            const requested = detectorsMeta.requested || [];

            return (
              <div className="space-y-4">
                {requested?.length > 0 && (
                  <div className="text-sm text-gray-700 dark:text-gray-200">
                    <span className="font-semibold">Requested:</span> {requested.length}
                  </div>
                )}

                <div className="grid md:grid-cols-3 gap-4">
                  <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <div className="font-semibold text-gray-900 dark:text-white mb-2">Executed ({executedSummary.length})</div>
                    {executedSummary.length ? (
                      <ul className="text-sm text-gray-700 dark:text-gray-200 space-y-1 max-h-56 overflow-auto">
                        {executedSummary.map((d) => (
                          <li key={d.detector} className="flex justify-between gap-3">
                            <span className="truncate" title={d.detector}>{d.detector}</span>
                            <span className="text-gray-500 dark:text-gray-400 shrink-0">{d.urlsCount} urls</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <div className="text-sm text-gray-500 dark:text-gray-400">None</div>
                    )}
                  </div>

                  <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <div className="font-semibold text-gray-900 dark:text-white mb-2">Skipped ({skippedSummary.length})</div>
                    {skippedSummary.length ? (
                      <ul className="text-sm text-gray-700 dark:text-gray-200 space-y-2 max-h-56 overflow-auto">
                        {skippedSummary.map((d) => (
                          <li key={d.detector}>
                            <div className="flex justify-between gap-3">
                              <span className="truncate" title={d.detector}>{d.detector}</span>
                              <span className="text-gray-500 dark:text-gray-400 shrink-0">{d.urlsCount} urls</span>
                            </div>
                            {d.reasons?.length > 0 && (
                              <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                {d.reasons.join(' | ')}
                              </div>
                            )}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <div className="text-sm text-gray-500 dark:text-gray-400">None</div>
                    )}
                  </div>

                  <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <div className="font-semibold text-gray-900 dark:text-white mb-2">Unknown ({unknown.length})</div>
                    {unknown.length ? (
                      <ul className="text-sm text-gray-700 dark:text-gray-200 space-y-1 max-h-56 overflow-auto">
                        {unknown.map((k) => (
                          <li key={k} className="truncate" title={k}>{k}</li>
                        ))}
                      </ul>
                    ) : (
                      <div className="text-sm text-gray-500 dark:text-gray-400">None</div>
                    )}
                  </div>
                </div>
              </div>
            );
          })()}
        </div>

        {/* Report / Vulnerabilities */}
        <div className="ui-card">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-4">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                Report ({filteredVulnerabilityCount}{hasActiveVulnerabilityFilters ? ` / ${totalVulnCount}` : ''})
              </h2>
              <div className="flex flex-col sm:flex-row gap-3 sm:items-center">
                <input
                  type="text"
                  value={filterQuery}
                  onChange={(e) => setFilterQuery(e.target.value)}
                  placeholder="Search title, URL, detector…"
                  className="ui-input w-full sm:w-64"
                />
                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  className="ui-input"
                  aria-label="Filter by severity"
                >
                  <option value="all">All severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
                <select
                  value={filterDetector}
                  onChange={(e) => setFilterDetector(e.target.value)}
                  className="ui-input"
                  aria-label="Filter by detector"
                >
                  <option value="all">All detectors</option>
                  {detectorsInFindings.map((d) => (
                    <option key={d} value={d}>{d}</option>
                  ))}
                </select>
                <button
                  type="button"
                  onClick={() => setFilterVerifiedOnly((v) => !v)}
                  className={`ui-btn flex items-center gap-2 whitespace-nowrap border transition-colors ${
                    filterVerifiedOnly
                      ? 'bg-green-500/10 text-green-700 dark:text-green-400 border-green-400/40'
                      : 'border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300'
                  }`}
                  title="Show only verified findings"
                >
                  <FiShield size={14} />
                  Verified only
                </button>
              </div>
            </div>
          </div>

          {filteredVulnerabilities.length > 0 ? (
            <>
              <div className="divide-y divide-gray-200 dark:divide-gray-700">
                {filteredVulnerabilities.map((vuln) => (
                  <VulnerabilityCard
                    key={vuln.id}
                    vulnerability={vuln}
                    onVerify={async (vulnId) => {
                      await vulnerabilityService.verify(vulnId);
                      queryClient.invalidateQueries(['vulnerabilities', id, vulnPage]);
                    }}
                  />
                ))}
              </div>
              {(vulnPage > 1 || !!vulnsData?.next) && (
                <div className="p-4 border-t border-gray-200 dark:border-gray-700">
                  <PaginationControls
                    page={vulnPage}
                    totalPages={vulnTotalPages}
                    hasPrev={vulnPage > 1 && !vulnsLoading}
                    hasNext={!!vulnsData?.next && !vulnsLoading}
                    onPrev={() => setVulnPage((p) => Math.max(1, p - 1))}
                    onNext={() => setVulnPage((p) => p + 1)}
                  />
                </div>
              )}
            </>
          ) : (
            <div className="p-12 text-center">
              <FiCheckCircle className="text-6xl text-green-500 mx-auto mb-4" />
              <p className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                {totalVulnCount === 0 ? 'No Vulnerabilities Found' : 'No results for current filters'}
              </p>
              <p className="text-gray-600 dark:text-gray-300">
                {totalVulnCount === 0
                  ? 'This target appears to be secure. No issues were detected during the scan.'
                  : 'Try clearing search, severity, or detector filters.'}
              </p>
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
};

const InfoRow = ({ label, value }) => (
  <div className="flex justify-between items-start gap-2">
    <span className="text-sm font-medium text-gray-600 dark:text-gray-300 flex-shrink-0">{label}:</span>
    <span className="text-sm text-gray-900 dark:text-gray-100 text-right min-w-0 break-words">{value}</span>
  </div>
);

const SeverityBar = ({ label, count, color }) => {
  const colors = {
    red: 'bg-red-500',
    orange: 'bg-orange-500',
    yellow: 'bg-yellow-500',
    blue: 'bg-blue-500',
    gray: 'bg-gray-400',
  };

  return (
    <div>
      <div className="flex justify-between text-sm mb-1">
        <span className="font-medium text-gray-700 dark:text-gray-200">{label}</span>
        <span className="text-gray-600 dark:text-gray-300">{count}</span>
      </div>
      <div className="w-full bg-gray-200 dark:bg-gray-800 rounded-full h-2">
        <div
          className={`h-2 rounded-full ${colors[color]}`}
          style={{ width: count > 0 ? `${Math.min((count / 10) * 100, 100)}%` : '0%' }}
        />
      </div>
    </div>
  );
};

const VulnerabilityCard = ({ vulnerability, onVerify }) => {
  const [expanded, setExpanded] = React.useState(false);
  const [verifying, setVerifying] = React.useState(false);

  const severityColors = {
    critical: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20',
    high: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20',
    medium: 'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border-yellow-500/20',
    low: 'bg-blue-500/10 text-blue-700 dark:text-blue-400 border-blue-500/20',
    info: 'bg-gray-500/10 text-gray-700 dark:text-gray-300 border-gray-500/20',
  };

  const severityIcon = {
    critical: <FiAlertTriangle className="text-red-600" />,
    high: <FiAlertTriangle className="text-orange-600" />,
    medium: <FiAlertTriangle className="text-yellow-600" />,
    low: <FiInfo className="text-blue-600" />,
    info: <FiInfo className="text-gray-600" />,
  };

  const confidence = Number(vulnerability.confidence ?? 0);
  const cvssScore = vulnerability.cvss_score != null ? Number(vulnerability.cvss_score) : null;
  const isVerified = Boolean(vulnerability.is_verified);

  const confidenceCls =
    confidence >= 75
      ? 'bg-green-500/10 text-green-700 dark:text-green-400 border-green-500/20'
      : confidence >= 55
      ? 'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border-yellow-500/20'
      : 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20';

  const handleVerify = async () => {
    if (!onVerify) return;
    try {
      setVerifying(true);
      await onVerify(vulnerability.id);
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="p-6 hover:bg-gray-50 dark:hover:bg-gray-900/30 transition">
      <div className="flex items-start gap-4 min-w-0">
        <div className="text-2xl flex-shrink-0">{severityIcon[vulnerability.severity]}</div>
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between mb-2 gap-2 flex-wrap">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white break-words">{vulnerability.title}</h3>
            <div className="flex items-center gap-2 flex-wrap">
              {isVerified && (
                <span className="px-2 py-0.5 rounded-full text-xs font-semibold border bg-green-500/10 text-green-700 dark:text-green-400 border-green-500/20 flex items-center gap-1">
                  <FiShield size={11} /> Verified
                </span>
              )}
              <span
                className={`px-3 py-1 rounded-full text-xs font-semibold border ${
                  severityColors[vulnerability.severity]
                }`}
              >
                {vulnerability.severity.toUpperCase()}
              </span>
            </div>
          </div>

          <p className="text-gray-600 dark:text-gray-300 mb-3 break-words">{vulnerability.description}</p>

          <div className="flex flex-wrap gap-4 text-sm text-gray-600 dark:text-gray-300 mb-3">
            <div>
              <span className="font-medium">Detector:</span> {vulnerability.detector}
            </div>
            {vulnerability.url && (
              <div>
                <span className="font-medium">URL:</span>{' '}
                <a
                  href={vulnerability.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:underline dark:text-blue-400 break-all"
                >
                  {vulnerability.url}
                </a>
              </div>
            )}
          </div>

          {/* Scoring badges */}
          <div className="flex flex-wrap gap-2 mb-3">
            {confidence > 0 && (
              <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${confidenceCls}`}>
                Confidence: {confidence}%
                {vulnerability.confidence_label ? ` (${vulnerability.confidence_label})` : ''}
              </span>
            )}
            {cvssScore != null && (
              <span className="px-2 py-0.5 rounded text-xs font-semibold border bg-purple-500/10 text-purple-700 dark:text-purple-400 border-purple-500/20">
                CVSS: {cvssScore.toFixed(1)}
              </span>
            )}
          </div>

          {expanded && (
            <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700 space-y-3">
              {vulnerability.evidence && (
                <div>
                  <div className="font-semibold text-gray-900 dark:text-white mb-1">Evidence:</div>
                  <pre className="bg-gray-100 dark:bg-gray-950/40 p-3 rounded text-xs overflow-x-auto whitespace-pre-wrap break-words text-gray-900 dark:text-gray-100">
                    {vulnerability.evidence}
                  </pre>
                </div>
              )}
              {vulnerability.payload && (
                <div>
                  <div className="font-semibold text-gray-900 dark:text-white mb-1">Payload:</div>
                  <pre className="bg-gray-100 dark:bg-gray-950/40 p-3 rounded text-xs overflow-x-auto whitespace-pre-wrap break-words text-gray-900 dark:text-gray-100">
                    {vulnerability.payload}
                  </pre>
                </div>
              )}
              {vulnerability.status_code && (
                <div className="text-gray-700 dark:text-gray-200">
                  <span className="font-semibold">Status Code:</span> {vulnerability.status_code}
                </div>
              )}
              {vulnerability.response_time && (
                <div className="text-gray-700 dark:text-gray-200">
                  <span className="font-semibold">Response Time:</span>{' '}
                  {vulnerability.response_time}ms
                </div>
              )}
              {vulnerability.notes && (
                <div className="text-gray-700 dark:text-gray-200">
                  <span className="font-semibold">Notes:</span> {vulnerability.notes}
                </div>
              )}
            </div>
          )}

          <div className="mt-3 flex items-center gap-4">
            <button
              onClick={() => setExpanded(!expanded)}
              className="text-sm text-primary hover:text-primary-600 font-semibold"
            >
              {expanded ? 'Show Less' : 'Show More'}
            </button>
            {onVerify && (
              <button
                onClick={handleVerify}
                disabled={verifying}
                className={`text-sm font-semibold flex items-center gap-1 transition-colors disabled:opacity-50 ${
                  isVerified
                    ? 'text-green-600 dark:text-green-400 hover:text-green-700'
                    : 'text-gray-500 dark:text-gray-400 hover:text-green-600 dark:hover:text-green-400'
                }`}
                title={isVerified ? 'Mark as unverified' : 'Mark as verified'}
              >
                <FiShield size={13} />
                {verifying ? 'Saving…' : isVerified ? 'Verified' : 'Mark Verified'}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanDetails;
