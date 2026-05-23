import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { FiPlay, FiLoader, FiCheckCircle, FiLock, FiSearch } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import LoadingState from '../components/states/LoadingState';
import ScanConsentGate from '../components/ScanConsentGate';
import UpgradeModal from '../components/UpgradeModal';
import DonationModal, { isDonationSnoozed } from '../components/DonationModal';
import FieldError from '../components/forms/FieldError';
import { useToast } from '../contexts/ToastContext';
import { getDetectorCategoryIcon } from '../lib/icons';
import { isNonEmpty } from '../lib/validation';
import ScanOptionsPanel from '../components/scans/ScanOptionsPanel';
import MobileUploadPanel from '../components/scans/MobileUploadPanel';
import NmapOptionsPanel from '../components/scans/NmapOptionsPanel';
import api from '../services/api';
import { domainVerifyService } from '../services/api';
import useScanWebsocket from '../hooks/useScanWebsocket';
import { isWsEnabled } from '../lib/websocket';

const formatEtaSeconds = (value) => {
  const s = Number(value);
  if (!Number.isFinite(s) || s <= 0) return null;
  const mins = Math.floor(s / 60);
  const secs = Math.floor(s % 60);
  if (mins <= 0) return `${secs}s`;
  return `${mins}m ${secs}s`;
};

const DetectorCategoryScan = () => {
  const { categoryId } = useParams(); // Match route param name
  const navigate = useNavigate();
  const toast = useToast();
  
  const [category, setCategory] = useState(null);
  const [detectors, setDetectors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  
  // Scan progress state
  const [activeScan, setActiveScan] = useState(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('');
  const [pollInterval, setPollInterval] = useState(null);
  const [liveScanDetails, setLiveScanDetails] = useState(null);
  const [showDonation, setShowDonation] = useState(false);
  const [completedScanId, setCompletedScanId] = useState(null);
  const [cancelling, setCancelling] = useState(false);

  const scanId = activeScan?.id;
  const { connected: wsConnected, lastEvent } = useScanWebsocket(scanId, {
    enabled: !!scanId && isWsEnabled(),
  });
  
  // Form state
  const [target, setTarget] = useState('');
  const [selectedDetectors, setSelectedDetectors] = useState([]);
  const [detectorQuery, setDetectorQuery] = useState('');
  const [touched, setTouched] = useState({ target: false, detectors: false });
  const [acceptDisclaimer, setAcceptDisclaimer] = useState(false);
  const [consentTouched, setConsentTouched] = useState(false);
  const [allowDestructive, setAllowDestructive] = useState(true);
  const [options, setOptions] = useState({ timeout: 15, scan_mode: 'normal', use_subfinder: false, use_amass: false });
  const [upgradeModal, setUpgradeModal] = useState(null);

  const filteredDetectors = useMemo(() => {
    const q = detectorQuery.trim().toLowerCase();
    if (!q) return detectors;
    return (detectors || []).filter((d) => String(d?.name || '').toLowerCase().includes(q));
  }, [detectors, detectorQuery]);

  const targetError = useMemo(() => {
    if (!isNonEmpty(target)) return 'Please enter a target URL.';
    return null;
  }, [target]);

  const detectorsError = useMemo(() => {
    if (selectedDetectors.length === 0) return 'Please select at least one detector.';
    return null;
  }, [selectedDetectors.length]);

  const fetchCategoryData = useCallback(async () => {
    try {
      // Fetch detector categories with access info
      const response = await api.get('/detector-categories/');
      
      const foundCategory = response.data.categories.find(c => c.key === categoryId);
      if (!foundCategory) {
        console.error('Category not found:', categoryId, 'Available:', response.data.categories.map(c => c.key));
        toast.error(`Category "${categoryId}" not found`);
        navigate('/dashboard');
        return;
      }
      
      setCategory(foundCategory);
      setDetectors(foundCategory.detectors || []);

      // Default: enable destructive checks (user can disable)
      setAllowDestructive(true);
      
      // Select all ALLOWED, NON-DANGEROUS detectors by default
      const allowedDetectorNames = foundCategory.detectors
        .filter(d => d.is_allowed && !d.is_dangerous)
        .map(d => d.name);
      setSelectedDetectors(allowedDetectorNames);
      
    } catch (err) {
      console.error('Failed to load category:', err);
      toast.error('Failed to load scanner data');
    } finally {
      setLoading(false);
    }
  }, [categoryId, navigate, toast]);

  useEffect(() => {
    fetchCategoryData();
  }, [fetchCategoryData]);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollInterval) {
        clearInterval(pollInterval);
      }
    };
  }, [pollInterval]);

  useEffect(() => {
    if (!lastEvent) return;
    const payload = lastEvent?.data;
    if (!payload) return;

    if (
      lastEvent.type === 'scan_status' ||
      lastEvent.type === 'scan_update' ||
      lastEvent.type === 'scan_complete' ||
      lastEvent.type === 'scan_error'
    ) {
      setLiveScanDetails((prev) => ({ ...(prev || {}), ...payload }));
      setActiveScan((prev) => ({ ...(prev || {}), ...payload, id: (prev || {})?.id || scanId }));
      if (typeof payload?.progress !== 'undefined') setScanProgress(payload.progress || 0);
      if (payload?.current_step || payload?.status) setScanStatus(payload.current_step || payload.status);
      if (payload?.status === 'completed' || payload?.status === 'failed' || payload?.status === 'stopped') {
        setScanning(false);
      }
    }
  }, [lastEvent, scanId]);

  const pollScanStatus = async (scanId) => {
    try {
      const response = await api.get(`/scans/${scanId}/`);
      
      const scan = response.data;
      setLiveScanDetails(scan);
      setScanProgress(scan.progress || 0);
      setScanStatus(scan.current_step || scan.status);
      
      // Stop polling if scan is complete
      if (scan.status === 'completed' || scan.status === 'failed' || scan.status === 'stopped') {
        if (pollInterval) {
          clearInterval(pollInterval);
        }
        setPollInterval(null);
        setScanning(false);
        setActiveScan(scan);
        
        if (scan.status === 'completed') {
          setCompletedScanId(scan.id);
          if (!isDonationSnoozed()) {
            setTimeout(() => setShowDonation(true), 500);
          } else {
            setTimeout(() => navigate(`/results/${scan.id}`), 500);
          }
        }
      }
    } catch (err) {
      console.error('Failed to poll scan status:', err);
    }
  };

  const handleCancelScan = async () => {
    if (!scanId) return;

    const status = String(liveScanDetails?.status || activeScan?.status || '').toLowerCase();
    if (status && status !== 'running' && status !== 'pending') {
      toast.info('This scan is already finished.');
      return;
    }

    try {
      setCancelling(true);
      await api.post(`/scans/stop/${scanId}/`);
      setScanStatus('Stopping scan...');
      toast.success('Scan stop requested');
    } catch (err) {
      const message =
        err?.response?.data?.detail ||
        err?.response?.data?.error ||
        err?.message ||
        'Failed to stop scan';
      toast.error(message);
    } finally {
      setCancelling(false);
    }
  };

  const extractApex = (url) => {
    try {
      const hostname = new URL(url).hostname.replace(/^www\./, '');
      const parts = hostname.split('.');
      return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
    } catch (_) {
      return url;
    }
  };

  const toggleDetector = async (detectorName, isAllowed) => {
    if (!isAllowed) return;
    const isChecking = !selectedDetectors.includes(detectorName);
    const detector = detectors.find(d => d.name === detectorName);

    if (detector?.is_dangerous && isChecking) {
      if (!target) {
        toast.error('Enter the target URL first before enabling dangerous detectors.');
        return;
      }
      try {
        const res = await domainVerifyService.list();
        const verified = res.data || [];
        const apex = extractApex(target);
        const isVerified = verified.some(
          v => v.status === 'verified' && v.domain === apex
        );
        if (!isVerified) {
          setUpgradeModal({
            title: 'Domain verification required',
            message: `Verify ownership of "${apex || target}" to enable dangerous detectors.`,
            bullets: ['Go to Verified Domains', 'Complete the HTTP or DNS challenge', 'Return here and enable the detector'],
            ctaHref: '/domain-verify',
            ctaLabel: 'Verify Domain',
          });
          return;
        }
      } catch (_) {
        setUpgradeModal({
          title: 'Domain verification required',
          message: 'Please verify ownership of the target domain before enabling dangerous detectors.',
          bullets: [],
          ctaHref: '/domain-verify',
          ctaLabel: 'Verify Domain',
        });
        return;
      }
    }

    if (selectedDetectors.includes(detectorName)) {
      setSelectedDetectors(selectedDetectors.filter(d => d !== detectorName));
    } else {
      setSelectedDetectors([...selectedDetectors, detectorName]);
    }
  };

  const selectAll = () => {
    // Select All skips dangerous detectors
    const allowedDetectors = detectors.filter(d => d.is_allowed && !d.is_dangerous).map(d => d.name);
    setSelectedDetectors(allowedDetectors);
  };

  const deselectAll = () => {
    setSelectedDetectors([]);
  };

  const handleStartScan = async (e) => {
    e.preventDefault();

    setTouched({ target: true, detectors: true });

    if (targetError || detectorsError) {
      return;
    }

    if (!acceptDisclaimer) {
      setConsentTouched(true);
      return;
    }

    setScanning(true);
    setScanProgress(0);
    setScanStatus('Starting scan...');
    setActiveScan(null);

    try {
      const response = await api.post('/scans/start-category-scan/', {
        target: target,
        category: category?.key || categoryId,
        consent: true,
        detectors: selectedDetectors,
        options: {
          ...options,
          allow_destructive: allowDestructive,
        },
      });

      const scanId = response.data.id;
      setActiveScan(response.data);
      
      // Start polling for progress
      const interval = setInterval(() => pollScanStatus(scanId), 2000);
      setPollInterval(interval);
      
    } catch (err) {
      console.error('Scan failed:', err);
      setScanning(false);
      setScanProgress(0);
      setScanStatus('');
      
      if (err.response?.status === 403 && err.response?.data?.requires_email_verification) {
        setUpgradeModal({
          title: 'Email verification required',
          message: err.response?.data?.error || 'Please verify your email to unlock dangerous scanners.',
          bullets: ['Open your email and click the verification link', 'If needed: Profile → request verification email'],
        });
      } else if (err.response?.status === 403 && err.response?.data?.requires_domain_verification) {
        const domain = err.response.data.domain || 'this domain';
        setUpgradeModal({
          title: 'Domain verification required',
          message: `You must verify ownership of "${domain}" before scanning it.`,
          bullets: ['Go to Verified Domains', 'Add your domain and complete the HTTP or DNS challenge', 'Then retry the scan'],
          ctaHref: '/domain-verify',
          ctaLabel: 'Verify Domain',
        });
      } else if (err.response?.status === 403) {
        setUpgradeModal({
          title: 'Action blocked',
          message: err.response?.data?.detail || err.response?.data?.error || 'This action is not allowed.',
          bullets: ['Check your configuration', 'Try again in a moment'],
        });
      } else {
        const status = err.response?.status;
        const message = err.response?.data?.detail || err.response?.data?.error || 'Failed to start scan';
        if (status === 503) {
          toast.error('Scanning temporarily unavailable. Please try again shortly.');
        } else if (status === 429) {
          toast.error('Too many requests. Please wait and try again.');
        } else {
          toast.error(message);
        }
      }
    }
  };

  if (loading) {
    return (
      <DashboardLayout>
        <LoadingState title="Loading category" subtitle="Fetching detectors and access rules…" />
      </DashboardLayout>
    );
  }

  const showVulnEnum = (category?.key || categoryId) === 'vuln';

  return (
    <DashboardLayout>
      {showDonation && (
        <DonationModal
          scanId={completedScanId}
          onClose={() => setShowDonation(false)}
        />
      )}
      <div className="ui-page">
        {/* Header */}
        <div className="mb-6 lg:mb-8">
          <div className="flex items-center gap-2 lg:gap-3 mb-2">
            <span className="text-3xl lg:text-4xl text-primary">
              {getDetectorCategoryIcon(category.key, { size: 36 })}
            </span>
            <h1 className="ui-title">{category.name}</h1>
          </div>
          <p className="ui-subtitle">
            {category.description}
          </p>
        </div>

        {/* Mobile category: show only APK/IPA upload panel */}
        {(category?.key || categoryId) === 'mobile' ? (
          <MobileUploadPanel />
        ) : (

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 lg:gap-6">
          {/* Detector Selection */}
          <div className="lg:col-span-1 order-2 lg:order-1">
            <div className="ui-card p-4 lg:p-6">
              <div className="flex items-center justify-between mb-3 lg:mb-4">
                <h3 className="text-base lg:text-lg font-semibold text-gray-900 dark:text-white">
                  Detectors <span className="text-sm text-gray-500 dark:text-gray-400">({detectors.length})</span>
                </h3>
                <div className="flex gap-2">
                  <button
                    onClick={selectAll}
                    className="text-xs px-2 py-1 text-primary hover:underline"
                  >
                    All
                  </button>
                  <button
                    onClick={deselectAll}
                    className="text-xs px-2 py-1 text-primary hover:underline"
                  >
                    None
                  </button>
                </div>
              </div>

              <div className="mb-3">
                <div className="relative">
                  <FiSearch className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    value={detectorQuery}
                    onChange={(e) => setDetectorQuery(e.target.value)}
                    placeholder="Search detectors…"
                    className="ui-input pl-9"
                  />
                </div>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Allowed: {detectors.filter((d) => d.is_allowed).length} · Locked: {detectors.filter((d) => !d.is_allowed).length}
                </p>
              </div>
              
              <div className="space-y-2 max-h-64 lg:max-h-96 overflow-y-auto">
                {filteredDetectors.map((detector) => {
                  const isSelected = selectedDetectors.includes(detector.name);
                  const isAllowed = detector.is_allowed;
                  
                  return (
                    <label
                      key={detector.name}
                      className={`flex items-start gap-2 lg:gap-3 p-2 lg:p-3 rounded-lg cursor-pointer transition ${
                        isAllowed
                          ? 'hover:bg-gray-50 dark:hover:bg-gray-800/40'
                          : 'bg-gray-100 dark:bg-gray-900/50 opacity-60'
                      }`}
                      onClick={() => toggleDetector(detector.name, isAllowed)}
                    >
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => {}}
                        disabled={!isAllowed}
                        className="mt-1"
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs lg:text-sm font-medium truncate text-gray-900 dark:text-white">
                            {detector.name.replace(/_/g, ' ').replace('detector', '').trim()}
                          </span>
                          {!isAllowed && <FiLock className="w-3 h-3 text-yellow-600 flex-shrink-0" />}
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Scan Form */}
          <div className="lg:col-span-2 order-1 lg:order-2">
            <form onSubmit={handleStartScan} className="ui-card p-4 lg:p-6">
              <h3 className="text-base lg:text-lg font-semibold mb-3 lg:mb-4 text-gray-900 dark:text-white">Scan Configuration</h3>
              
              {/* Target URL */}
              <div className="mb-3 lg:mb-4">
                <label className="block text-xs lg:text-sm font-medium mb-2 text-gray-700 dark:text-gray-200">
                  Target URL *
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
                  required
                />
                <FieldError
                  id="detector-category-scan-target-error"
                  message={touched.target ? targetError : null}
                />
              </div>

              {/* Selected Detectors Summary */}
              <div className="mb-3 lg:mb-4">
                <label className="block text-xs lg:text-sm font-medium mb-2 text-gray-700 dark:text-gray-200">
                  Selected Detectors
                </label>
                <div className="p-2 lg:p-3 rounded-lg border bg-gray-50 dark:bg-gray-900/40 border-gray-200 dark:border-gray-700">
                  <span className="text-xs lg:text-sm text-gray-700 dark:text-gray-200">
                    {selectedDetectors.length} of {detectors.filter(d => d.is_allowed).length} available detectors selected
                  </span>
                </div>
                <FieldError
                  id="detector-category-scan-detectors-error"
                  message={touched.detectors ? detectorsError : null}
                />
              </div>

              <div className="mb-3 lg:mb-4">
                <ScanOptionsPanel
                  value={options}
                  onChange={setOptions}
                  disabled={scanning}
                  title="Scan configuration"
                  defaultOpen={false}
                  showTimeout
                  showScanMode
                />
              </div>

              {selectedDetectors.includes('nmap_detector') && (
                <div className="mb-3 lg:mb-4">
                  <NmapOptionsPanel
                    value={options}
                    onChange={setOptions}
                    disabled={scanning}
                  />
                </div>
              )}

              {showVulnEnum && (
                <div className="mb-3 lg:mb-4 p-3 rounded-lg border bg-gray-50 dark:bg-gray-900/40 border-gray-200 dark:border-gray-700">
                  <div className="text-sm font-semibold text-gray-900 dark:text-white mb-2">
                    Vuln pre-scan (optional)
                  </div>
                  <label className="flex items-start gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={!!options.use_subfinder}
                      onChange={(e) => setOptions((prev) => ({ ...prev, use_subfinder: e.target.checked }))}
                      className="mt-1"
                      disabled={scanning}
                    />
                    <span className="text-xs lg:text-sm text-gray-700 dark:text-gray-200">
                      Run <strong>subfinder</strong> first and feed discovered subdomains into the Vuln scan.
                    </span>
                  </label>

                  <label className="flex items-start gap-2 cursor-pointer mt-2">
                    <input
                      type="checkbox"
                      checked={!!options.use_amass}
                      onChange={(e) => setOptions((prev) => ({ ...prev, use_amass: e.target.checked }))}
                      className="mt-1"
                      disabled={scanning}
                    />
                    <span className="text-xs lg:text-sm text-gray-700 dark:text-gray-200">
                      Run <strong>amass</strong> (passive) first and feed discovered subdomains into the Vuln scan.
                    </span>
                  </label>

                  <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
                    These steps are visible in scan progress and saved into results (pre-scan summary + subdomain count).
                  </p>
                </div>
              )}

              <div className="mb-4 lg:mb-6">
                <ScanConsentGate
                  checked={acceptDisclaimer}
                  onChange={(next) => {
                    setConsentTouched(true);
                    setAcceptDisclaimer(next);
                  }}
                  disabled={scanning}
                />

                <FieldError
                  id="detector-category-scan-consent-error"
                  message={
                    consentTouched && !acceptDisclaimer
                      ? 'Please confirm you have authorization to scan this target.'
                      : null
                  }
                />

                <label className="flex items-start gap-2 lg:gap-3 cursor-pointer mt-3">
                  <input
                    type="checkbox"
                    checked={allowDestructive}
                    onChange={(e) => setAllowDestructive(e.target.checked)}
                    className="mt-1"
                    disabled={scanning}
                  />
                  <span className="text-xs lg:text-sm text-gray-700 dark:text-gray-200">
                    Enable aggressive checks (backup file probing, parameter fuzzing). Some detectors will skip unless this is enabled.
                  </span>
                </label>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={scanning || selectedDetectors.length === 0 || !acceptDisclaimer}
                className="ui-btn ui-btn-primary w-full justify-center flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {scanning ? (
                  <>
                    <FiLoader className="w-4 lg:w-5 h-4 lg:h-5 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <FiPlay className="w-4 lg:w-5 h-4 lg:h-5" />
                    Start Scan
                  </>
                )}
              </button>

              {/* Scan Progress */}
              {scanning && activeScan && (
                <div className="mt-6 p-4 rounded-lg border-2 bg-blue-50 dark:bg-blue-900/10 border-blue-300 dark:border-blue-800/40">
                  <div className="flex items-center gap-2 mb-3">
                    <FiLoader className="w-5 h-5 animate-spin text-blue-600" />
                    <h4 className="text-lg font-semibold text-gray-900 dark:text-white">Scan in Progress</h4>
                    <button
                      type="button"
                      onClick={handleCancelScan}
                      disabled={cancelling || !scanId}
                      className="ml-auto ui-btn bg-white text-red-600 border border-red-200 hover:bg-red-50 disabled:opacity-50 dark:bg-gray-900 dark:border-red-800/40 dark:hover:bg-red-900/20"
                    >
                      {cancelling ? 'Stopping…' : 'Stop Scan'}
                    </button>
                    <span className="ml-auto text-xs text-gray-500 dark:text-gray-400">
                      {wsConnected ? 'Live updates connected' : 'Live updates unavailable — polling'}
                    </span>
                  </div>
                  
                  {/* Progress Bar */}
                  <div className="mb-3">
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-gray-600 dark:text-gray-300">Progress</span>
                      <span className="font-semibold text-blue-600">{scanProgress}%</span>
                    </div>
                    <div className="h-3 rounded-full overflow-hidden bg-gray-200 dark:bg-gray-700">
                      <div 
                        className="h-full bg-gradient-to-r from-blue-500 to-purple-500 transition-all duration-500"
                        style={{ width: `${scanProgress}%` }}
                      />
                    </div>
                  </div>
                  
                  {/* Current Step */}
                  <div className="text-sm text-gray-600 dark:text-gray-300">
                    <strong>Status:</strong> {scanStatus}
                  </div>

                  {(liveScanDetails?.current_detector || liveScanDetails?.current_url || liveScanDetails?.eta_seconds) && (
                    <div className="mt-2 grid grid-cols-1 gap-1 text-xs text-gray-600 dark:text-gray-300">
                      {liveScanDetails?.current_detector && (
                        <div>
                          <strong>Detector:</strong> {liveScanDetails.current_detector}
                        </div>
                      )}
                      {liveScanDetails?.current_url && (
                        <div className="truncate">
                          <strong>URL:</strong> {liveScanDetails.current_url}
                        </div>
                      )}
                      {formatEtaSeconds(liveScanDetails?.eta_seconds) && (
                        <div>
                          <strong>ETA:</strong> {formatEtaSeconds(liveScanDetails.eta_seconds)}
                        </div>
                      )}
                    </div>
                  )}

                  {liveScanDetails?.raw_results?.pre_scan && (
                    <div className="mt-2 text-xs text-gray-600 dark:text-gray-300">
                      <strong>Pre-scan:</strong>{' '}
                      {liveScanDetails.raw_results.pre_scan.domain ? (
                        <span>
                          {liveScanDetails.raw_results.pre_scan.domain} ·{' '}
                          {(liveScanDetails.raw_results.pre_scan.subdomains || []).length} subdomains
                        </span>
                      ) : (
                        <span>started</span>
                      )}
                    </div>
                  )}

                  {(() => {
                    const metaWarnings = Array.isArray(liveScanDetails?.raw_results?.metadata?.warnings)
                      ? liveScanDetails.raw_results.metadata.warnings
                      : [];
                    const detectorErrors = Array.isArray(liveScanDetails?.raw_results?.metadata?.detectors?.errors)
                      ? liveScanDetails.raw_results.metadata.detectors.errors
                      : [];
                    const fatal = liveScanDetails?.raw_results?.metadata?.fatal_error;
                    const total = metaWarnings.length + detectorErrors.length + (fatal ? 1 : 0);
                    if (!total) return null;
                    return (
                      <div className="mt-2 text-xs text-red-700 dark:text-red-300">
                        <strong>Warnings:</strong> {total} (see results for details)
                      </div>
                    );
                  })()}
                  
                  {/* Scan Info */}
                  <div className="mt-3 pt-3 border-t border-gray-300 dark:border-gray-600">
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div>
                        <span className="text-gray-500 dark:text-gray-400">Scan ID:</span>
                        <span className="ml-2 font-mono">{activeScan.id}</span>
                      </div>
                      <div>
                        <span className="text-gray-500 dark:text-gray-400">Target:</span>
                        <span className="ml-2 truncate">{activeScan.target}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Completed Scan */}
              {!scanning && activeScan && activeScan.status === 'completed' && (
                <div className="mt-6 p-4 rounded-lg border-2 bg-green-50 dark:bg-green-900/10 border-green-300 dark:border-green-800/40">
                  <div className="flex items-center gap-2 mb-3">
                    <FiCheckCircle className="w-5 h-5 text-green-600" />
                    <h4 className="text-lg font-semibold text-green-600">Scan Completed!</h4>
                  </div>
                  <p className="mb-4 text-gray-700 dark:text-gray-200">
                    Found <strong>{activeScan.vulnerabilities_found || 0}</strong> vulnerabilities
                  </p>
                  <Link
                    to={`/results/${activeScan.id}`}
                    className="ui-btn bg-green-600 hover:bg-green-700 text-white inline-flex items-center gap-2"
                  >
                    View Results →
                  </Link>
                </div>
              )}
            </form>

            <UpgradeModal
              open={!!upgradeModal}
              title={upgradeModal?.title}
              message={upgradeModal?.message}
              bullets={upgradeModal?.bullets}
              ctaHref={upgradeModal?.ctaHref}
              ctaLabel={upgradeModal?.ctaLabel}
              onClose={() => setUpgradeModal(null)}
            />
          </div>
        </div>
        )} {/* end non-mobile grid */}
      </div>
    </DashboardLayout>
  );
};

export default DetectorCategoryScan;
