import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { FiPlay, FiLoader, FiCheckCircle, FiSettings, FiSearch } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import LoadingState from '../components/states/LoadingState';
import ErrorState from '../components/states/ErrorState';
import ScanConsentGate from '../components/ScanConsentGate';
import SubscriptionUsageHeader from '../components/SubscriptionUsageHeader';
import UpgradeModal from '../components/UpgradeModal';
import FieldError from '../components/forms/FieldError';
import { useToast } from '../contexts/ToastContext';
import { getScanCategoryIcon } from '../lib/icons';
import { isNonEmpty } from '../lib/validation';
import useScanWebsocket from '../hooks/useScanWebsocket';
import { isWsEnabled } from '../lib/websocket';
import api from '../services/api';
import { domainVerifyService } from '../services/api';

const formatEtaSeconds = (value) => {
  const s = Number(value);
  if (!Number.isFinite(s) || s <= 0) return null;
  const mins = Math.floor(s / 60);
  const secs = Math.floor(s % 60);
  if (mins <= 0) return `${secs}s`;
  return `${mins}m ${secs}s`;
};

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
    const reason = entry?.reason;
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

const CategoryScan = () => {
  const { categoryId } = useParams();
  const navigate = useNavigate();
  
  const [category, setCategory] = useState(null);
  const [detectors, setDetectors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('');
  const [results, setResults] = useState(null);
  const [activeScanId, setActiveScanId] = useState(null);
  const [liveScanDetails, setLiveScanDetails] = useState(null);
  const [cancelling, setCancelling] = useState(false);
  const [subscription, setSubscription] = useState(null);
  const [hasAccess, setHasAccess] = useState(null); // null = loading, true = access, false = no access
  const [plans, setPlans] = useState([]); // For upgrade page
  const [upgradeModal, setUpgradeModal] = useState(null);
  const [showDetectorDetails, setShowDetectorDetails] = useState(false);
  const pollIntervalRef = useRef(null);
  
  // Form state
  const [target, setTarget] = useState('');
  const [selectedDetectors, setSelectedDetectors] = useState([]);
  const [detectorQuery, setDetectorQuery] = useState('');
  const [touched, setTouched] = useState({ target: false, detectors: false });
  const [acceptDisclaimer, setAcceptDisclaimer] = useState(false);
  const [consentTouched, setConsentTouched] = useState(false);
  const toast = useToast();
  const [options, setOptions] = useState({
    depth: 3,
    timeout: 30,
    follow_redirects: true,
    verify_ssl: true,
    nuclei_templates: '',
    nuclei_severity: 'low,medium,high,critical',
    cve_db_path: '',
  });

  const { connected: wsConnected, lastEvent } = useScanWebsocket(activeScanId, {
    enabled: !!activeScanId && isWsEnabled(),
  });

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
      if (typeof payload?.progress !== 'undefined') setScanProgress(payload.progress || 0);
      if (payload?.current_step || payload?.status) setScanStatus(payload.current_step || payload.status);

      if (payload?.status === 'completed' || payload?.status === 'failed' || payload?.status === 'stopped') {
        setScanning(false);
        setResults((prev) => ({ ...(prev || {}), ...payload }));
        if (payload?.status === 'completed' && activeScanId) {
          fetchVulnerabilities(activeScanId);
        }
      }
    }
  }, [lastEvent, activeScanId]);

  useEffect(() => () => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
  }, []);

  const fetchCategoryData = useCallback(async () => {
    try {
      // Fetch all categories
      const categoriesResponse = await api.get('/scan-categories/');
      
      const foundCategory = categoriesResponse.data.find(c => c.name === categoryId);
      if (!foundCategory) {
        toast.error('Category not found');
        navigate('/dashboard');
        return;
      }
      
      setCategory(foundCategory);
      
      // Fetch detectors for this category
      const detectorsResponse = await api.get(`/scan-categories/${foundCategory.id}/detectors/`);
      
      setDetectors(detectorsResponse.data);
      // Select all NON-dangerous detectors by default
      setSelectedDetectors(detectorsResponse.data.filter(d => !d.is_dangerous).map(d => d.id));
      
    } catch (err) {
      console.error('Failed to load category:', err);
      toast.error('Failed to load scanner data');
    } finally {
      setLoading(false);
    }
  }, [categoryId, navigate, toast]);

  const fetchSubscription = useCallback(async () => {
    try {
      const response = await api.get('/subscriptions/current/');
      setSubscription(response.data);
    } catch (err) {
      console.error('Failed to fetch subscription:', err);
    }
  }, []);

  const fetchPlans = useCallback(async () => {
    try {
      const response = await api.get('/plans/');
      setPlans(response.data);
    } catch (err) {
      console.error('Failed to fetch plans:', err);
    }
  }, []);

  useEffect(() => {
    fetchCategoryData();
    fetchSubscription();
    fetchPlans();
  }, [fetchCategoryData, fetchSubscription, fetchPlans]);

  // Check access when both category and subscription are loaded
  useEffect(() => {
    if (category && subscription) {
      const planHierarchy = { 'free': 0, 'pro': 1, 'pro plan': 1, 'enterprise': 2 };
      // subscription has plan_name, not plan.name
      const userPlanName = (subscription.plan_name || subscription.plan?.name || 'free').toLowerCase();
      const userPlanLevel = planHierarchy[userPlanName] || 0;
      const requiredPlanLevel = planHierarchy[category.required_plan?.toLowerCase()] || 0;
      
      console.log('Access check:', {
        category: category.name,
        required: category.required_plan,
        userPlan: userPlanName,
        userLevel: userPlanLevel,
        requiredLevel: requiredPlanLevel,
        hasAccess: userPlanLevel >= requiredPlanLevel
      });
      
      setHasAccess(userPlanLevel >= requiredPlanLevel);
    } else if (category && !subscription) {
      // If subscription hasn't loaded yet, check if it's a free category
      const isFree = category.required_plan?.toLowerCase() === 'free';
      console.log('No subscription loaded, category:', category.name, 'is free?', isFree);
      setHasAccess(isFree);
    }
  }, [category, subscription]);

  const handleStartScan = async (e) => {
    e.preventDefault();

    setTouched({ target: true, detectors: true });

    if (!isNonEmpty(target) || selectedDetectors.length === 0) {
      return;
    }

    if (!acceptDisclaimer) {
      setConsentTouched(true);
      return;
    }

    setScanning(true);
    setScanProgress(0);
    setScanStatus('Initializing scan...');
    setResults(null);
    setActiveScanId(null);
    setLiveScanDetails(null);

    try {
      // Convert detector IDs to names
      const detectorNames = detectors
        .filter(d => selectedDetectors.includes(d.id))
        .map(d => d.name);
      
      const response = await api.post('/scans/start-category-scan/', {
        category: category.id,
        target: target,
        consent: true,
        detectors: detectorNames,
        options: options,
      });

      const scanId = response.data.id;

      setActiveScanId(scanId);
      setLiveScanDetails(response.data);
      
      // Start polling for progress
      pollScanProgress(scanId);
      
    } catch (err) {
      console.error('Scan failed:', err);
      setScanning(false);
      
      // Handle 402 Payment Required (daily limit exceeded)
      if (err.response?.status === 402) {
        setUpgradeModal({
          title: 'Scan limit reached',
          message: err.response?.data?.error || 'Your plan scan limit has been reached.',
          bullets: ['Higher daily/monthly limits', 'More detectors & categories', 'Priority support'],
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
          title: 'Upgrade required',
          message: err.response?.data?.detail || err.response?.data?.error || 'This action requires a higher plan.',
          bullets: ['Higher limits', 'Teams & integrations', 'Advanced scanners'],
        });
      } else {
        const status = err.response?.status;
        const message = err.response?.data?.error || err.response?.data?.detail || 'Failed to start scan';
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

  const pollScanProgress = async (scanId) => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
    }

    const interval = setInterval(async () => {
      try {
        const response = await api.get(`/scans/${scanId}/`);
        
        const scan = response.data;
        setLiveScanDetails(scan);
        setScanStatus(scan.current_step || scan.status);
        setScanProgress(scan.progress || 0);
        
        if (
          scan.status === 'completed' ||
          scan.status === 'failed' ||
          scan.status === 'stopped'
        ) {
          clearInterval(interval);
          if (pollIntervalRef.current === interval) {
            pollIntervalRef.current = null;
          }
          setScanning(false);
          setResults(scan);
          
          if (scan.status === 'completed') {
            fetchVulnerabilities(scanId);
          }
        }
        
      } catch (err) {
        console.error('Failed to fetch scan progress:', err);
        clearInterval(interval);
        if (pollIntervalRef.current === interval) {
          pollIntervalRef.current = null;
        }
        setScanning(false);
      }
    }, 2000);

    pollIntervalRef.current = interval;
  };

  const handleCancelScan = async () => {
    if (!activeScanId) return;

    const status = String(liveScanDetails?.status || '').toLowerCase();
    if (status && status !== 'running' && status !== 'pending') {
      toast.info('This scan is already finished.');
      return;
    }

    try {
      setCancelling(true);
      await api.post(`/scans/stop/${activeScanId}/`);
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

  const fetchVulnerabilities = async (scanId) => {
    try {
      const response = await api.get(`/scans/${scanId}/vulnerabilities/`);
      
      setResults(prev => ({ ...prev, vulnerabilities: response.data.results || [] }));
    } catch (err) {
      console.error('Failed to fetch vulnerabilities:', err);
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

  const toggleDetector = async (detectorId) => {
    const detector = detectors.find(d => d.id === detectorId);
    const isChecking = !selectedDetectors.includes(detectorId);

    if (detector?.is_dangerous && isChecking) {
      // Require domain verification before enabling a dangerous detector
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
        // If check fails, still block and let backend gate it
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

    setSelectedDetectors(prev =>
      prev.includes(detectorId)
        ? prev.filter(id => id !== detectorId)
        : [...prev, detectorId]
    );
  };

  const toggleAllDetectors = () => {
    if (selectedDetectors.length === detectors.length) {
      setSelectedDetectors([]);
    } else {
      // Select All skips dangerous detectors
      setSelectedDetectors(detectors.filter(d => !d.is_dangerous).map(d => d.id));
    }
  };

  if (loading) {
    return (
      <DashboardLayout>
        <LoadingState title="Loading scanner" subtitle="Preparing your scan configuration…" />
      </DashboardLayout>
    );
  }

  if (!category) {
    return (
      <DashboardLayout>
        <ErrorState
          title="Category not found"
          message="This scan category may have been removed or you may not have access."
          action={
            <button onClick={() => navigate('/dashboard')} className="ui-btn ui-btn-primary">
              Back to Dashboard
            </button>
          }
        />
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="ui-page">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-4 mb-2">
            <span className="text-4xl text-primary">{getScanCategoryIcon(category.name, { size: 36 })}</span>
            <h1 className="ui-title">{category.display_name}</h1>
            {category.required_plan !== 'free' && (
              <span className="px-3 py-1 bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-200 rounded-full text-sm font-semibold uppercase">
                {category.required_plan}
              </span>
            )}
          </div>
          <p className="text-gray-600 dark:text-gray-300">{category.description}</p>
        </div>

        {/* Show Upgrade UI if no access */}
        {hasAccess === false ? (
          <div className="bg-gradient-to-r from-purple-600 to-pink-600 text-white rounded-lg shadow-xl p-12 text-center">
            <div className="mb-6">
              <div className="inline-block p-4 bg-white bg-opacity-20 rounded-full mb-4">
                <svg className="w-16 h-16" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
                </svg>
              </div>
              <h2 className="text-3xl font-bold mb-4">Upgrade Required</h2>
              <p className="text-xl mb-2">
                {category.display_name} scanner requires a <span className="font-bold">{category.required_plan.toUpperCase()}</span> plan
              </p>
              <p className="text-white text-opacity-90 mb-8">
                You are currently on the <span className="font-semibold">{subscription?.plan?.display_name || 'Free'}</span> plan
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8 text-left">
              {plans.map((plan, index) => {
                const isFree = plan.price === 0 || plan.price === '0.00';
                const isPopular = plan.is_popular;
                
                return (
                  <div 
                    key={plan.id}
                    className={`rounded-lg p-6 ${
                      isPopular 
                        ? 'bg-white text-gray-900 shadow-2xl transform scale-105 border-4 border-yellow-400' 
                        : 'bg-white bg-opacity-10 backdrop-blur-sm'
                    }`}
                  >
                    {isPopular && (
                      <div className="text-center mb-2">
                        <span className="bg-yellow-400 text-yellow-900 px-3 py-1 rounded-full text-xs font-bold">RECOMMENDED</span>
                      </div>
                    )}
                    
                    <h3 className={`text-lg font-bold mb-2 ${isPopular ? 'text-gray-900' : ''}`}>
                      {plan.display_name}
                    </h3>
                    <div className={`text-2xl font-bold mb-4 ${isPopular ? 'text-gray-900' : ''}`}>
                      {isFree ? 'Free' : `$${plan.price}`}
                      <span className="text-sm">/month</span>
                    </div>
                    
                    <ul className={`space-y-2 text-sm ${isPopular ? 'text-gray-700' : ''}`}>
                      <li>✓ {plan.daily_scan_limit === -1 ? 'Unlimited' : plan.daily_scan_limit} scans per day</li>
                      {plan.features && plan.features.slice(0, 6).map((feature, idx) => (
                        <li key={idx}>✓ {feature}</li>
                      ))}
                    </ul>
                    
                    {!isFree && (
                      <button 
                        onClick={() => navigate('/pricing')}
                        className={`w-full mt-4 py-3 rounded-lg font-bold transition ${
                          isPopular
                            ? 'bg-gradient-to-r from-purple-600 to-pink-600 text-white hover:opacity-90'
                            : 'bg-white bg-opacity-20 hover:bg-opacity-30'
                        }`}
                      >
                        {plan.name === 'enterprise' ? 'Contact Sales' : `Upgrade to ${plan.display_name}`}
                      </button>
                    )}
                  </div>
                );
              })}
            </div>

            <button
              onClick={() => navigate('/dashboard')}
              className="px-6 py-3 bg-white bg-opacity-20 hover:bg-opacity-30 rounded-lg font-semibold transition"
            >
              Back to Dashboard
            </button>
          </div>
        ) : (
          /* Scanner Form - Show only if user has access */
          <>
          <SubscriptionUsageHeader className="mb-6" />

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left: Configuration */}
          <div className="lg:col-span-2">
            <div className="ui-card p-6">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-6 flex items-center gap-2">
                <FiSettings /> Scan Configuration
              </h2>

              <form onSubmit={handleStartScan}>
                {/* Target URL */}
                <div className="mb-6">
                  <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">
                    Target URL <span className="text-red-500">*</span>
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
                    className={`ui-input ${touched.target && !isNonEmpty(target) ? 'ui-input-error' : ''}`}
                    required
                    disabled={scanning}
                  />
                  <FieldError
                    id="category-scan-target-error"
                    message={touched.target && !isNonEmpty(target) ? 'Please enter a target URL.' : null}
                  />
                </div>

                {/* Advanced Options */}
                <div className="mb-6">
                  <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Advanced Options</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-gray-700 dark:text-gray-200 text-sm mb-2">Scan Depth</label>
                      <input
                        type="number"
                        min="1"
                        max="10"
                        value={options.depth}
                        onChange={(e) => setOptions({ ...options, depth: parseInt(e.target.value) })}
                        className="ui-input"
                        disabled={scanning}
                      />
                    </div>
                    <div>
                      <label className="block text-gray-700 dark:text-gray-200 text-sm mb-2">Timeout (seconds)</label>
                      <input
                        type="number"
                        min="10"
                        max="300"
                        value={options.timeout}
                        onChange={(e) => setOptions({ ...options, timeout: parseInt(e.target.value) })}
                        className="ui-input"
                        disabled={scanning}
                      />
                    </div>
                  </div>

                  <div className="mt-4 grid grid-cols-1 gap-4">
                    <div>
                      <label className="block text-gray-700 dark:text-gray-200 text-sm mb-2">Nuclei Templates Path (optional)</label>
                      <input
                        type="text"
                        value={options.nuclei_templates}
                        onChange={(e) => setOptions({ ...options, nuclei_templates: e.target.value })}
                        placeholder="/path/to/nuclei-templates"
                        className="ui-input"
                        disabled={scanning}
                      />
                      <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Only needed if you selected the Nuclei detector and templates aren't auto-detected.</p>
                    </div>
                    <div>
                      <label className="block text-gray-700 dark:text-gray-200 text-sm mb-2">Nuclei Severity Filter</label>
                      <input
                        type="text"
                        value={options.nuclei_severity}
                        onChange={(e) => setOptions({ ...options, nuclei_severity: e.target.value })}
                        placeholder="low,medium,high,critical"
                        className="ui-input"
                        disabled={scanning}
                      />
                    </div>
                    <div>
                      <label className="block text-gray-700 dark:text-gray-200 text-sm mb-2">CVE DB Path (optional)</label>
                      <input
                        type="text"
                        value={options.cve_db_path}
                        onChange={(e) => setOptions({ ...options, cve_db_path: e.target.value })}
                        placeholder="/path/to/cve-db"
                        className="ui-input"
                        disabled={scanning}
                      />
                      <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Only needed if you selected the CVE DB detector and the server doesn't have CVE_DB_PATH set.</p>
                    </div>
                  </div>

                  <div className="mt-4 space-y-2">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={options.follow_redirects}
                        onChange={(e) => setOptions({ ...options, follow_redirects: e.target.checked })}
                        className="w-4 h-4 text-primary rounded"
                        disabled={scanning}
                      />
                      <span className="text-sm text-gray-700 dark:text-gray-200">Follow Redirects</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={options.verify_ssl}
                        onChange={(e) => setOptions({ ...options, verify_ssl: e.target.checked })}
                        className="w-4 h-4 text-primary rounded"
                        disabled={scanning}
                      />
                      <span className="text-sm text-gray-700 dark:text-gray-200">Verify SSL Certificate</span>
                    </label>
                  </div>
                </div>

                {/* Detector Selection */}
                <div className="mb-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold text-gray-900 dark:text-white">
                      Detectors ({selectedDetectors.length}/{detectors.length})
                    </h3>
                    <button
                      type="button"
                      onClick={toggleAllDetectors}
                      className="text-sm text-primary hover:underline"
                      disabled={scanning}
                    >
                      {selectedDetectors.length === detectors.length ? 'Deselect All' : 'Select All'}
                    </button>
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
                        disabled={scanning}
                      />
                    </div>
                    <FieldError
                      id="category-scan-detectors-error"
                      message={touched.detectors && selectedDetectors.length === 0 ? 'Please select at least one detector.' : null}
                      className="mt-2"
                    />
                  </div>
                  
                  <div className="max-h-96 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900/30">
                    {detectors
                      .filter((detector) => {
                        const q = detectorQuery.trim().toLowerCase();
                        if (!q) return true;
                        return (
                          String(detector.display_name || '').toLowerCase().includes(q) ||
                          String(detector.name || '').toLowerCase().includes(q) ||
                          (detector.tags || []).some((tag) => String(tag).toLowerCase().includes(q))
                        );
                      })
                      .map((detector) => (
                      <label
                        key={detector.id}
                        className={`flex items-start gap-3 p-4 border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/40 cursor-pointer ${
                          scanning ? 'opacity-50 cursor-not-allowed' : ''
                        }`}
                        onClick={() => setTouched((t) => ({ ...t, detectors: true }))}
                      >
                        <input
                          type="checkbox"
                          checked={selectedDetectors.includes(detector.id)}
                          onChange={() => toggleDetector(detector.id)}
                          className="mt-1 w-5 h-5 text-primary rounded"
                          disabled={scanning}
                        />
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-semibold text-gray-900 dark:text-white">{detector.display_name}</span>
                            <span className={`text-xs px-2 py-0.5 rounded font-semibold ${
                              detector.severity === 'critical' ? 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-200' :
                              detector.severity === 'high' ? 'bg-orange-50 text-orange-700 dark:bg-orange-900/30 dark:text-orange-200' :
                              detector.severity === 'medium' ? 'bg-yellow-50 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-200' :
                              detector.severity === 'low' ? 'bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-200' :
                              'bg-gray-50 text-gray-700 dark:bg-gray-800/40 dark:text-gray-200'
                            }`}>
                              {detector.severity.toUpperCase()}
                            </span>
                            {detector.is_dangerous && (
                              <span className="text-xs px-2 py-0.5 rounded bg-red-600 text-white font-semibold">
                                🔴 DANGEROUS
                              </span>
                            )}
                          </div>
                          <p className="text-sm text-gray-600 dark:text-gray-300">{detector.description || 'No description'}</p>
                          {detector.tags && detector.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-2">
                              {detector.tags.map((tag, idx) => (
                                <span key={idx} className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 rounded">
                                  {tag}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </label>
                    ))}
                  </div>
                </div>

                <ScanConsentGate
                  checked={acceptDisclaimer}
                  onChange={(next) => {
                    setConsentTouched(true);
                    setAcceptDisclaimer(next);
                  }}
                  disabled={scanning}
                />

                <FieldError
                  id="category-scan-consent-error"
                  message={
                    consentTouched && !acceptDisclaimer
                      ? 'Please confirm you have authorization to scan this target.'
                      : null
                  }
                />

                {/* Submit Button */}
                <button
                  type="submit"
                  disabled={scanning || selectedDetectors.length === 0 || !acceptDisclaimer}
                  className="ui-btn ui-btn-primary w-full justify-center flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {scanning ? (
                    <>
                      <FiLoader className="animate-spin" size={20} />
                      Scanning... {scanProgress}%
                    </>
                  ) : (
                    <>
                      <FiPlay size={20} />
                      Start {category.display_name} Scan
                    </>
                  )}
                </button>
              </form>
            </div>
          </div>
          </>

          {/* Right: Progress & Results */}
          <div className="lg:col-span-1">
            {/* Progress */}
            {scanning && (
              <div className="ui-card p-6 mb-6">
                <div className="flex items-center justify-between gap-3 mb-4">
                  <h3 className="font-semibold text-gray-900 dark:text-white">Scan Progress</h3>
                  <button
                    type="button"
                    onClick={handleCancelScan}
                    disabled={cancelling || !activeScanId}
                    className="ui-btn bg-white text-red-600 border border-red-200 hover:bg-red-50 disabled:opacity-50 dark:bg-gray-900 dark:border-red-800/40 dark:hover:bg-red-900/20"
                  >
                    {cancelling ? 'Stopping…' : 'Stop Scan'}
                  </button>
                </div>
                <div className="text-xs text-gray-500 dark:text-gray-400 mb-3">
                  {wsConnected ? 'Live updates connected' : 'Live updates unavailable — polling'}
                </div>
                <div className="mb-4">
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-4">
                    <div
                      className="bg-primary h-4 rounded-full transition-all duration-500"
                      style={{ width: `${scanProgress}%` }}
                    ></div>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-300 mt-2">{scanProgress}% complete</p>
                </div>
                <div className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-200">
                  <FiLoader className="animate-spin" />
                  <span>{scanStatus}</span>
                </div>

                {(liveScanDetails?.current_detector || liveScanDetails?.current_url || liveScanDetails?.eta_seconds) && (
                  <div className="mt-3 grid grid-cols-1 gap-1 text-xs text-gray-600 dark:text-gray-300">
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
              </div>
            )}

            {/* Results Summary */}
            {results && (
              <div className="ui-card p-6">
                <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Scan Results</h3>
                
                {results.status === 'completed' ? (
                  <>
                    <div className="flex items-center gap-2 text-green-600 mb-4">
                      <FiCheckCircle size={24} />
                      <span className="font-semibold">Scan Completed</span>
                    </div>
                    
                    <div className="space-y-3">
                      <div className="p-3 bg-gray-50 dark:bg-gray-900/40 rounded-lg border border-gray-200 dark:border-gray-700">
                        <div className="text-sm text-gray-600 dark:text-gray-300">Vulnerabilities Found</div>
                        <div className="text-2xl font-bold text-gray-900 dark:text-white">
                          {results.vulnerabilities_found || results.vulnerabilities?.length || 0}
                        </div>
                      </div>

                      {(() => {
                        const raw = coerceJsonObject(results.raw_results);
                        const detectorsMeta = raw?.metadata?.detectors;
                        if (!detectorsMeta) return null;

                        const executedSummary = summarizeExecuted(detectorsMeta.executed);
                        const skippedSummary = summarizeSkipped(detectorsMeta.skipped);
                        const unknown = detectorsMeta.unknown || [];

                        return (
                          <div className="p-3 border border-gray-200 dark:border-gray-700 rounded-lg">
                            <div className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Detectors</div>
                            <div className="text-xs text-gray-600 dark:text-gray-300 mb-2">
                              Executed: <span className="font-semibold text-gray-900 dark:text-white">{executedSummary.length}</span>
                              {' '}· Skipped: <span className="font-semibold text-gray-900 dark:text-white">{skippedSummary.length}</span>
                              {' '}· Unknown: <span className="font-semibold text-gray-900 dark:text-white">{unknown.length}</span>
                            </div>

                            <button
                              type="button"
                              onClick={() => setShowDetectorDetails((v) => !v)}
                              className="text-xs text-primary hover:underline"
                            >
                              {showDetectorDetails ? 'Hide detector details' : 'Show detector details'}
                            </button>

                            {skippedSummary.length > 0 && (
                              <div className="text-xs text-gray-700 dark:text-gray-200 space-y-2 max-h-44 overflow-auto">
                                {skippedSummary.slice(0, 8).map((d) => (
                                  <div key={d.detector}>
                                    <div className="flex justify-between gap-2">
                                      <span className="truncate" title={d.detector}>{d.detector}</span>
                                      <span className="text-gray-500 dark:text-gray-400 shrink-0">{d.urlsCount} urls</span>
                                    </div>
                                    {d.reasons?.length > 0 && (
                                      <div className="text-[11px] text-gray-500 dark:text-gray-400">{d.reasons.join(' | ')}</div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            )}

                            {showDetectorDetails && (
                              <div className="mt-3 border-t pt-3 space-y-3">
                                <div>
                                  <div className="text-xs font-semibold text-gray-900 dark:text-white mb-1">Executed ({executedSummary.length})</div>
                                  {executedSummary.length ? (
                                    <ul className="text-xs text-gray-700 dark:text-gray-200 space-y-1 max-h-40 overflow-auto">
                                      {executedSummary.map((d) => (
                                        <li key={d.detector} className="flex justify-between gap-2">
                                          <span className="truncate" title={d.detector}>{d.detector}</span>
                                          <span className="text-gray-500 dark:text-gray-400 shrink-0">{d.urlsCount} urls</span>
                                        </li>
                                      ))}
                                    </ul>
                                  ) : (
                                    <div className="text-xs text-gray-500 dark:text-gray-400">None</div>
                                  )}
                                </div>

                                <div>
                                  <div className="text-xs font-semibold text-gray-900 dark:text-white mb-1">Skipped ({skippedSummary.length})</div>
                                  {skippedSummary.length ? (
                                    <ul className="text-xs text-gray-700 dark:text-gray-200 space-y-2 max-h-52 overflow-auto">
                                      {skippedSummary.map((d) => (
                                        <li key={d.detector}>
                                          <div className="flex justify-between gap-2">
                                            <span className="truncate" title={d.detector}>{d.detector}</span>
                                            <span className="text-gray-500 dark:text-gray-400 shrink-0">{d.urlsCount} urls</span>
                                          </div>
                                          {d.reasons?.length > 0 && (
                                            <div className="text-[11px] text-gray-500 dark:text-gray-400">{d.reasons.join(' | ')}</div>
                                          )}
                                        </li>
                                      ))}
                                    </ul>
                                  ) : (
                                    <div className="text-xs text-gray-500 dark:text-gray-400">None</div>
                                  )}
                                </div>

                                <div>
                                  <div className="text-xs font-semibold text-gray-900 dark:text-white mb-1">Unknown ({unknown.length})</div>
                                  {unknown.length ? (
                                    <ul className="text-xs text-gray-700 dark:text-gray-200 space-y-1 max-h-32 overflow-auto">
                                      {unknown.map((k) => (
                                        <li key={k} className="truncate" title={k}>{k}</li>
                                      ))}
                                    </ul>
                                  ) : (
                                    <div className="text-xs text-gray-500 dark:text-gray-400">None</div>
                                  )}
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })()}
                      
                      {results.vulnerabilities && results.vulnerabilities.length > 0 && (
                        <div className="space-y-2">
                          {results.vulnerabilities.slice(0, 5).map((vuln, idx) => (
                            <div key={idx} className="p-3 border border-gray-200 dark:border-gray-700 rounded-lg">
                              <div className="flex items-start justify-between gap-2">
                                <span className="text-sm font-semibold text-gray-900 dark:text-white">{vuln.title}</span>
                                <span className={`text-xs px-2 py-0.5 rounded font-semibold ${
                                  vuln.severity === 'critical' ? 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-200' :
                                  vuln.severity === 'high' ? 'bg-orange-50 text-orange-700 dark:bg-orange-900/30 dark:text-orange-200' :
                                  vuln.severity === 'medium' ? 'bg-yellow-50 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-200' :
                                  'bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-200'
                                }`}>
                                  {vuln.severity}
                                </span>
                              </div>
                            </div>
                          ))}
                          {results.vulnerabilities.length > 5 && (
                            <p className="text-xs text-gray-500 dark:text-gray-400 text-center">
                              +{results.vulnerabilities.length - 5} more
                            </p>
                          )}
                        </div>
                      )}
                    </div>
                    
                    <button
                      onClick={() => navigate(`/scan/details/${results.id}`)}
                      className="ui-btn ui-btn-primary w-full justify-center mt-4"
                    >
                      View Full Report
                    </button>
                  </>
                ) : (
                  <div className="flex items-center gap-2 text-red-600">
                    <FiAlertTriangle size={24} />
                    <span className="font-semibold">Scan Failed</span>
                  </div>
                )}
              </div>
            )}

            {/* Info Card */}
            {!scanning && !results && (
              <div className="ui-card p-6 bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-800/40">
                <h3 className="font-semibold text-blue-900 dark:text-blue-200 mb-2">About {category.display_name}</h3>
                <p className="text-sm text-blue-800 dark:text-blue-200/90 mb-4">{category.description}</p>
                <div className="text-sm text-blue-700 dark:text-blue-200/80">
                  <div className="mb-2">
                    <strong>Detectors:</strong> {category.detector_count}
                  </div>
                  {category.dangerous_detector_count > 0 && (
                    <div className="mb-2 text-red-600 dark:text-red-300">
                      <strong>⚠️ Dangerous Tools:</strong> {category.dangerous_detector_count}
                    </div>
                  )}
                  <div>
                    <strong>Required Plan:</strong> {category.required_plan.toUpperCase()}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
        )}

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
    </DashboardLayout>
  );
};

export default CategoryScan;
