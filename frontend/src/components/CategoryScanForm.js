import React, { useMemo, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { FiSearch, FiAlertCircle, FiLoader } from 'react-icons/fi';
import { getScanCategoryIcon } from '../lib/icons';
import ScanConsentGate from './ScanConsentGate';
import FieldError from './forms/FieldError';
import { isNonEmpty } from '../lib/validation';
import api from '../services/api';

const planRank = (plan, isEnterpriseOnly) => {
  // Some APIs expose enterprise gating via boolean instead of required_plan
  if (isEnterpriseOnly) return 2;
  if (plan === 'free') return 0;
  if (plan === 'pro') return 1;
  if (plan === 'enterprise') return 2;
  return 99;
};

const CategoryScanForm = ({ onScanCreated }) => {
  const [categories, setCategories] = useState([]);
  const [selectedCategory, setSelectedCategory] = useState(null);
  const [detectors, setDetectors] = useState([]);
  const [selectedDetectors, setSelectedDetectors] = useState([]);
  const [target, setTarget] = useState('');
  const [acceptDisclaimer, setAcceptDisclaimer] = useState(false);
  const [options, setOptions] = useState({
    concurrency: 10,
    timeout: 30,
    nuclei_templates: '',
    nuclei_severity: 'low,medium,high,critical',
    cve_db_path: '',
  });
  const [loading, setLoading] = useState(false);
  const [loadingCategories, setLoadingCategories] = useState(true);
  const [error, setError] = useState('');
  const [touched, setTouched] = useState({});
  const navigate = useNavigate();

  const fieldErrors = useMemo(() => {
    const next = {};
    if (!selectedCategory) next.selectedCategory = 'Please select a scan category.';
    if (!isNonEmpty(target)) next.target = 'Please enter a target URL.';
    if (selectedCategory && selectedDetectors.length === 0) next.detectors = 'Please select at least one detector.';
    if (!acceptDisclaimer) next.acceptDisclaimer = 'Please confirm you have authorization to scan this target.';
    return next;
  }, [acceptDisclaimer, selectedCategory, selectedDetectors.length, target]);

  const hasErrors = Object.values(fieldErrors).some(Boolean);

  useEffect(() => {
    fetchCategories();
  }, []);

  useEffect(() => {
    if (selectedCategory) {
      fetchDetectors(selectedCategory.id);
    }
  }, [selectedCategory]);

  const fetchCategories = async () => {
    setLoadingCategories(true);
    try {
      const response = await api.get('/scan-categories/');
      const nextCategories = (response.data || [])
        .slice()
        .sort((a, b) => {
          const aRank = planRank(a?.required_plan, a?.is_enterprise_only);
          const bRank = planRank(b?.required_plan, b?.is_enterprise_only);
          if (aRank !== bRank) return aRank - bRank;
          return String(a?.display_name || a?.name || '').localeCompare(
            String(b?.display_name || b?.name || '')
          );
        });
      setCategories(nextCategories);
    } catch (err) {
      setError('Failed to load scan categories');
    } finally {
      setLoadingCategories(false);
    }
  };

  const fetchDetectors = async (categoryId) => {
    try {
      const response = await api.get(`/scan-categories/${categoryId}/detectors/`);
      setDetectors(response.data);
      // Auto-select all detectors by default
      setSelectedDetectors(response.data.map(d => d.name));
    } catch (err) {
      setError('Failed to load detectors');
    }
  };

  const handleCategorySelect = (category) => {
    setSelectedCategory(category);
    setError('');
  };

  const handleDetectorToggle = (detectorName) => {
    setSelectedDetectors(prev => 
      prev.includes(detectorName)
        ? prev.filter(d => d !== detectorName)
        : [...prev, detectorName]
    );
  };

  const handleSelectAll = () => {
    setSelectedDetectors(detectors.map(d => d.name));
  };

  const handleDeselectAll = () => {
    setSelectedDetectors([]);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    setTouched({ selectedCategory: true, target: true, detectors: true, acceptDisclaimer: true });
    if (hasErrors) {
      setError('Please fix the highlighted fields.');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const response = await api.post('/scans/start-category-scan/', {
        target: target,
        category: selectedCategory.id,
        consent: true,
        detectors: selectedDetectors,
        options: options,
      });

      // Reset form
      setTarget('');
      setSelectedCategory(null);
      setSelectedDetectors([]);
      setDetectors([]);
      setAcceptDisclaimer(false);

      // Notify parent component
      if (onScanCreated) {
        onScanCreated(response.data);
      }

      // Navigate to scan details
      navigate(`/scan/details/${response.data.id}`);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-100 text-red-800 border-red-200 dark:bg-red-900/30 dark:text-red-200 dark:border-red-800',
      high: 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/30 dark:text-orange-200 dark:border-orange-800',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-200 dark:border-yellow-800',
      low: 'bg-green-100 text-green-800 border-green-200 dark:bg-green-900/20 dark:text-green-200 dark:border-green-800',
      info: 'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/30 dark:text-blue-200 dark:border-blue-800',
    };
    return colors[severity] || colors.info;
  };

  return (
    <div className="ui-card p-6">
      <h3 className="text-2xl font-bold mb-6 text-gray-900 dark:text-white">Create Category-Based Scan</h3>

      {error && (
        <div className="ui-alert ui-alert-error mb-6 flex items-start gap-3">
          <FiAlertCircle className="text-red-600 mt-0.5 flex-shrink-0" />
          <p className="text-red-700 text-sm">{error}</p>
        </div>
      )}

      <form onSubmit={handleSubmit}>
        {/* Target URL */}
        <div className="mb-6">
          <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">Target URL</label>
          <input
            type="url"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onBlur={() => setTouched((t) => ({ ...t, target: true }))}
            placeholder="https://example.com"
            className={`ui-input ${touched.target && fieldErrors.target ? 'ui-input-error' : ''}`}
            aria-invalid={touched.target && !!fieldErrors.target}
            aria-describedby={touched.target && fieldErrors.target ? 'category-scan-target-error' : undefined}
          />
          <FieldError id="category-scan-target-error" message={touched.target ? fieldErrors.target : null} />
        </div>

        {/* Advanced Options */}
        <div className="mb-6">
          <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-3">Advanced Options (optional)</label>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-gray-700 dark:text-gray-200 text-sm mb-2">Concurrency</label>
              <input
                type="number"
                min="1"
                max="100"
                value={options.concurrency}
                onChange={(e) => setOptions({ ...options, concurrency: parseInt(e.target.value) || 1 })}
                className="ui-input py-2"
              />
            </div>
            <div>
              <label className="block text-gray-700 dark:text-gray-200 text-sm mb-2">Timeout (seconds)</label>
              <input
                type="number"
                min="10"
                max="300"
                value={options.timeout}
                onChange={(e) => setOptions({ ...options, timeout: parseInt(e.target.value) || 10 })}
                className="ui-input py-2"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-gray-700 dark:text-gray-200 text-sm mb-2">Nuclei Templates Path</label>
              <input
                type="text"
                value={options.nuclei_templates}
                onChange={(e) => setOptions({ ...options, nuclei_templates: e.target.value })}
                placeholder="/path/to/nuclei-templates"
                className="ui-input py-2"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-gray-700 dark:text-gray-200 text-sm mb-2">Nuclei Severity Filter</label>
              <input
                type="text"
                value={options.nuclei_severity}
                onChange={(e) => setOptions({ ...options, nuclei_severity: e.target.value })}
                placeholder="low,medium,high,critical"
                className="ui-input py-2"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-gray-700 dark:text-gray-200 text-sm mb-2">CVE DB Path</label>
              <input
                type="text"
                value={options.cve_db_path}
                onChange={(e) => setOptions({ ...options, cve_db_path: e.target.value })}
                placeholder="/path/to/cve-db"
                className="ui-input py-2"
              />
            </div>
          </div>
        </div>

        {/* Category Selection */}
        <div className="mb-6">
          <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-3">Select Scan Category</label>
          <FieldError
            id="category-scan-category-error"
            message={touched.selectedCategory ? fieldErrors.selectedCategory : null}
            className="mb-2"
          />
          
          {loadingCategories ? (
            <div className="flex justify-center py-8">
              <FiLoader className="animate-spin text-primary" size={32} />
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {categories.map((category) => (
                <button
                  key={category.id}
                  type="button"
                  onClick={() => {
                    setTouched((t) => ({ ...t, selectedCategory: true }));
                    handleCategorySelect(category);
                  }}
                  className={`p-4 border-2 rounded-lg text-left transition ${
                    selectedCategory?.id === category.id
                      ? 'border-primary bg-primary/5 dark:bg-primary/10'
                      : 'border-gray-200 dark:border-gray-700 hover:border-primary hover:bg-gray-50 dark:hover:bg-gray-900/30'
                  }`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <span className="text-2xl text-primary">
                      {getScanCategoryIcon(category.name, { size: 22 })}
                    </span>
                    {category.is_enterprise_only && (
                      <span className="text-xs px-2 py-0.5 rounded bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-200 font-semibold">
                        ENT
                      </span>
                    )}
                    {category.required_plan === 'pro' && (
                      <span className="text-xs px-2 py-0.5 rounded bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-200 font-semibold">
                        PRO
                      </span>
                    )}
                  </div>
                  <h4 className="font-bold text-gray-900 dark:text-white mb-1">{category.display_name}</h4>
                  <p className="text-xs text-gray-600 dark:text-gray-300 mb-2">{category.description}</p>
                  <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
                    <span>{category.detector_count} detectors</span>
                    {category.dangerous_detector_count > 0 && (
                      <span className="text-red-600 dark:text-red-400 font-semibold">
                        {category.dangerous_detector_count} dangerous
                      </span>
                    )}
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Legal Disclaimer */}
        <div className="mb-6">
          <ScanConsentGate
            id="category-scan-consent"
            checked={acceptDisclaimer}
            onChange={(next) => {
              setTouched((t) => ({ ...t, acceptDisclaimer: true }));
              setAcceptDisclaimer(next);
            }}
          />
          <FieldError
            id="category-scan-consent-error"
            message={touched.acceptDisclaimer ? fieldErrors.acceptDisclaimer : null}
          />
        </div>

        {/* Detector Selection */}
        {selectedCategory && detectors.length > 0 && (
          <div className="mb-6">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-3">
              <label className="block text-gray-700 dark:text-gray-200 font-semibold">
                Select Detectors ({selectedDetectors.length}/{detectors.length})
              </label>
              <div className="flex flex-wrap gap-2 w-full sm:w-auto">
                <button
                  type="button"
                  onClick={handleSelectAll}
                  className="ui-btn ui-btn-primary px-3 py-1 text-xs flex-1 sm:flex-none"
                >
                  Select All
                </button>
                <button
                  type="button"
                  onClick={handleDeselectAll}
                  className="ui-btn ui-btn-secondary px-3 py-1 text-xs flex-1 sm:flex-none"
                >
                  Deselect All
                </button>
              </div>
            </div>

            <div className="max-h-96 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <div className="space-y-2">
                {detectors.map((detector) => (
                  <label
                    key={detector.id}
                    className="flex items-start gap-3 p-3 hover:bg-gray-50 dark:hover:bg-gray-900/30 rounded cursor-pointer transition"
                  >
                    <input
                      type="checkbox"
                      checked={selectedDetectors.includes(detector.name)}
                      onChange={() => handleDetectorToggle(detector.name)}
                      className="mt-1 w-4 h-4 text-primary focus:ring-primary border-gray-300 rounded"
                    />
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-semibold text-gray-900 dark:text-white">{detector.display_name}</span>
                        <span className={`text-xs px-2 py-0.5 rounded border ${getSeverityColor(detector.severity)}`}>
                          {detector.severity.toUpperCase()}
                        </span>
                        {detector.is_dangerous && (
                          <span className="text-xs px-2 py-0.5 rounded bg-red-100 text-red-700 border border-red-200 dark:bg-red-900/30 dark:text-red-200 dark:border-red-800 font-semibold">
                            🔴 DANGEROUS
                          </span>
                        )}
                        {detector.is_beta && (
                          <span className="text-xs px-2 py-0.5 rounded bg-yellow-100 text-yellow-700 border border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-200 dark:border-yellow-800">
                            ⚠️ BETA
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-gray-600 dark:text-gray-300">{detector.description}</p>
                      {detector.tags && detector.tags.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {detector.tags.map((tag, idx) => (
                            <span key={idx} className="text-xs px-2 py-0.5 bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300 rounded">
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

            <FieldError
              id="category-scan-detectors-error"
              message={touched.detectors ? fieldErrors.detectors : null}
              className="mt-2"
            />
          </div>
        )}

        {/* Submit Button */}
        <button
          type="submit"
          disabled={loading || hasErrors}
          className="ui-btn ui-btn-primary w-full justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? (
            <>
              <FiLoader className="animate-spin" />
              <span>Starting Scan...</span>
            </>
          ) : (
            <>
              <FiSearch />
              <span>Start Scan</span>
            </>
          )}
        </button>
      </form>
    </div>
  );
};

export default CategoryScanForm;
