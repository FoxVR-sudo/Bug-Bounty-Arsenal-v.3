import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FiUpload, FiSmartphone, FiCheckCircle, FiAlertCircle, FiLoader, FiX } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import { useToast } from '../contexts/ToastContext';
import { mobileScanService } from '../services/api';

const ALLOWED_EXTENSIONS = ['.apk', '.ipa'];
const MAX_FILE_MB = 100;
const MAX_FILE_BYTES = MAX_FILE_MB * 1024 * 1024;

const PLATFORM_INFO = {
  android: {
    label: 'Android APK',
    icon: '🤖',
    checks: [
      'Dangerous permissions (SMS, microphone, contacts…)',
      'Debug mode enabled',
      'ADB backup allowed',
      'Cleartext HTTP traffic',
      'Exported components (activities, services)',
      'Hardcoded secrets & API keys',
      'Weak cryptography (DES, MD5, RC4)',
      'Hardcoded HTTP URLs',
      'Certificate pinning absence',
    ],
  },
  ios: {
    label: 'iOS IPA',
    icon: '🍎',
    checks: [
      'App Transport Security (ATS) disabled',
      'Insecure HTTP exception domains',
      'Custom URL scheme injection risks',
      'Binary security (PIE, Stack Canaries, ARC)',
      'Hardcoded secrets & tokens',
      'Jailbreak detection absence',
    ],
  },
};

const formatBytes = (bytes) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const MobileScan = () => {
  const toast = useToast();
  const navigate = useNavigate();
  const fileInputRef = useRef(null);

  const [file, setFile] = useState(null);
  const [platform, setPlatform] = useState('');
  const [appName, setAppName] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const [fileError, setFileError] = useState('');

  const [submitting, setSubmitting] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [scanStatus, setScanStatus] = useState(null);
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState('');

  const pollRef = useRef(null);

  // ── Polling scan status ─────────────────────────────────────────────────

  useEffect(() => {
    if (!scanId) return;

    const poll = async () => {
      try {
        const res = await mobileScanService.getStatus(scanId);
        const data = res.data;
        setProgress(data.progress || 0);
        setCurrentStep(data.current_step || '');
        setScanStatus(data.status);

        if (data.status === 'completed' || data.status === 'failed') {
          clearInterval(pollRef.current);
          if (data.status === 'completed') {
            toast.success(`Scan complete — ${data.vulnerabilities_found || 0} findings`);
            navigate(`/scan/details/${scanId}`);
          } else {
            setSubmitting(false);
            toast.error('Mobile scan failed. See scan details for more info.');
          }
        }
      } catch {
        // ignore transient errors
      }
    };

    pollRef.current = setInterval(poll, 3000);
    return () => clearInterval(pollRef.current);
  }, [scanId, navigate, toast]);

  // ── File validation ─────────────────────────────────────────────────────

  const validateFile = useCallback((f) => {
    if (!f) return 'Please select a file.';
    const ext = f.name.toLowerCase().slice(f.name.lastIndexOf('.'));
    if (!ALLOWED_EXTENSIONS.includes(ext)) return `Only .apk and .ipa files are supported.`;
    if (f.size > MAX_FILE_BYTES) return `File too large. Maximum size is ${MAX_FILE_MB} MB.`;
    return '';
  }, []);

  const handleFileSelect = useCallback((f) => {
    const err = validateFile(f);
    setFileError(err);
    if (err) {
      setFile(null);
      setPlatform('');
      setAppName('');
      return;
    }
    setFile(f);
    const ext = f.name.toLowerCase().slice(f.name.lastIndexOf('.'));
    setPlatform(ext === '.apk' ? 'android' : 'ios');
    setAppName(f.name.replace(/\.(apk|ipa)$/i, ''));
  }, [validateFile]);

  // ── Drag & drop ─────────────────────────────────────────────────────────

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFileSelect(f);
  }, [handleFileSelect]);

  const onDragOver = (e) => { e.preventDefault(); setDragOver(true); };
  const onDragLeave = () => setDragOver(false);

  // ── Submit ───────────────────────────────────────────────────────────────

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file || fileError) return;

    const formData = new FormData();
    formData.append('file', file);
    if (appName.trim()) formData.append('app_name', appName.trim());

    setSubmitting(true);
    setScanStatus('pending');
    setProgress(0);
    setCurrentStep('Uploading…');

    try {
      const res = await mobileScanService.start(formData);
      setScanId(res.data.scan_id);
      setCurrentStep('Queued…');
      toast.info(`${res.data.platform_label} scan started`);
    } catch (err) {
      const msg = err?.response?.data?.error || 'Failed to start scan. Please try again.';
      toast.error(msg);
      setScanStatus(null);
      setSubmitting(false);
    }
  };

  const handleClear = () => {
    setFile(null);
    setPlatform('');
    setAppName('');
    setFileError('');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  // ── Render ───────────────────────────────────────────────────────────────

  const info = PLATFORM_INFO[platform];
  const isScanning = submitting && scanStatus && scanStatus !== 'failed';

  return (
    <DashboardLayout>
      <div className="max-w-2xl mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <FiSmartphone className="text-indigo-500 text-2xl" />
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              Mobile App Scanner
            </h1>
          </div>
          <p className="text-gray-500 dark:text-gray-400">
            Upload an Android <strong>.apk</strong> or iOS <strong>.ipa</strong> file for static
            security analysis. No external tools required — analysis runs entirely on the server.
          </p>
        </div>

        {/* Upload form */}
        {!isScanning && (
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Drop zone */}
            <div
              className={`relative border-2 border-dashed rounded-xl p-8 text-center transition-colors cursor-pointer
                ${dragOver ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20' : 'border-gray-300 dark:border-gray-600 hover:border-indigo-400 dark:hover:border-indigo-500'}
                ${fileError ? 'border-red-400 bg-red-50 dark:bg-red-900/10' : ''}`}
              onDrop={onDrop}
              onDragOver={onDragOver}
              onDragLeave={onDragLeave}
              onClick={() => !file && fileInputRef.current?.click()}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => e.key === 'Enter' && fileInputRef.current?.click()}
              aria-label="Upload APK or IPA file"
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".apk,.ipa"
                className="hidden"
                onChange={(e) => handleFileSelect(e.target.files[0])}
              />

              {file ? (
                <div className="flex items-center justify-center gap-4">
                  <span className="text-3xl">{info?.icon || '📱'}</span>
                  <div className="text-left">
                    <p className="font-semibold text-gray-800 dark:text-gray-100">{file.name}</p>
                    <p className="text-sm text-gray-500">{formatBytes(file.size)} · {info?.label}</p>
                  </div>
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); handleClear(); }}
                    className="ml-2 text-gray-400 hover:text-red-500"
                    aria-label="Remove file"
                  >
                    <FiX />
                  </button>
                </div>
              ) : (
                <>
                  <FiUpload className="mx-auto text-4xl text-gray-400 mb-3" />
                  <p className="text-gray-600 dark:text-gray-300 font-medium">
                    Drag & drop or <span className="text-indigo-600 dark:text-indigo-400 underline">browse</span>
                  </p>
                  <p className="text-sm text-gray-400 mt-1">.apk or .ipa · max {MAX_FILE_MB} MB</p>
                </>
              )}
            </div>

            {fileError && (
              <p className="flex items-center gap-1 text-sm text-red-600">
                <FiAlertCircle /> {fileError}
              </p>
            )}

            {/* App name */}
            {file && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  App name (optional)
                </label>
                <input
                  type="text"
                  value={appName}
                  onChange={(e) => setAppName(e.target.value)}
                  maxLength={100}
                  placeholder="e.g. MyApp v2.3.1"
                  className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 text-sm
                    bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100
                    focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>
            )}

            {/* What will be checked */}
            {info && (
              <div className="bg-gray-50 dark:bg-gray-800/50 rounded-xl p-4">
                <p className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                  {info.icon} What will be checked ({info.label}):
                </p>
                <ul className="space-y-1">
                  {info.checks.map((c) => (
                    <li key={c} className="flex items-start gap-2 text-sm text-gray-600 dark:text-gray-400">
                      <FiCheckCircle className="mt-0.5 text-green-500 flex-shrink-0" />
                      {c}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <button
              type="submit"
              disabled={!file || !!fileError}
              className="w-full bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed
                text-white font-semibold py-3 rounded-xl transition-colors flex items-center justify-center gap-2"
            >
              <FiSmartphone />
              Start Security Scan
            </button>
          </form>
        )}

        {/* Progress */}
        {isScanning && (
          <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6 space-y-4">
            <div className="flex items-center gap-3">
              <FiLoader className="animate-spin text-indigo-500 text-xl" />
              <div>
                <p className="font-semibold text-gray-800 dark:text-gray-100">
                  Analysing {file?.name}…
                </p>
                <p className="text-sm text-gray-500">{currentStep}</p>
              </div>
            </div>

            {/* Progress bar */}
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2.5">
              <div
                className="bg-indigo-600 h-2.5 rounded-full transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
            <p className="text-right text-xs text-gray-400">{progress}%</p>
          </div>
        )}

        {/* Failed state */}
        {scanStatus === 'failed' && (
          <div className="mt-4 p-4 rounded-xl bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 flex gap-3">
            <FiAlertCircle className="text-red-500 mt-0.5 flex-shrink-0" />
            <div>
              <p className="font-semibold text-red-700 dark:text-red-300">Scan failed</p>
              <p className="text-sm text-red-600 dark:text-red-400">{currentStep}</p>
              <button
                className="mt-2 text-sm text-indigo-600 underline"
                onClick={() => { setScanStatus(null); setSubmitting(false); setScanId(null); }}
              >
                Try again
              </button>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default MobileScan;
