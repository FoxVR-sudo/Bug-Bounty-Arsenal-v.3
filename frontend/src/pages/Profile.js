import React, { useEffect, useState } from 'react';
import { useQuery } from 'react-query';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import { scanService, statsService, userService, twoFactorService } from '../services/api';
import { FiMail, FiCalendar, FiActivity, FiShield, FiAward, FiAlertTriangle, FiDownload, FiPrinter } from 'react-icons/fi';
import { VerifiedDomainsPanel } from './VerifiedDomains';
import QRCode from 'qrcode.react';
import DashboardLayout from '../components/DashboardLayout';
import LoadingState from '../components/states/LoadingState';
import ErrorState from '../components/states/ErrorState';
import PaginationControls from '../components/PaginationControls';

const Profile = () => {
  const [scanFilter, setScanFilter] = useState('all'); // all, completed, failed, running
  const [scanPage, setScanPage] = useState(1);
  const token = localStorage.getItem('token');

  const [twoFactorError, setTwoFactorError] = useState('');
  const [twoFactorLoading, setTwoFactorLoading] = useState(false);
  const [twoFactorSetup, setTwoFactorSetup] = useState(null);
  const [twoFactorConfirmCode, setTwoFactorConfirmCode] = useState('');
  const [twoFactorBackupCodes, setTwoFactorBackupCodes] = useState(null);
  const [twoFactorActionPassword, setTwoFactorActionPassword] = useState('');
  const [twoFactorActionCode, setTwoFactorActionCode] = useState('');
  const [twoFactorToast, setTwoFactorToast] = useState('');

  const {
    data: profile,
    isLoading: profileLoading,
    error: profileError,
    refetch: refetchProfile,
  } = useQuery(
    'profile',
    () => statsService.getOverview().then(res => res.data),
    { enabled: !!token }
  );

  const {
    data: me,
  } = useQuery(
    'me',
    () => userService.getMe().then(res => res.data),
    { enabled: !!token }
  );

  const {
    data: twoFactorStatus,
    refetch: refetchTwoFactorStatus,
  } = useQuery(
    'twoFactorStatus',
    () => twoFactorService.status().then(res => res.data),
    { enabled: !!token }
  );

  const startTwoFactorSetup = async () => {
    setTwoFactorError('');
    setTwoFactorBackupCodes(null);
    setTwoFactorConfirmCode('');
    setTwoFactorLoading(true);
    try {
      const res = await twoFactorService.setup();
      setTwoFactorSetup(res.data);
      await refetchTwoFactorStatus();
    } catch (e) {
      setTwoFactorError(e.response?.data?.detail || 'Failed to start 2FA setup.');
    } finally {
      setTwoFactorLoading(false);
    }
  };

  const confirmTwoFactorSetup = async () => {
    setTwoFactorError('');
    setTwoFactorLoading(true);
    try {
      const res = await twoFactorService.confirm(twoFactorConfirmCode);
      setTwoFactorBackupCodes(res.data?.backup_codes || []);
      setTwoFactorSetup(null);
      setTwoFactorConfirmCode('');
      await refetchTwoFactorStatus();
    } catch (e) {
      setTwoFactorError(e.response?.data?.detail || 'Failed to confirm 2FA.');
    } finally {
      setTwoFactorLoading(false);
    }
  };

  const regenerateBackupCodes = async () => {
    setTwoFactorError('');
    setTwoFactorLoading(true);
    try {
      const res = await twoFactorService.regenerateBackupCodes(twoFactorActionPassword, twoFactorActionCode);
      setTwoFactorBackupCodes(res.data?.backup_codes || []);
      setTwoFactorActionPassword('');
      setTwoFactorActionCode('');
      await refetchTwoFactorStatus();
    } catch (e) {
      setTwoFactorError(e.response?.data?.detail || 'Failed to regenerate backup codes.');
    } finally {
      setTwoFactorLoading(false);
    }
  };

  const disableTwoFactor = async () => {
    setTwoFactorError('');
    setTwoFactorLoading(true);
    try {
      await twoFactorService.disable(twoFactorActionPassword, twoFactorActionCode);
      setTwoFactorBackupCodes(null);
      setTwoFactorSetup(null);
      setTwoFactorActionPassword('');
      setTwoFactorActionCode('');
      await refetchTwoFactorStatus();
    } catch (e) {
      setTwoFactorError(e.response?.data?.detail || 'Failed to disable 2FA.');
    } finally {
      setTwoFactorLoading(false);
    }
  };

  const {
    data: scansData,
    isLoading: scansLoading,
    error: scansError,
  } = useQuery(
    ['profileScans', scanPage, scanFilter],
    async () => {
      const params = { page: scanPage, page_size: 20 };
      if (scanFilter && scanFilter !== 'all') params.status = scanFilter;
      const response = await scanService.getAll(params);
      return response.data;
    },
    { enabled: !!token, keepPreviousData: true }
  );

  useEffect(() => {
    setScanPage(1);
  }, [scanFilter]);


  if (profileLoading && !profile) {
    return (
      <DashboardLayout>
        <LoadingState title="Loading profile" subtitle="Fetching your account overview…" />
      </DashboardLayout>
    );
  }

  if (profileError && !profile) {
    const msg =
      profileError?.response?.data?.error ||
      profileError?.response?.data?.detail ||
      profileError?.message ||
      'Please try again.';
    return (
      <DashboardLayout>
        <ErrorState
          title="Couldn’t load profile"
          message={msg}
          action={
            <button onClick={() => refetchProfile()} className="ui-btn ui-btn-primary">
              Retry
            </button>
          }
        />
      </DashboardLayout>
    );
  }

  const scans = (() => {
    if (!scansData) return [];
    if (Array.isArray(scansData)) return scansData;
    if (Array.isArray(scansData.results)) return scansData.results;
    return [];
  })();

  const totalScanPages =
    typeof scansData?.count === 'number' ? Math.max(1, Math.ceil(scansData.count / 20)) : undefined;
  
  const filteredScans = scans.filter((scan) => {
    if (scanFilter === 'all') return true;
    return scan.status === scanFilter;
  });

  const userEmail = (() => {
    const storedUser = localStorage.getItem('user');
    if (!storedUser) return 'admin@bugbounty-arsenal.com';

    // Sometimes we store the email directly; other times we store a JSON object.
    if (storedUser.includes('{')) {
      try {
        const parsed = JSON.parse(storedUser);
        return parsed?.email || parsed?.user?.email || parsed?.username || parsed?.user?.username || 'admin@bugbounty-arsenal.com';
      } catch (e) {
        // Fall through to using the raw string.
      }
    }

    return storedUser;
  })();

  const isPrivilegedUser = Boolean(
    me?.is_superuser || me?.is_admin || me?.is_staff
  );

  const memberSince = me?.date_joined ? format(new Date(me.date_joined), 'PPP') : '—';
  const roleLabel = me?.is_superuser
    ? 'Superuser'
    : me?.is_admin
    ? 'Admin'
    : me?.is_staff
    ? 'Staff'
    : 'User';
  const phoneLabel = me?.phone ? me.phone : '—';
  const phoneVerifiedLabel = me?.phone_verified ? 'Verified' : 'Not verified';
  const companyName = me?.company_name || '—';
  const companyVerifiedLabel = me?.company_verified ? 'Verified' : 'Not verified';
  const addressLabel = me?.address || me?.company_address || '—';
  const countryLabel = me?.company_country || '—';
  const lastSeenLocation = [me?.last_seen_city, me?.last_seen_country].filter(Boolean).join(', ') || '—';
  const planLabel = me?.current_plan || 'Free';
  const clientIp = me?.client_ip || '—';
  const accountStatusLabel = token ? 'Active' : 'Unknown';
  const emailVerifiedLabel = me?.is_verified ? 'Verified' : 'Not verified';
  const twoFactorEnabled =
    typeof twoFactorStatus?.enabled === 'boolean'
      ? twoFactorStatus.enabled
      : Boolean(me?.two_factor_enabled);
  const twoFactorLabel = twoFactorEnabled ? 'Enabled' : 'Disabled';
  const apiLimits = me?.api_limits || {};

  const copyToClipboard = async (text, successMessage = 'Copied') => {
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(String(text));
      } else {
        const el = document.createElement('textarea');
        el.value = String(text);
        document.body.appendChild(el);
        el.select();
        document.execCommand('copy');
        document.body.removeChild(el);
      }
      setTwoFactorToast(successMessage);
      setTimeout(() => setTwoFactorToast(''), 2000);
    } catch (e) {
      setTwoFactorError('Copy failed. Please copy manually.');
    }
  };

  const downloadBackupCodes = () => {
    if (!twoFactorBackupCodes?.length) return;
    const email = me?.email || userEmail;
    const content = [
      'BugBounty Arsenal - 2FA Backup Codes',
      `Account: ${email}`,
      `Generated: ${new Date().toISOString()}`,
      '',
      ...twoFactorBackupCodes,
      '',
      'Keep these codes safe. Each code can be used once.',
    ].join('\n');

    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `backup-codes-${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const printBackupCodes = () => {
    if (!twoFactorBackupCodes?.length) return;

    const email = me?.email || userEmail;
    const now = new Date();
    const codes = twoFactorBackupCodes;

    const printWindow = window.open('', '_blank', 'noopener,noreferrer,width=720,height=900');
    if (!printWindow) {
      setTwoFactorError('Pop-up blocked. Please allow pop-ups to print backup codes.');
      return;
    }

    const escapeHtml = (value) => String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');

    const codesHtml = codes
      .map((c) => (
        `<tr>
          <td class="cb"><span class="checkbox" aria-hidden="true"></span></td>
          <td class="code"><code>${escapeHtml(c)}</code></td>
        </tr>`
      ))
      .join('');

    printWindow.document.open();
    printWindow.document.write(`
      <!doctype html>
      <html>
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>2FA Backup Codes</title>
          <style>
            body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; color: #111827; }
            h1 { font-size: 20px; margin: 0 0 10px; }
            .meta { font-size: 12px; color: #4b5563; margin-bottom: 16px; }
            .box { border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px; }
            .cut { margin: 16px 0; border-top: 1px dashed #9ca3af; position: relative; }
            .cut span { position: absolute; top: -10px; left: 0; background: #fff; padding-right: 8px; font-size: 11px; color: #6b7280; }
            table { width: 100%; border-collapse: collapse; }
            tbody { column-count: 2; column-gap: 24px; }
            tr { break-inside: avoid; display: table; width: 100%; }
            td { padding: 6px 0; vertical-align: middle; }
            td.cb { width: 22px; }
            .checkbox { display: inline-block; width: 12px; height: 12px; border: 1px solid #6b7280; border-radius: 2px; }
            code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 14px; }
            .note { margin-top: 14px; font-size: 12px; color: #374151; }
            @media print {
              body { margin: 0.5in; }
              .box { border-color: #9ca3af; }
            }
          </style>
        </head>
        <body>
          <h1>BugBounty Arsenal — 2FA Backup Codes</h1>
          <div class="meta">
            Account: ${escapeHtml(email)}<br/>
            Generated: ${escapeHtml(now.toLocaleString())}
          </div>
          <div class="note">
            Tip: Print and store offline. You can tick a checkbox when a code is used.
          </div>
          <div class="cut"><span>Cut here</span></div>
          <div class="box">
            <table>
              <tbody>
                ${codesHtml}
              </tbody>
            </table>
            <div class="note">
              Keep these codes safe. Each code can be used once. If you suspect compromise, regenerate codes immediately.
            </div>
          </div>
          <script>
            window.addEventListener('load', () => {
              setTimeout(() => window.print(), 50);
            });
          </script>
        </body>
      </html>
    `);
    printWindow.document.close();
  };

  const exportHistoryCsv = () => {
    if (!scans.length) return;

    const headers = [
      'id',
      'target',
      'scan_type',
      'scan_category',
      'status',
      'vulnerabilities_found',
      'created_at',
    ];

    const escapeCsv = (value) => {
      const stringValue = value == null ? '' : String(value);
      const escaped = stringValue.replace(/"/g, '""');
      return `"${escaped}"`;
    };

    const rows = scans.map((scan) => (
      headers
        .map((key) => escapeCsv(scan[key]))
        .join(',')
    ));

    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = `scan-history-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
  };

  return (
    <DashboardLayout>
      <div className="ui-page">
        <div className="mb-8">
          <h1 className="ui-title">Profile</h1>
          <p className="ui-subtitle mt-2">Manage your account and view your statistics</p>
        </div>

        {!token && (
          <div className="ui-alert ui-alert-error mb-6">
            You are not logged in. Please <Link className="ui-link" to="/login">log in</Link> to view your profile.
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Profile Info */}
          <div className="lg:col-span-2 space-y-6">
            {/* Basic Info */}
            <div className="ui-card p-6">
              <h2 className="text-xl font-semibold mb-6 text-gray-900 dark:text-white">Account Information</h2>
              <div className="space-y-4">
                <div className="flex items-center gap-4">
                  <div className="bg-primary text-white rounded-full w-20 h-20 flex items-center justify-center text-3xl font-bold">
                    {userEmail.charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <h3 className="text-xl font-semibold text-gray-900 dark:text-white">
                      {me?.full_name || userEmail.split('@')[0]}
                    </h3>
                    <p className="text-gray-600 dark:text-gray-300 flex items-center gap-2">
                      <FiMail size={16} />
                      {userEmail}
                    </p>
                  </div>
                </div>

                <div className="border-t border-gray-200 dark:border-gray-700 pt-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-600 dark:text-gray-300 flex items-center gap-2">
                      <FiCalendar size={16} />
                      Member Since
                    </span>
                    <span className="font-semibold text-gray-900 dark:text-white">{memberSince}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-600 dark:text-gray-300 flex items-center gap-2">
                      <FiShield size={16} />
                      Account Status
                    </span>
                    <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm font-semibold">
                      {accountStatusLabel}
                    </span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600 dark:text-gray-300">Plan</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{planLabel}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600 dark:text-gray-300">Role</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{roleLabel}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600 dark:text-gray-300">Email Verification</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{emailVerifiedLabel}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600 dark:text-gray-300">2FA Status</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{twoFactorLabel}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600 dark:text-gray-300">Phone</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{phoneLabel}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600 dark:text-gray-300">Phone Status</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{phoneVerifiedLabel}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600 dark:text-gray-300">Company</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{companyName}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600 dark:text-gray-300">Company Status</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{companyVerifiedLabel}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600 dark:text-gray-300">Address</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{addressLabel}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600 dark:text-gray-300">Country</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{countryLabel}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600 dark:text-gray-300">Last Seen Location</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{lastSeenLocation}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600 dark:text-gray-300">Client IP</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{clientIp}</span>
                    </div>
                    <div className="md:col-span-2 border-t border-gray-200 dark:border-gray-700 pt-3">
                      <div className="text-sm text-gray-700 dark:text-gray-200 font-semibold mb-2">API limits</div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                        <div className="flex items-center justify-between">
                          <span className="text-gray-600 dark:text-gray-300">User</span>
                          <span className="font-semibold text-gray-900 dark:text-white">{apiLimits.user || '—'}</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-gray-600 dark:text-gray-300">Scan start</span>
                          <span className="font-semibold text-gray-900 dark:text-white">{apiLimits.scan_start || '—'}</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-gray-600 dark:text-gray-300">Scan stop</span>
                          <span className="font-semibold text-gray-900 dark:text-white">{apiLimits.scan_stop || '—'}</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-gray-600 dark:text-gray-300">Export</span>
                          <span className="font-semibold text-gray-900 dark:text-white">{apiLimits.export || '—'}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Legal acceptance */}
            <div className="ui-card p-6">
              <h2 className="text-xl font-semibold mb-2 text-gray-900 dark:text-white">Legal & Compliance</h2>
              <p className="text-sm text-gray-600 dark:text-gray-300 mb-4">
                Your acceptance of our legal documents is recorded for audit and abuse prevention.
              </p>

              {me?.legal_acceptance ? (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-600 dark:text-gray-300">Last acceptance</span>
                    <span className="font-semibold text-gray-900 dark:text-white">
                      {me.legal_acceptance.accepted_at
                        ? format(new Date(me.legal_acceptance.accepted_at), 'PPP p')
                        : '—'}
                    </span>
                  </div>

                  <div className="border-t border-gray-200 dark:border-gray-700 pt-3">
                    <div className="text-sm text-gray-700 dark:text-gray-200 font-semibold mb-2">Document versions</div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                      <div className="flex items-center justify-between">
                        <span className="text-gray-600 dark:text-gray-300">Terms</span>
                        <span className="font-mono text-xs text-gray-900 dark:text-gray-100">
                          {me.legal_acceptance.documents?.terms || '—'}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-gray-600 dark:text-gray-300">Privacy</span>
                        <span className="font-mono text-xs text-gray-900 dark:text-gray-100">
                          {me.legal_acceptance.documents?.privacy || '—'}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-gray-600 dark:text-gray-300">Disclaimer</span>
                        <span className="font-mono text-xs text-gray-900 dark:text-gray-100">
                          {me.legal_acceptance.documents?.disclaimer || '—'}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-gray-600 dark:text-gray-300">AUP</span>
                        <span className="font-mono text-xs text-gray-900 dark:text-gray-100">
                          {me.legal_acceptance.documents?.aup || '—'}
                        </span>
                      </div>
                    </div>

                    <div className="mt-4 text-xs text-gray-500 dark:text-gray-300">
                      Links: <Link className="ui-link" to="/terms" target="_blank">Terms</Link>,{' '}
                      <Link className="ui-link" to="/privacy" target="_blank">Privacy</Link>,{' '}
                      <Link className="ui-link" to="/disclaimer" target="_blank">Disclaimer</Link>,{' '}
                      <Link className="ui-link" to="/aup" target="_blank">AUP</Link>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="ui-alert ui-alert-warning">
                  No legal acceptance record found for this account yet.
                </div>
              )}
            </div>

            {/* Security (2FA) */}
            <div className="ui-card p-6">
              <h2 className="text-xl font-semibold mb-2 text-gray-900 dark:text-white">Security</h2>
              <p className="text-sm text-gray-600 dark:text-gray-300 mb-4">
                Two-factor authentication (TOTP) adds an extra layer of protection.
              </p>

              {twoFactorError && (
                <div className="ui-alert ui-alert-error mb-4">{twoFactorError}</div>
              )}

              {twoFactorToast && (
                <div className="ui-alert ui-alert-success mb-4">{twoFactorToast}</div>
              )}

              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2 text-gray-700 dark:text-gray-200">
                  <FiShield />
                  <span className="font-semibold">2FA Status</span>
                </div>
                {twoFactorStatus?.enabled ? (
                  <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm font-semibold">Enabled</span>
                ) : (
                  <span className="px-3 py-1 bg-yellow-100 text-yellow-800 rounded-full text-sm font-semibold">Disabled</span>
                )}
              </div>

              {!twoFactorStatus?.enabled && (
                <div className="space-y-4">
                  <button
                    type="button"
                    onClick={startTwoFactorSetup}
                    className="ui-btn ui-btn-primary"
                    disabled={twoFactorLoading}
                  >
                    Start 2FA Setup
                  </button>

                  {twoFactorSetup && (
                    <div className="ui-card p-4 bg-gray-50 dark:bg-gray-800/50 border border-gray-200/60 dark:border-gray-700/60">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="text-sm text-gray-700 dark:text-gray-200">
                          <div className="font-semibold mb-2">1) Scan QR in your authenticator app</div>
                          <div className="mb-2">Account: <span className="font-mono">{me?.email || userEmail}</span></div>

                          <div className="mt-3">
                            <div className="text-xs text-gray-500 dark:text-gray-300 mb-1">Manual entry secret</div>
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs break-all">{twoFactorSetup.secret}</span>
                              <button
                                type="button"
                                className="ui-btn ui-btn-secondary"
                                onClick={() => copyToClipboard(twoFactorSetup.secret, 'Secret copied')}
                              >
                                Copy
                              </button>
                            </div>
                          </div>

                          <div className="mt-3">
                            <button
                              type="button"
                              className="ui-btn ui-btn-secondary"
                              onClick={() => copyToClipboard(twoFactorSetup.otpauth_url, 'Setup link copied')}
                            >
                              Copy setup link
                            </button>
                          </div>
                        </div>

                        <div className="flex items-center justify-center">
                          <div className="bg-white p-3 rounded-lg border border-gray-200">
                            <QRCode value={twoFactorSetup.otpauth_url} size={180} />
                          </div>
                        </div>
                      </div>

                      <div className="mt-4">
                        <div className="font-semibold mb-2">2) Confirm with a 6-digit code</div>
                        <input
                          type="text"
                          value={twoFactorConfirmCode}
                          onChange={(e) => setTwoFactorConfirmCode(e.target.value)}
                          className="ui-input"
                          placeholder="123456"
                        />
                        <button
                          type="button"
                          onClick={confirmTwoFactorSetup}
                          className="ui-btn ui-btn-primary mt-3"
                          disabled={!twoFactorConfirmCode || twoFactorLoading}
                        >
                          Confirm & Enable 2FA
                        </button>
                        <p className="text-xs text-gray-500 dark:text-gray-300 mt-2">
                          Keep your backup codes safe. They will be shown once.
                        </p>
                      </div>
                    </div>
                  )}

                  {twoFactorBackupCodes && (
                    <div className="ui-alert ui-alert-warning">
                      <div className="flex items-start gap-2">
                        <FiAlertTriangle className="mt-0.5" />
                        <div>
                          <div className="font-semibold mb-2">Backup codes (shown once)</div>
                          <div className="flex flex-wrap gap-2 mb-3">
                            <button type="button" className="ui-btn ui-btn-secondary" onClick={downloadBackupCodes}>
                              <FiDownload className="mr-2" /> Download
                            </button>
                            <button type="button" className="ui-btn ui-btn-secondary" onClick={printBackupCodes}>
                              <FiPrinter className="mr-2" /> Print
                            </button>
                            <button
                              type="button"
                              className="ui-btn ui-btn-secondary"
                              onClick={() => copyToClipboard(twoFactorBackupCodes.join('\n'), 'Backup codes copied')}
                            >
                              Copy all
                            </button>
                          </div>
                          <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                            {twoFactorBackupCodes.map((c) => (
                              <div key={c} className="px-2 py-1 bg-white/80 dark:bg-gray-900/40 rounded border border-gray-200/60 dark:border-gray-700/60">
                                {c}
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {twoFactorStatus?.enabled && (
                <div className="space-y-4">
                  <div className="ui-card p-4 bg-gray-50 dark:bg-gray-800/50 border border-gray-200/60 dark:border-gray-700/60">
                    <div className="font-semibold mb-2">Sensitive actions</div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div>
                        <label className="block text-sm font-semibold text-gray-700 dark:text-gray-200 mb-1">Password</label>
                        <input
                          type="password"
                          value={twoFactorActionPassword}
                          onChange={(e) => setTwoFactorActionPassword(e.target.value)}
                          className="ui-input"
                          placeholder="••••••••"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-semibold text-gray-700 dark:text-gray-200 mb-1">2FA Code</label>
                        <input
                          type="text"
                          value={twoFactorActionCode}
                          onChange={(e) => setTwoFactorActionCode(e.target.value)}
                          className="ui-input"
                          placeholder="123456 or backup"
                        />
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-2 mt-3">
                      <button
                        type="button"
                        onClick={regenerateBackupCodes}
                        className="ui-btn ui-btn-secondary"
                        disabled={!twoFactorActionPassword || !twoFactorActionCode || twoFactorLoading}
                      >
                        Regenerate Backup Codes
                      </button>
                      <button
                        type="button"
                        onClick={disableTwoFactor}
                        className="ui-btn ui-btn-secondary text-red-700 dark:text-red-200"
                        disabled={!twoFactorActionPassword || !twoFactorActionCode || twoFactorLoading}
                      >
                        Disable 2FA
                      </button>
                    </div>
                  </div>

                  {twoFactorBackupCodes && (
                    <div className="ui-alert ui-alert-warning">
                      <div className="flex items-start gap-2">
                        <FiAlertTriangle className="mt-0.5" />
                        <div>
                          <div className="font-semibold mb-2">Backup codes (shown once)</div>
                          <div className="flex flex-wrap gap-2 mb-3">
                            <button type="button" className="ui-btn ui-btn-secondary" onClick={downloadBackupCodes}>
                              <FiDownload className="mr-2" /> Download
                            </button>
                            <button type="button" className="ui-btn ui-btn-secondary" onClick={printBackupCodes}>
                              <FiPrinter className="mr-2" /> Print
                            </button>
                            <button
                              type="button"
                              className="ui-btn ui-btn-secondary"
                              onClick={() => copyToClipboard(twoFactorBackupCodes.join('\n'), 'Backup codes copied')}
                            >
                              Copy all
                            </button>
                          </div>
                          <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                            {twoFactorBackupCodes.map((c) => (
                              <div key={c} className="px-2 py-1 bg-white/80 dark:bg-gray-900/40 rounded border border-gray-200/60 dark:border-gray-700/60">
                                {c}
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Verified Domains */}
            <div className="ui-card p-6">
              <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">Verified Domains</h2>
              <VerifiedDomainsPanel />
            </div>

            {/* Monthly Stats */}
            <div className="ui-card p-6">
              <h2 className="text-xl font-semibold mb-6 text-gray-900 dark:text-white">Monthly Statistics</h2>
              {(profileLoading || scansLoading) && (
                <div className="text-sm text-gray-500 dark:text-gray-300 mb-4">Loading statistics...</div>
              )}
              {(profileError || scansError) && (
                <div className="ui-alert ui-alert-error mb-4">
                  Failed to load profile data. Please refresh and try again.
                </div>
              )}
              <div className="grid grid-cols-2 gap-6">
                <StatBox
                  label="Scans This Month"
                  value={profile?.monthly_scans || 0}
                  icon={<FiActivity />}
                  color="blue"
                />
                <StatBox
                  label="Vulnerabilities Found"
                  value={profile?.monthly_vulnerabilities || 0}
                  icon={<FiShield />}
                  color="red"
                />
                <StatBox
                  label="Critical Issues"
                  value={profile?.monthly_critical || 0}
                  icon={<FiAward />}
                  color="orange"
                />
                <StatBox
                  label="Scans Completed"
                  value={profile?.monthly_completed || 0}
                  icon={<FiActivity />}
                  color="green"
                />
              </div>
            </div>

            {/* Activity Log */}
            <div className="ui-card p-6">
              <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">Scan History</h2>
              {isPrivilegedUser && (
                <p className="mb-4 text-sm text-gray-600 dark:text-gray-300">
                  Admin view: showing scans across all registered users.
                </p>
              )}
              
              {/* Filter Tabs */}
              <div className="flex gap-2 mb-4 border-b border-gray-200 dark:border-gray-700">
                <button
                  onClick={() => setScanFilter('all')}
                  className={`px-4 py-2 font-semibold transition ${
                    scanFilter === 'all'
                      ? 'text-primary border-b-2 border-primary'
                      : 'text-gray-600 hover:text-gray-900 dark:text-gray-300 dark:hover:text-white'
                  }`}
                >
                  All
                </button>
                <button
                  onClick={() => setScanFilter('completed')}
                  className={`px-4 py-2 font-semibold transition ${
                    scanFilter === 'completed'
                      ? 'text-primary border-b-2 border-primary'
                      : 'text-gray-600 hover:text-gray-900 dark:text-gray-300 dark:hover:text-white'
                  }`}
                >
                  Completed
                </button>
                <button
                  onClick={() => setScanFilter('running')}
                  className={`px-4 py-2 font-semibold transition ${
                    scanFilter === 'running'
                      ? 'text-primary border-b-2 border-primary'
                      : 'text-gray-600 hover:text-gray-900 dark:text-gray-300 dark:hover:text-white'
                  }`}
                >
                  Running
                </button>
                <button
                  onClick={() => setScanFilter('failed')}
                  className={`px-4 py-2 font-semibold transition ${
                    scanFilter === 'failed'
                      ? 'text-primary border-b-2 border-primary'
                      : 'text-gray-600 hover:text-gray-900 dark:text-gray-300 dark:hover:text-white'
                  }`}
                >
                  Failed
                </button>
              </div>

              {/* Scans Table */}
                {scansLoading ? (
                  <div className="text-center py-8 text-gray-500 dark:text-gray-300">
                    {isPrivilegedUser ? 'Loading scans across all users...' : 'Loading scans...'}
                  </div>
                ) : filteredScans.length === 0 ? (
                <div className="text-center py-8 text-gray-500 dark:text-gray-300">
                  {isPrivilegedUser ? 'No scans found for any registered user' : 'No scans found'}
                </div>
              ) : (
                <div className="ui-table-wrap">
                  <table className="min-w-[900px] w-full">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-700">
                        <th className="text-left py-3 px-4 text-sm font-semibold text-gray-900 dark:text-white">Target</th>
                        <th className="text-left py-3 px-4 text-sm font-semibold text-gray-900 dark:text-white">Type</th>
                        <th className="text-left py-3 px-4 text-sm font-semibold text-gray-900 dark:text-white">Status</th>
                        <th className="text-left py-3 px-4 text-sm font-semibold text-gray-900 dark:text-white">Findings</th>
                        <th className="text-left py-3 px-4 text-sm font-semibold text-gray-900 dark:text-white">Date</th>
                        <th className="text-left py-3 px-4 text-sm font-semibold text-gray-900 dark:text-white">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredScans.map((scan) => (
                        <tr key={scan.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-900/30">
                          <td className="py-3 px-4 text-sm text-gray-900 dark:text-gray-100">
                            <div>{scan.target}</div>
                            {isPrivilegedUser && (
                              <div className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                Owner: {scan.user_email || 'Unknown user'}
                              </div>
                            )}
                          </td>
                          <td className="py-3 px-4 text-sm text-gray-600 dark:text-gray-300">{scan.scan_category || scan.scan_type || 'General'}</td>
                          <td className="py-3 px-4">
                            <StatusBadge status={scan.status} />
                          </td>
                          <td className="py-3 px-4">
                            {scan.vulnerabilities_found > 0 ? (
                              <span className="flex items-center gap-1 text-red-600 font-semibold text-sm">
                                <FiAlertTriangle size={14} />
                                {scan.vulnerabilities_found}
                              </span>
                            ) : (
                              <span className="text-sm text-gray-500 dark:text-gray-300">0</span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-sm text-gray-600 dark:text-gray-300">
                            {format(new Date(scan.created_at), 'MMM dd, HH:mm')}
                          </td>
                          <td className="py-3 px-4">
                            <Link
                              to={`/scan/details/${scan.id}`}
                              className="text-primary hover:text-primary-600 text-sm font-semibold"
                            >
                              View
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>

                  <div className="pt-4">
                    <PaginationControls
                      page={scanPage}
                      totalPages={totalScanPages}
                      hasPrev={scanPage > 1 && !scansLoading}
                      hasNext={!!scansData?.next && !scansLoading}
                      onPrev={() => setScanPage((p) => Math.max(1, p - 1))}
                      onNext={() => setScanPage((p) => p + 1)}
                    />
                  </div>
                </div>
              )}
              
              {/* Export Button */}
              {scans.length > 0 && (
                <div className="mt-4 flex justify-end">
                  <button
                    onClick={exportHistoryCsv}
                    className="flex items-center gap-2 px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg transition dark:bg-gray-800 dark:text-gray-200 dark:hover:bg-gray-700"
                  >
                    <FiDownload size={16} />
                    Export History
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Sidebar - Daily Stats */}
          <div className="lg:col-span-1">
            <div className="ui-card p-6 sticky top-8">
              <h2 className="text-xl font-semibold mb-6 text-gray-900 dark:text-white">Today's Activity</h2>
              <div className="space-y-6">
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-gray-600 dark:text-gray-300">Daily Scans</span>
                    <span className="text-2xl font-bold text-primary">{profile?.daily_scans || 0}</span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-800 rounded-full h-2">
                    <div
                      className="bg-primary h-2 rounded-full"
                      style={{ width: `${Math.min((profile?.daily_scans || 0) / 10 * 100, 100)}%` }}
                    ></div>
                  </div>
                  <p className="text-xs text-gray-500 dark:text-gray-300 mt-1">Limit: 10 per day</p>
                </div>

                <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
                  <h3 className="font-semibold mb-3 text-gray-900 dark:text-white">Quick Stats</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-gray-600 dark:text-gray-300 text-sm">Running Scans</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{profile?.running_scans || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600 dark:text-gray-300 text-sm">Queued</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{profile?.queued_scans || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600 dark:text-gray-300 text-sm">Completed Today</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{profile?.completed_today || 0}</span>
                    </div>
                  </div>
                </div>

                <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
                  <a
                    href="https://www.paypal.com/ncp/payment/9M7YPHHLDZU74"
                    target="_blank"
                    rel="noreferrer"
                    className="w-full block text-center bg-primary text-white py-2 rounded-lg hover:bg-primary-600 transition"
                  >
                    ❤️ Support the Project
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

const StatusBadge = ({ status }) => {
  const styles = {
    pending: 'bg-yellow-100 text-yellow-800',
    running: 'bg-blue-100 text-blue-800',
    completed: 'bg-green-100 text-green-800',
    failed: 'bg-red-100 text-red-800',
  };

  return (
    <span className={`px-2 py-1 rounded-full text-xs font-semibold ${styles[status] || 'bg-gray-100 text-gray-800'}`}>
      {status}
    </span>
  );
};

const StatBox = ({ label, value, icon, color }) => {
  const colors = {
    blue: 'bg-blue-500/10 text-blue-500',
    red: 'bg-red-500/10 text-red-500',
    orange: 'bg-orange-500/10 text-orange-500',
    green: 'bg-green-500/10 text-green-500',
  };

  return (
    <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
      <div className={`inline-flex p-2 rounded-lg ${colors[color]} mb-3`}>
        {React.cloneElement(icon, { size: 20 })}
      </div>
      <p className="text-gray-600 dark:text-gray-300 text-sm mb-1">{label}</p>
      <p className="text-3xl font-bold text-gray-900 dark:text-white">{value}</p>
    </div>
  );
};

export default Profile;
