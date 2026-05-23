import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import {
  FiShield, FiPlus, FiTrash2, FiCheckCircle, FiClock,
  FiAlertTriangle, FiCopy, FiRefreshCw, FiGlobe,
} from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import LoadingState from '../components/states/LoadingState';
import ErrorState from '../components/states/ErrorState';
import { domainVerifyService } from '../services/api';
import { useToast } from '../contexts/ToastContext';

const STATUS_BADGE = {
  verified: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
  pending: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  failed: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
};

export const VerifiedDomainsPanel = () => {
  const toast = useToast();
  const queryClient = useQueryClient();

  const [newDomain, setNewDomain] = useState('');
  const [pendingDetails, setPendingDetails] = useState(null); // token/instructions for a pending domain
  const [checking, setChecking] = useState(''); // domain currently being re-checked

  const { data: domains = [], isLoading, isError, error, refetch } = useQuery(
    'domain-verifications',
    () => domainVerifyService.list().then((r) => r.data),
    { refetchOnWindowFocus: false },
  );

  const initiateMutation = useMutation(
    (domain) => domainVerifyService.initiate(domain).then((r) => r.data),
    {
      onSuccess: (data) => {
        queryClient.invalidateQueries('domain-verifications');
        if (data.status === 'verified') {
          toast.success(`${data.domain} is already verified.`);
          setPendingDetails(null);
        } else {
          setPendingDetails(data);
        }
        setNewDomain('');
      },
      onError: (err) => {
        toast.error(err.response?.data?.error || 'Failed to initiate verification.');
      },
    },
  );

  const removeMutation = useMutation(
    (domain) => domainVerifyService.remove(domain),
    {
      onSuccess: (_, domain) => {
        queryClient.invalidateQueries('domain-verifications');
        toast.success(`${domain} removed.`);
        if (pendingDetails?.domain === domain) setPendingDetails(null);
      },
      onError: () => toast.error('Failed to remove domain.'),
    },
  );

  const handleCheck = async (domain) => {
    setChecking(domain);
    try {
      const res = await domainVerifyService.check(domain);
      const data = res.data;
      if (data.verified) {
        toast.success(`${domain} verified successfully via ${data.method}!`);
        queryClient.invalidateQueries('domain-verifications');
        if (pendingDetails?.domain === domain) setPendingDetails(null);
      } else {
        toast.error(data.error || 'Verification failed. Check the instructions below.');
      }
    } catch (e) {
      toast.error(e.response?.data?.error || 'Check failed.');
    } finally {
      setChecking('');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => toast.success('Copied!'));
  };

  const handleInitiate = (e) => {
    e.preventDefault();
    if (!newDomain.trim()) return;
    initiateMutation.mutate(newDomain.trim());
  };

  // Open pending details for an existing pending domain
  const showInstructions = (record) => {
    if (record.status !== 'verified') {
      setPendingDetails({
        domain: record.domain,
        token: record.dns_txt_value?.split('=')[1] || '',
        instructions: {
          http: {
            url: record.http_challenge_url,
            file_content: record.dns_txt_value?.split('=')[1] || '',
          },
          dns: {
            record_type: 'TXT',
            record_name: record.domain,
            record_value: record.dns_txt_value || '',
          },
        },
      });
    }
  };

  return (
    <div>
      <div className="mb-6">
        <p className="text-sm text-gray-600 dark:text-gray-300">
          Dangerous scanners (command injection, SSRF, XXE, file upload probes, etc.) require you
          to prove you own the target domain before running.
        </p>
      </div>

      {/* How it works */}
        <div className="ui-card p-5 mb-8 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-700/40">
          <h3 className="font-semibold text-blue-900 dark:text-blue-200 mb-2 flex items-center gap-2">
            <FiAlertTriangle /> Why is this required?
          </h3>
          <p className="text-sm text-blue-800 dark:text-blue-100">
            Certain test payloads (OS command injection, blind SSRF callbacks, XXE entity expansion,
            malicious file uploads) can cause real damage to systems you don&apos;t own. Domain
            verification ensures you are an authorised party before these tests run.
          </p>
        </div>

        {/* Add domain form */}
        <div className="ui-card p-6 mb-8">
          <h2 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Add a Domain</h2>
          <form onSubmit={handleInitiate} className="flex gap-3 flex-wrap">
            <input
              type="text"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="example.com"
              className="ui-input flex-1 min-w-[220px]"
            />
            <button
              type="submit"
              disabled={initiateMutation.isLoading || !newDomain.trim()}
              className="ui-btn ui-btn-primary gap-2"
            >
              <FiPlus /> {initiateMutation.isLoading ? 'Adding…' : 'Add Domain'}
            </button>
          </form>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
            Enter the apex domain only (e.g. <code>example.com</code>, not <code>https://www.example.com/path</code>).
          </p>
        </div>

        {/* Pending verification instructions */}
        {pendingDetails && (
          <div className="ui-card p-6 mb-8 border border-yellow-300 dark:border-yellow-600/50 bg-yellow-50 dark:bg-yellow-900/20">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-yellow-900 dark:text-yellow-200 flex items-center gap-2">
                <FiClock /> Verify ownership of <span className="font-mono">{pendingDetails.domain}</span>
              </h2>
              <button
                onClick={() => setPendingDetails(null)}
                className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 text-xl leading-none"
              >
                ✕
              </button>
            </div>

            <p className="text-sm text-yellow-800 dark:text-yellow-100 mb-4">
              Choose <strong>one</strong> of the two methods below, then click &ldquo;Check Now&rdquo;.
            </p>

            {/* Method 1 — HTTP well-known */}
            <div className="mb-4">
              <h3 className="text-sm font-semibold text-gray-800 dark:text-white mb-1">
                Method 1 — HTTP file
              </h3>
              <p className="text-xs text-gray-600 dark:text-gray-300 mb-1">
                Create a plain-text file accessible at:
              </p>
              <div className="flex items-center gap-2 mb-1">
                <code className="text-xs bg-white dark:bg-gray-800 px-2 py-1 rounded border border-gray-200 dark:border-gray-700 flex-1 break-all">
                  {pendingDetails.instructions.http.url}
                </code>
                <button onClick={() => copyToClipboard(pendingDetails.instructions.http.url)} className="text-gray-400 hover:text-primary">
                  <FiCopy />
                </button>
              </div>
              <p className="text-xs text-gray-600 dark:text-gray-300 mb-1">File contents (must contain):</p>
              <div className="flex items-center gap-2">
                <code className="text-xs bg-white dark:bg-gray-800 px-2 py-1 rounded border border-gray-200 dark:border-gray-700 flex-1 font-mono">
                  {pendingDetails.instructions.http.file_content}
                </code>
                <button onClick={() => copyToClipboard(pendingDetails.instructions.http.file_content)} className="text-gray-400 hover:text-primary">
                  <FiCopy />
                </button>
              </div>
            </div>

            {/* Method 2 — DNS TXT */}
            <div className="mb-5">
              <h3 className="text-sm font-semibold text-gray-800 dark:text-white mb-1">
                Method 2 — DNS TXT record
              </h3>
              <p className="text-xs text-gray-600 dark:text-gray-300 mb-1">
                Add a TXT record to <code>{pendingDetails.instructions.dns.record_name}</code>:
              </p>
              <div className="overflow-x-auto">
                <table className="text-xs w-full border border-gray-200 dark:border-gray-700 rounded">
                  <thead className="bg-gray-100 dark:bg-gray-800">
                    <tr>
                      <th className="px-3 py-1 text-left">Type</th>
                      <th className="px-3 py-1 text-left">Name</th>
                      <th className="px-3 py-1 text-left">Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="bg-white dark:bg-gray-900/40">
                      <td className="px-3 py-1 font-mono">TXT</td>
                      <td className="px-3 py-1 font-mono">{pendingDetails.instructions.dns.record_name}</td>
                      <td className="px-3 py-1 font-mono flex items-center gap-2">
                        {pendingDetails.instructions.dns.record_value}
                        <button onClick={() => copyToClipboard(pendingDetails.instructions.dns.record_value)} className="text-gray-400 hover:text-primary">
                          <FiCopy />
                        </button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                DNS changes can take up to 30 minutes to propagate.
              </p>
            </div>

            <button
              onClick={() => handleCheck(pendingDetails.domain)}
              disabled={checking === pendingDetails.domain}
              className="ui-btn ui-btn-primary gap-2"
            >
              <FiRefreshCw className={checking === pendingDetails.domain ? 'animate-spin' : ''} />
              {checking === pendingDetails.domain ? 'Checking…' : 'Check Now'}
            </button>
          </div>
        )}

        {/* Domain list */}
        {isLoading && (
          <LoadingState title="Loading domains" minHeightClassName="min-h-[20vh]" />
        )}
        {!isLoading && isError && (
          <ErrorState
            title="Failed to load domains"
            message={error?.message}
            action={<button onClick={() => refetch()} className="ui-btn ui-btn-primary">Retry</button>}
            minHeightClassName="min-h-[20vh]"
          />
        )}
        {!isLoading && !isError && domains.length === 0 && (
          <div className="text-center py-12 text-gray-500 dark:text-gray-400">
            <FiGlobe size={40} className="mx-auto mb-3 opacity-40" />
            <p>No domains added yet.</p>
          </div>
        )}
        {!isLoading && !isError && domains.length > 0 && (
          <div className="ui-card overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 dark:bg-gray-800/60 border-b border-gray-200 dark:border-gray-700">
                <tr>
                  <th className="px-4 py-3 text-left font-semibold text-gray-700 dark:text-gray-300">Domain</th>
                  <th className="px-4 py-3 text-left font-semibold text-gray-700 dark:text-gray-300">Status</th>
                  <th className="px-4 py-3 text-left font-semibold text-gray-700 dark:text-gray-300">Verified at</th>
                  <th className="px-4 py-3 text-right font-semibold text-gray-700 dark:text-gray-300">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700/50">
                {domains.map((d) => (
                  <tr key={d.domain} className="hover:bg-gray-50/50 dark:hover:bg-gray-800/30 transition-colors">
                    <td className="px-4 py-3 font-mono font-medium text-gray-900 dark:text-white">
                      {d.domain}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 rounded-full text-xs font-semibold ${STATUS_BADGE[d.status] || STATUS_BADGE.pending}`}>
                        {d.status === 'verified' && <FiCheckCircle className="inline mr-1" />}
                        {d.status === 'pending' && <FiClock className="inline mr-1" />}
                        {d.status.charAt(0).toUpperCase() + d.status.slice(1)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-500 dark:text-gray-400 text-xs">
                      {d.verified_at ? new Date(d.verified_at).toLocaleString() : '—'}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        {d.status !== 'verified' && (
                          <>
                            <button
                              onClick={() => showInstructions(d)}
                              className="text-xs text-blue-600 hover:text-blue-800 dark:text-blue-400"
                            >
                              Instructions
                            </button>
                            <button
                              onClick={() => handleCheck(d.domain)}
                              disabled={checking === d.domain}
                              className="text-xs text-green-600 hover:text-green-800 dark:text-green-400 flex items-center gap-1"
                            >
                              <FiRefreshCw size={12} className={checking === d.domain ? 'animate-spin' : ''} />
                              Check
                            </button>
                          </>
                        )}
                        <button
                          onClick={() => removeMutation.mutate(d.domain)}
                          disabled={removeMutation.isLoading}
                          className="text-red-500 hover:text-red-700 dark:hover:text-red-400"
                          title="Remove"
                        >
                          <FiTrash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
    </div>
  );
};

const VerifiedDomains = () => (
  <DashboardLayout>
    <div className="ui-page">
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <FiShield className="text-primary" size={28} />
          <h1 className="ui-title">Verified Domains</h1>
        </div>
        <p className="ui-subtitle">
          Dangerous scanners (command injection, SSRF, XXE, file upload probes, etc.) require you
          to prove you own the target domain before running.
        </p>
      </div>
      <VerifiedDomainsPanel />
    </div>
  </DashboardLayout>
);

export default VerifiedDomains;
