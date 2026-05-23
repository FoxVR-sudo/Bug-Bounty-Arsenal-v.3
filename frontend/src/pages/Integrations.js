import React, { useMemo, useState, useEffect, useRef } from 'react';
import { FiCheck, FiX, FiSend, FiSettings } from 'react-icons/fi';
import { SiSlack, SiJira, SiDiscord, SiTelegram, SiGithub, SiGitlab } from 'react-icons/si';
import { MdEmail } from 'react-icons/md';
import { FiGlobe } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import LoadingState from '../components/states/LoadingState';
import ErrorState from '../components/states/ErrorState';
import FieldError from '../components/forms/FieldError';
import { isNonEmpty } from '../lib/validation';
import api from '../services/api';
import useModalA11y from '../hooks/useModalA11y';

const Integrations = () => {
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [modalError, setModalError] = useState('');
  const [selectedIntegration, setSelectedIntegration] = useState(null);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [configTouched, setConfigTouched] = useState({ api_key: false, webhook_url: false, channel: false });
  
  // Config form state
  const [config, setConfig] = useState({
    enabled: false,
    api_key: '',
    webhook_url: '',
    channel: '',
    events: {
      scan_started: true,
      scan_completed: true,
      vulnerability_found: true,
      scan_failed: false,
    }
  });

  const configModalRef = useModalA11y(showConfigModal, {
    onClose: () => setShowConfigModal(false),
  });
  const configTitleIdRef = useRef(`integration-config-title-${Math.random().toString(36).slice(2)}`);
  const configDescIdRef = useRef(`integration-config-desc-${Math.random().toString(36).slice(2)}`);

  const availableIntegrations = [
    {
      id: 'slack',
      name: 'Slack',
      icon: SiSlack,
      color: 'text-purple-600',
      bgColor: 'bg-purple-50 dark:bg-purple-500/10',
      description: 'Send scan results to Slack channels',
      fields: ['webhook_url', 'channel'],
      placeholder: {
        webhook_url: 'Slack webhook URL',
        channel: '#security-alerts'
      }
    },
    {
      id: 'jira',
      name: 'Jira',
      icon: SiJira,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50 dark:bg-blue-500/10',
      description: 'Create Jira tickets for vulnerabilities',
      fields: ['api_key', 'webhook_url'],
      placeholder: {
        api_key: 'Jira API token',
        webhook_url: 'https://your-domain.atlassian.net'
      }
    },
    {
      id: 'discord',
      name: 'Discord',
      icon: SiDiscord,
      color: 'text-indigo-600',
      bgColor: 'bg-indigo-50 dark:bg-indigo-500/10',
      description: 'Post alerts to Discord channels',
      fields: ['webhook_url'],
      placeholder: {
        webhook_url: 'Discord webhook URL'
      }
    },
    {
      id: 'telegram',
      name: 'Telegram',
      icon: SiTelegram,
      color: 'text-sky-600',
      bgColor: 'bg-sky-50 dark:bg-sky-500/10',
      description: 'Send notifications to Telegram',
      fields: ['api_key', 'channel'],
      placeholder: {
        api_key: 'Telegram bot token',
        channel: '@your_channel or chat_id'
      }
    },
    {
      id: 'github',
      name: 'GitHub',
      icon: SiGithub,
      color: 'text-gray-900 dark:text-gray-100',
      bgColor: 'bg-gray-50 dark:bg-gray-500/10',
      description: 'Create GitHub issues for findings',
      fields: ['api_key', 'webhook_url'],
      placeholder: {
        api_key: 'GitHub personal access token',
        webhook_url: 'owner/repository'
      }
    },
    {
      id: 'gitlab',
      name: 'GitLab',
      icon: SiGitlab,
      color: 'text-orange-600',
      bgColor: 'bg-orange-50 dark:bg-orange-500/10',
      description: 'Create GitLab issues automatically',
      fields: ['api_key', 'webhook_url'],
      placeholder: {
        api_key: 'GitLab access token',
        webhook_url: 'project_id or group/project'
      }
    },
    {
      id: 'webhook',
      name: 'Custom Webhook',
      icon: FiGlobe,
      color: 'text-green-600',
      bgColor: 'bg-green-50 dark:bg-green-500/10',
      description: 'Send events to custom endpoints',
      fields: ['webhook_url', 'api_key'],
      placeholder: {
        webhook_url: 'https://your-api.com/webhook',
        api_key: 'Optional shared secret'
      }
    },
    {
      id: 'email',
      name: 'Email',
      icon: MdEmail,
      color: 'text-red-600',
      bgColor: 'bg-red-50 dark:bg-red-500/10',
      description: 'Email notifications for scan results',
      fields: ['channel'],
      placeholder: {
        channel: 'security-team@company.com'
      }
    }
  ];

  useEffect(() => {
    fetchIntegrations();
  }, []);

  const fetchIntegrations = async () => {
    setLoading(true);
    try {
      const response = await api.get('/integrations/');
      setIntegrations(response.data.results || response.data);
    } catch (err) {
      setError('Failed to load integrations');
    } finally {
      setLoading(false);
    }
  };

  const handleOpenConfig = (integrationType) => {
    const existing = integrations.find(i => i.integration_type === integrationType);

    const existingEventsRaw = existing?.events;
    const existingEvents = Array.isArray(existingEventsRaw)
      ? Object.fromEntries(existingEventsRaw.map((e) => [e, true]))
      : (existingEventsRaw || null);
    
    if (existing) {
      setConfig({
        enabled: existing.enabled ?? existing.is_active ?? false,
        api_key: existing.config?.api_key || '',
        webhook_url: existing.config?.webhook_url || '',
        channel: existing.config?.channel || '',
        events: existingEvents || {
          scan_started: true,
          scan_completed: true,
          vulnerability_found: true,
          scan_failed: false,
        }
      });
      setSelectedIntegration({
        ...availableIntegrations.find(i => i.id === integrationType),
        existing: true,
        integrationId: existing.id,
      });
    } else {
      setConfig({
        enabled: true,
        api_key: '',
        webhook_url: '',
        channel: '',
        events: {
          scan_started: true,
          scan_completed: true,
          vulnerability_found: true,
          scan_failed: false,
        }
      });
      setSelectedIntegration({ ...availableIntegrations.find(i => i.id === integrationType), existing: false, integrationId: null });
    }

    setConfigTouched({ api_key: false, webhook_url: false, channel: false });
    setModalError('');
    setShowConfigModal(true);
  };

  const requiredFields = useMemo(() => {
    if (!selectedIntegration) return { api_key: false, webhook_url: false, channel: false };
    const webhookRequired =
      selectedIntegration.fields.includes('webhook_url') &&
      !['webhook', 'github', 'gitlab'].includes(selectedIntegration.id);
    const apiKeyRequired =
      selectedIntegration.fields.includes('api_key') &&
      selectedIntegration.id !== 'webhook';
    const channelRequired = selectedIntegration.id === 'email' && selectedIntegration.fields.includes('channel');
    return { api_key: apiKeyRequired, webhook_url: webhookRequired, channel: channelRequired };
  }, [selectedIntegration]);

  const effectiveRequiredFields = useMemo(() => {
    if (!config.enabled) return { api_key: false, webhook_url: false, channel: false };
    return requiredFields;
  }, [config.enabled, requiredFields]);

  const configErrors = useMemo(() => {
    return {
      api_key: effectiveRequiredFields.api_key && !isNonEmpty(config.api_key) ? 'API key is required.' : null,
      webhook_url: effectiveRequiredFields.webhook_url && !isNonEmpty(config.webhook_url) ? 'Webhook URL is required.' : null,
      channel: effectiveRequiredFields.channel && !isNonEmpty(config.channel) ? 'Recipient is required.' : null,
    };
  }, [config.api_key, config.channel, config.webhook_url, effectiveRequiredFields]);

  const hasConfigErrors = useMemo(() => {
    return Object.values(configErrors).some(Boolean);
  }, [configErrors]);

  const handleSaveIntegration = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (hasConfigErrors) {
      setConfigTouched({
        api_key: configTouched.api_key || effectiveRequiredFields.api_key,
        webhook_url: configTouched.webhook_url || effectiveRequiredFields.webhook_url,
        channel: configTouched.channel || effectiveRequiredFields.channel,
      });
      return;
    }

    try {
      const payload = {
        integration_type: selectedIntegration.id,
        name: selectedIntegration.name,
        enabled: config.enabled,
        config: {
          api_key: config.api_key,
          webhook_url: config.webhook_url,
          channel: config.channel,
        },
        events: config.events
      };

      if (selectedIntegration.existing) {
        // Update existing
        await api.put(`/integrations/${selectedIntegration.integrationId}/`, payload);
        setSuccess('Integration updated successfully!');
      } else {
        // Create new
        await api.post('/integrations/', payload);
        setSuccess('Integration created successfully!');
      }

      setShowConfigModal(false);
      fetchIntegrations();
    } catch (err) {
      const msg = err.response?.data?.error || err.response?.data?.detail
        || Object.values(err.response?.data || {}).flat().join(' ') || 'Failed to save integration';
      setModalError(msg);
    }
  };

  const handleTestIntegration = async () => {
    setModalError('');
    
    try {
      await api.post(`/integrations/${selectedIntegration.integrationId}/test/`, {});
      setSuccess('Test notification sent successfully!');
    } catch (err) {
      const msg = err.response?.data?.message || err.response?.data?.error || 'Failed to send test notification';
      setModalError(msg);
    }
  };

  const handleToggleIntegration = async (integrationId, enabled) => {
    try {
      await api.patch(`/integrations/${integrationId}/`, { enabled: !enabled });
      fetchIntegrations();
    } catch (err) {
      setError('Failed to toggle integration');
    }
  };

  if (loading) {
    return (
      <DashboardLayout>
        <LoadingState title="Loading integrations" subtitle="Fetching available integrations…" />
      </DashboardLayout>
    );
  }

  if (error && (!integrations || integrations.length === 0)) {
    return (
      <DashboardLayout>
        <ErrorState
          title="Couldn’t load integrations"
          message={error}
          action={
            <button
              onClick={() => {
                setError('');
                fetchIntegrations();
              }}
              className="ui-btn ui-btn-primary"
            >
              Retry
            </button>
          }
        />
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="ui-page">
        <div className="mb-8">
          <h1 className="ui-title mb-2">Integrations</h1>
          <p className="ui-subtitle">Connect BugBounty Arsenal with your favorite tools</p>
        </div>

        {error && (
          <div className="ui-alert ui-alert-error mb-6 flex items-center justify-between">
            <span>{error}</span>
            <button onClick={() => setError('')} className="ui-btn ui-btn-ghost p-2" aria-label="Dismiss">
              <FiX />
            </button>
          </div>
        )}

        {success && (
          <div className="ui-alert ui-alert-success mb-6 flex items-center justify-between">
            <span>{success}</span>
            <button onClick={() => setSuccess('')} className="ui-btn ui-btn-ghost p-2" aria-label="Dismiss">
              <FiX />
            </button>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {availableIntegrations.map((integration) => {
            const Icon = integration.icon;
            const existing = integrations.find(i => i.integration_type === integration.id);
            const isEnabled = existing ? (existing.enabled ?? existing.is_active ?? false) : false;
            const existingEventsRaw = existing?.events;
            const existingEvents = Array.isArray(existingEventsRaw)
              ? Object.fromEntries(existingEventsRaw.map((e) => [e, true]))
              : (existingEventsRaw || {});

            return (
              <div key={integration.id} className="ui-card rounded-lg hover:shadow-lg transition">
                <div className="p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className={`p-3 rounded-lg ${integration.bgColor}`}>
                      <Icon className={integration.color} size={28} />
                    </div>
                    {existing && (
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={isEnabled}
                          onChange={() => handleToggleIntegration(existing.id, isEnabled)}
                          className="sr-only peer"
                        />
                        <div className="w-11 h-6 bg-gray-200 dark:bg-gray-700 peer-focus:ring-2 peer-focus:ring-primary rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white dark:after:bg-gray-200 after:border-gray-300 dark:after:border-gray-600 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                      </label>
                    )}
                  </div>

                  <h3 className="text-lg font-bold mb-2 text-gray-900 dark:text-white">{integration.name}</h3>
                  <p className="text-sm mb-4 text-gray-600 dark:text-gray-300">{integration.description}</p>

                  {existing && (
                    <div className="mb-4 p-3 rounded border bg-gray-50 dark:bg-gray-900/40 border-gray-200 dark:border-gray-700">
                      <div className="text-xs mb-1 text-gray-500 dark:text-gray-400">Events Configured:</div>
                      <div className="flex flex-wrap gap-1">
                        {Object.entries(existingEvents).filter(([_, v]) => v).map(([event]) => (
                          <span key={event} className="text-xs px-2 py-1 rounded border bg-white dark:bg-gray-950/40 border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-200">
                            {event.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <button
                    onClick={() => handleOpenConfig(integration.id)}
                    className="ui-btn ui-btn-secondary w-full justify-center flex items-center gap-2"
                  >
                    <FiSettings size={16} />
                    {existing ? 'Configure' : 'Setup'}
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        {/* Configuration Modal */}
        {showConfigModal && selectedIntegration && (
          <div
            className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
            onMouseDown={(e) => {
              if (e.target === e.currentTarget) setShowConfigModal(false);
            }}
          >
            <div
              ref={configModalRef}
              role="dialog"
              aria-modal="true"
              aria-labelledby={configTitleIdRef.current}
              aria-describedby={configDescIdRef.current}
              tabIndex={-1}
              className="ui-card rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto bg-white/95 dark:bg-gray-900/80 backdrop-blur-xl border border-gray-200/50 dark:border-gray-700/50"
            >
              <div className="sticky top-0 p-6 bg-white/95 dark:bg-gray-900/90 border-b border-gray-200/50 dark:border-gray-700/50 backdrop-blur-xl">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-center gap-4 min-w-0">
                    <div className={`p-3 rounded-lg ${selectedIntegration.bgColor}`}>
                      {React.createElement(selectedIntegration.icon, { className: selectedIntegration.color, size: 32 })}
                    </div>
                    <div className="min-w-0">
                      <h3
                        id={configTitleIdRef.current}
                        className="text-2xl font-bold text-gray-900 dark:text-white"
                      >
                        {selectedIntegration.name} Integration
                      </h3>
                      <p className="text-sm text-gray-600 dark:text-gray-300">{selectedIntegration.description}</p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setShowConfigModal(false)}
                    className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
                    aria-label="Close dialog"
                  >
                    <FiX size={22} />
                  </button>
                </div>
                <p id={configDescIdRef.current} className="sr-only">
                  Configure integration settings and event triggers.
                </p>
              </div>

              <form onSubmit={handleSaveIntegration} className="p-6">
                {modalError && (
                  <div className="ui-alert ui-alert-error mb-4 flex items-center justify-between">
                    <span>{modalError}</span>
                    <button type="button" onClick={() => setModalError('')} className="ui-btn ui-btn-ghost p-1" aria-label="Dismiss"><FiX /></button>
                  </div>
                )}
                {/* Enable/Disable */}
                <div className="mb-6 flex items-center justify-between p-4 rounded-lg border bg-gray-50 dark:bg-gray-900/40 border-gray-200 dark:border-gray-700">
                  <div>
                    <h4 className="font-semibold text-gray-900 dark:text-white">Enable Integration</h4>
                    <p className="text-sm text-gray-600 dark:text-gray-300">Activate this integration to receive notifications</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={config.enabled}
                      onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
                      className="sr-only peer"
                    />
                    <div className="w-11 h-6 bg-gray-200 dark:bg-gray-700 peer-focus:ring-2 peer-focus:ring-primary rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white dark:after:bg-gray-200 after:border-gray-300 dark:after:border-gray-600 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                  </label>
                </div>

                {/* Configuration Fields */}
                <div className="space-y-4 mb-6">
                  {selectedIntegration.fields.includes('webhook_url') && (
                    <div>
                      <label className="block font-semibold mb-2 text-gray-700 dark:text-gray-200">
                        Webhook URL {selectedIntegration.id !== 'webhook' && selectedIntegration.id !== 'github' && selectedIntegration.id !== 'gitlab' && <span className="text-red-500">*</span>}
                      </label>
                      <input
                        type="text"
                        value={config.webhook_url}
                        onChange={(e) => {
                          setConfig({ ...config, webhook_url: e.target.value });
                          if (!configTouched.webhook_url) setConfigTouched((t) => ({ ...t, webhook_url: true }));
                        }}
                        onBlur={() => setConfigTouched((t) => ({ ...t, webhook_url: true }))}
                        placeholder={selectedIntegration.placeholder.webhook_url}
                        className={`ui-input ${configTouched.webhook_url && configErrors.webhook_url ? 'ui-input-error' : ''}`}
                        aria-invalid={configTouched.webhook_url && !!configErrors.webhook_url}
                        aria-describedby="integration-webhook-url-error"
                      />
                      <div id="integration-webhook-url-error">
                        <FieldError message={configTouched.webhook_url ? configErrors.webhook_url : null} />
                      </div>
                    </div>
                  )}

                  {selectedIntegration.fields.includes('api_key') && (
                    <div>
                      <label className="block font-semibold mb-2 text-gray-700 dark:text-gray-200">
                        API Key / Token {selectedIntegration.id !== 'webhook' && <span className="text-red-500">*</span>}
                      </label>
                      <input
                        type="password"
                        value={config.api_key}
                        onChange={(e) => {
                          setConfig({ ...config, api_key: e.target.value });
                          if (!configTouched.api_key) setConfigTouched((t) => ({ ...t, api_key: true }));
                        }}
                        onBlur={() => setConfigTouched((t) => ({ ...t, api_key: true }))}
                        placeholder={selectedIntegration.placeholder.api_key}
                        className={`ui-input ${configTouched.api_key && configErrors.api_key ? 'ui-input-error' : ''}`}
                        aria-invalid={configTouched.api_key && !!configErrors.api_key}
                        aria-describedby="integration-api-key-error"
                      />
                      <div id="integration-api-key-error">
                        <FieldError message={configTouched.api_key ? configErrors.api_key : null} />
                      </div>
                    </div>
                  )}

                  {selectedIntegration.fields.includes('channel') && (
                    <div>
                      <label className="block font-semibold mb-2 text-gray-700 dark:text-gray-200">
                        Channel / Recipient
                      </label>
                      <input
                        type="text"
                        value={config.channel}
                        onChange={(e) => {
                          setConfig({ ...config, channel: e.target.value });
                          if (!configTouched.channel) setConfigTouched((t) => ({ ...t, channel: true }));
                        }}
                        onBlur={() => setConfigTouched((t) => ({ ...t, channel: true }))}
                        placeholder={selectedIntegration.placeholder.channel}
                        className={`ui-input ${configTouched.channel && configErrors.channel ? 'ui-input-error' : ''}`}
                        aria-invalid={configTouched.channel && !!configErrors.channel}
                        aria-describedby="integration-channel-error"
                      />
                      <div id="integration-channel-error">
                        <FieldError message={configTouched.channel ? configErrors.channel : null} />
                      </div>
                    </div>
                  )}
                </div>

                {/* Event Triggers */}
                <div className="mb-6">
                  <h4 className="font-semibold mb-3 text-gray-900 dark:text-white">Event Triggers</h4>
                  <div className="space-y-2">
                    {Object.keys(config.events).map((event) => (
                      <label key={event} className="flex items-center gap-3 p-3 rounded-lg cursor-pointer border bg-gray-50 dark:bg-gray-900/40 border-gray-200 dark:border-gray-700 hover:bg-gray-100 dark:hover:bg-gray-800/60">
                        <input
                          type="checkbox"
                          checked={config.events[event]}
                          onChange={(e) => setConfig({
                            ...config,
                            events: { ...config.events, [event]: e.target.checked }
                          })}
                          className="w-5 h-5 text-primary rounded focus:ring-2 focus:ring-primary"
                        />
                        <div className="flex-1">
                          <div className="font-semibold capitalize text-gray-900 dark:text-white">
                            {event.replace(/_/g, ' ')}
                          </div>
                          <div className="text-xs text-gray-600 dark:text-gray-300">
                            {event === 'scan_started' && 'Notify when a new scan begins'}
                            {event === 'scan_completed' && 'Notify when a scan finishes successfully'}
                            {event === 'vulnerability_found' && 'Notify when vulnerabilities are detected'}
                            {event === 'scan_failed' && 'Notify when a scan encounters errors'}
                          </div>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex gap-4">
                  <button
                    type="submit"
                    disabled={hasConfigErrors}
                    className="ui-btn ui-btn-primary flex-1 justify-center flex items-center gap-2"
                  >
                    <FiCheck /> Save Configuration
                  </button>
                  {selectedIntegration.existing && (
                    <button
                      type="button"
                      onClick={handleTestIntegration}
                      className="ui-btn bg-green-600 hover:bg-green-700 text-white justify-center flex items-center gap-2"
                    >
                      <FiSend /> Test
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => setShowConfigModal(false)}
                    className="ui-btn ui-btn-secondary"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default Integrations;
