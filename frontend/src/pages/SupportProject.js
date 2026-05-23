import React, { useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { FiArrowRight } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import LoadingState from '../components/states/LoadingState';

const SupportProject = () => {
  const donateUrl = process.env.REACT_APP_DONATE_URL;
  const location = useLocation();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(false);
  }, []);

  const redirectNotice = useMemo(() => {
    const params = new URLSearchParams(location.search);
    const source = params.get('source');

    if (source === 'legacy-payment') {
      return 'Legacy payment confirmation pages are disabled in the free public edition. Support links stay here.';
    }
    if (source === 'legacy-pricing' || source === 'legacy-subscription') {
      return 'Pricing and subscription pages are disabled in the free public edition.';
    }
    return null;
  }, [location.search]);

  return (
    <DashboardLayout>
      <div className="ui-page">
        <div className="mb-8">
          <h1 className="ui-title">Support the Project</h1>
          <p className="ui-subtitle mt-2">
            This public edition is free. Donations are optional and help cover infrastructure, maintenance, and community support.
          </p>
        </div>

        {redirectNotice ? (
          <div className="ui-alert ui-alert-info mb-6">{redirectNotice}</div>
        ) : null}

        {loading ? (
          <LoadingState title="Loading" subtitle="Preparing project support options..." />
        ) : (
          <div className="ui-card p-6">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-2">Keep the free edition sustainable</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              BugBounty Arsenal stays free in this public release. If you want to help, you can support hosting and continued development with an optional donation.
            </p>

            {donateUrl ? (
              <a
                href={donateUrl}
                target="_blank"
                rel="noreferrer"
                className="ui-btn ui-btn-primary inline-flex items-center gap-2"
              >
                <FiArrowRight /> Donate with PayPal
              </a>
            ) : (
              <div className="ui-alert ui-alert-warning">Donation link is not configured.</div>
            )}
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default SupportProject;