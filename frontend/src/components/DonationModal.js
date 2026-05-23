import React from 'react';
import { FiHeart } from 'react-icons/fi';
import { useNavigate } from 'react-router-dom';

const STORAGE_KEY = 'donation_snoozed_until';

const TIERS = [
  { url: 'https://www.paypal.com/ncp/payment/M5R5PAC3XAT3Q',  days: 7,  label: '$5',  desc: '7 days' },
  { url: 'https://www.paypal.com/ncp/payment/Y8KCDGLLP4A3L', days: 15, label: '$10', desc: '15 days' },
  { url: 'https://www.paypal.com/ncp/payment/4W4K55WXZFHYC', days: 30, label: '$20', desc: '30 days' },
  { url: 'https://www.paypal.com/ncp/payment/5S5MWLGXS4V7U', days: 90, label: '$50', desc: '90 days' },
];

export const isDonationSnoozed = () => {
  try {
    const until = localStorage.getItem(STORAGE_KEY);
    if (!until) return false;
    return Date.now() < Number(until);
  } catch (_) {
    return false;
  }
};

const snoozeDonation = (days) => {
  try {
    const until = Date.now() + days * 24 * 60 * 60 * 1000;
    localStorage.setItem(STORAGE_KEY, String(until));
  } catch (_) {}
};

const DonationModal = ({ onClose, scanId, reason }) => {
  const navigate = useNavigate();
  const [selectedTier, setSelectedTier] = React.useState(null);
  const isRateLimit = reason === 'rateLimit';

  const handleTier = (tier) => {
    setSelectedTier(tier);
    window.open(tier.url, '_blank', 'noreferrer');
  };

  const handleDonated = () => {
    if (selectedTier) snoozeDonation(selectedTier.days);
    onClose();
    if (scanId) navigate(`/results/${scanId}`);
  };

  const handleLater = () => {
    onClose();
    if (scanId) navigate(`/results/${scanId}`);
  };

  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
      onMouseDown={(e) => { if (e.target === e.currentTarget) handleLater(); }}
    >
      <div className="ui-card rounded-2xl shadow-2xl border max-w-md w-full p-8 text-center bg-white dark:bg-gray-900 border-gray-200/50 dark:border-gray-700/50">
        <div className="mx-auto w-16 h-16 bg-red-50 dark:bg-red-900/20 rounded-full flex items-center justify-center mb-4">
          <FiHeart className="text-red-500" size={32} />
        </div>
        <h3 className="text-2xl font-bold mb-2 text-gray-900 dark:text-white">
          {isRateLimit ? 'Rate limit reached 🚦' : 'Scan Complete! 🎉'}
        </h3>
        <p className="text-gray-600 dark:text-gray-300 mb-5 text-sm leading-relaxed">
          {isRateLimit
            ? 'You\'ve hit the hourly request limit. Support BugBounty Arsenal to unlock higher limits and keep the service running.'
            : 'BugBounty Arsenal is free and open source. Support its development and hide this popup for a while.'}
        </p>

        <div className="grid grid-cols-4 gap-2 mb-5">
          {TIERS.map((tier) => (
            <button
              key={tier.label}
              type="button"
              onClick={() => handleTier(tier)}
              className={`flex flex-col items-center gap-1 rounded-xl border-2 transition p-3 group ${
                selectedTier?.label === tier.label
                  ? 'border-primary bg-primary/10 dark:bg-primary/20'
                  : 'border-gray-200 dark:border-gray-700 hover:border-primary bg-gray-50 dark:bg-gray-800 hover:bg-primary/5'
              }`}
            >
              <span className="text-lg font-bold text-gray-900 dark:text-white group-hover:text-primary transition">{tier.label}</span>
              <span className="text-xs text-gray-500 dark:text-gray-400">{tier.desc}</span>
            </button>
          ))}
        </div>

        {selectedTier && (
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
            After completing payment, click "I've donated" to hide this popup for {selectedTier.days} days.
          </p>
        )}

        <div className="flex flex-col gap-2">
          <button
            type="button"
            onClick={handleDonated}
            disabled={!selectedTier}
            className="ui-btn ui-btn-secondary px-6 py-2.5 gap-2 inline-flex items-center justify-center text-sm disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <FiHeart size={15} className="text-red-500" /> I've donated
          </button>
          <button
            type="button"
            onClick={handleLater}
            className="text-sm text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 transition py-1"
          >
            Maybe later
          </button>
        </div>
      </div>
    </div>
  );
};

export default DonationModal;

