import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FiShield, FiMail } from 'react-icons/fi';

const Footer = ({ embedded = false }) => {
  const currentYear = new Date().getFullYear();
  const buildSha = process.env.REACT_APP_BUILD_SHA;
  const buildShort = typeof buildSha === 'string' && buildSha.length >= 7 ? buildSha.slice(0, 7) : null;
  const donateUrl = 'https://www.paypal.com/ncp/payment/9M7YPHHLDZU74';

  const [sidebarOpen, setSidebarOpen] = useState(() => {
    try {
      return localStorage.getItem('sidebarOpen') === 'true';
    } catch (_) {
      return false;
    }
  });

  const [hasToken, setHasToken] = useState(() => {
    try {
      return Boolean(localStorage.getItem('token'));
    } catch (_) {
      return false;
    }
  });

  useEffect(() => {
    const handler = (event) => {
      setSidebarOpen(Boolean(event?.detail));
      try {
        setHasToken(Boolean(localStorage.getItem('token')));
      } catch (_) {
        // ignore
      }
    };

    window.addEventListener('bba:sidebarOpenChanged', handler);
    return () => window.removeEventListener('bba:sidebarOpenChanged', handler);
  }, []);

  const desktopOffset = !embedded && hasToken && sidebarOpen;

  return (
    <footer
      className={`relative z-[51] bg-white dark:bg-gray-900/80 backdrop-blur-xl text-gray-600 dark:text-gray-300 border-t border-gray-200 dark:border-gray-800/50 shadow-md dark:shadow-2xl transition-[padding] duration-300 ${desktopOffset ? 'lg:pl-64' : 'lg:pl-0'}`}
    >
      <div className="max-w-7xl mx-auto px-4 py-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2 text-white font-semibold">
            <FiShield className="text-primary" />
            <span className="text-gray-900 dark:text-white">BugBounty Arsenal</span>
            <span className="text-xs text-gray-400 dark:text-gray-500">© {currentYear}</span>
          </div>

          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
            <Link to="/terms" className="hover:text-primary transition">Terms</Link>
            <Link to="/privacy" className="hover:text-primary transition">Privacy</Link>
            <Link to="/disclaimer" className="hover:text-primary transition">Disclaimer</Link>
            <Link to="/aup" className="hover:text-primary transition">AUP</Link>
            <a
              href={donateUrl}
              target="_blank"
              rel="noreferrer"
              className="hover:text-primary transition"
            >
              Donate
            </a>
            <Link to="/contact" className="hover:text-primary transition">Contact</Link>
            <a
              href="mailto:support@bugbounty-arsenal.net"
              className="hover:text-primary transition inline-flex items-center gap-1"
            >
              <FiMail className="w-4 h-4" />
              <span className="hidden md:inline">support@bugbounty-arsenal.net</span>
              <span className="md:hidden">Support</span>
            </a>
            {buildShort && (
              <span className="text-xs text-gray-400 dark:text-gray-500">Build {buildShort}</span>
            )}
          </div>
        </div>

        <p className="mt-3 text-xs text-gray-400 dark:text-gray-500">
          Legal use only. Unauthorized scanning is illegal.
        </p>
      </div>
    </footer>
  );
};

export default Footer;
