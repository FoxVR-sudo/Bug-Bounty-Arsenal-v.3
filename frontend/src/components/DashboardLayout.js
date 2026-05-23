import React, { useState } from 'react';
import Sidebar from './Sidebar';
import Footer from './Footer';
import { FiMenu, FiX } from 'react-icons/fi';
import { FiMoon, FiSun, FiLogOut } from 'react-icons/fi';
import { Link, useNavigate } from 'react-router-dom';
import { useTheme } from '../contexts/ThemeContext';
import { authService } from '../services/api';

const DashboardLayout = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = useState(() => {
    try {
      const saved = localStorage.getItem('sidebarOpen');
      if (saved !== null) return saved === 'true';
      return window.innerWidth >= 1024;
    } catch (_) {
      return true;
    }
  });
  const navigate = useNavigate();
  const { toggleTheme, isDark } = useTheme();

  const setSidebarOpenAndPersist = (next) => {
    setSidebarOpen(next);
    try {
      localStorage.setItem('sidebarOpen', String(next));
    } catch (_) {
      // ignore
    }
    try {
      window.dispatchEvent(new CustomEvent('bba:sidebarOpenChanged', { detail: next }));
    } catch (_) {
      // ignore
    }
  };

  const toggleSidebar = () => {
    setSidebarOpenAndPersist(!sidebarOpen);
  };

  const handleLogout = () => {
    authService.logout();
    navigate('/login');
  };
  
  return (
    <div className="flex h-screen overflow-hidden bg-gradient-to-br from-gray-50 via-white to-gray-100 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900">
      {/* Top header (actions) */}
      <header className="fixed top-0 left-0 right-0 z-50 h-16 border-b border-gray-200/60 dark:border-gray-800/60 bg-white/80 dark:bg-gray-900/70 backdrop-blur-xl">
        <div className="h-full px-4 sm:px-6 lg:px-8 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            {/* Mobile menu button */}
            <button
              type="button"
              onClick={toggleSidebar}
              className="inline-flex items-center justify-center p-2 rounded-lg bg-white text-gray-900 shadow-sm border border-gray-200 hover:bg-gray-50 dark:bg-gray-900 dark:text-white dark:border-gray-800 dark:hover:bg-gray-800"
              aria-label={sidebarOpen ? 'Close menu' : 'Open menu'}
            >
              {sidebarOpen ? <FiX className="w-5 h-5" /> : <FiMenu className="w-5 h-5" />}
            </button>

            {/* Brand -> Home */}
            <Link
              to="/"
              className="flex items-center gap-2 font-bold text-gray-900 dark:text-white truncate"
              aria-label="Go to home"
            >
              <span className="inline-flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10 text-primary">
                B
              </span>
              <span className="truncate">BugBounty Arsenal</span>
            </Link>
          </div>

          <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={toggleTheme}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border border-gray-200 bg-white text-gray-800 hover:bg-gray-50 dark:border-gray-800 dark:bg-gray-900 dark:text-gray-200 dark:hover:bg-gray-800 transition"
            aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {isDark ? <FiSun className="w-4 h-4" /> : <FiMoon className="w-4 h-4" />}
            <span className="hidden sm:inline">{isDark ? 'Light' : 'Dark'}</span>
          </button>

          <button
            type="button"
            onClick={handleLogout}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border border-red-200 bg-white text-red-700 hover:bg-red-50 dark:border-red-900/40 dark:bg-gray-900 dark:text-red-300 dark:hover:bg-red-950/20 transition"
          >
            <FiLogOut className="w-4 h-4" />
            <span className="hidden sm:inline">Logout</span>
          </button>
        </div>
        </div>
      </header>

      {/* Overlay for mobile */}
      {sidebarOpen && (
        <div
          className="lg:hidden fixed top-16 left-0 right-0 bottom-0 bg-black bg-opacity-50 z-40"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <div
        className={`${
          sidebarOpen ? 'translate-x-0 lg:translate-x-0' : '-translate-x-full lg:-translate-x-full'
        } fixed top-16 bottom-0 left-0 z-50 w-64 transition-transform duration-300`}
      >
        <Sidebar
          onNavigate={() => {
            // Only auto-close on mobile.
            try {
              if (!window.matchMedia('(min-width: 1024px)').matches) setSidebarOpenAndPersist(false);
            } catch (_) {
              setSidebarOpenAndPersist(false);
            }
          }}
        />
      </div>

      {/* Main content */}
      <main className={`flex-1 overflow-y-auto overscroll-contain pt-16 transition-[padding] duration-300 ${sidebarOpen ? 'lg:pl-64' : 'lg:pl-0'}`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {children}
        </div>
        <Footer embedded />
      </main>
    </div>
  );
};

export default DashboardLayout;
