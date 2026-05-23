import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { getDetectorCategoryIcon } from '../lib/icons';
import api from '../services/api';

const Sidebar = ({ onNavigate }) => {
  const location = useLocation();
  const [categories, setCategories] = useState([]);
  const donateUrl = process.env.REACT_APP_DONATE_URL;

  const navItemBase =
    'block px-3 lg:px-4 py-2.5 lg:py-3 rounded-lg transition font-medium text-sm lg:text-base';
  const navItemInactive =
    'text-gray-700 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-800 dark:hover:text-white';

  const compactNavItemBase =
    'flex items-center justify-between px-2 lg:px-3 py-2 rounded-lg transition font-medium text-xs lg:text-sm';
  const compactNavItemInactive =
    'text-gray-700 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-800 dark:hover:text-white';

  const handleNavClick = () => {
    if (onNavigate) onNavigate();
  };

  useEffect(() => {
    fetchCategories();
  }, []);

  const fetchCategories = async () => {
    try {
      // Use NEW detector-categories API with plan-based access
      const response = await api.get('/detector-categories/');

      setCategories((response.data.categories || []).slice());
    } catch (err) {
      console.error('Failed to fetch categories:', err);
    }
  };

  const isActive = (path) => location.pathname === path;

  return (
    <div className="h-full w-64 flex flex-col bg-white text-gray-900 border-r border-gray-200 dark:bg-gray-900 dark:text-white dark:border-gray-800">

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4">
        {/* Main Navigation */}
        <div className="px-3 lg:px-4 mb-6">
          <Link
            to="/dashboard"
            onClick={handleNavClick}
            className={`${navItemBase} ${isActive('/dashboard') ? 'bg-primary text-white' : navItemInactive}`}
          >
            Dashboard
          </Link>
        </div>

        {/* V3.0: Detector Categories with Icons */}
        <div className="px-3 lg:px-4 mb-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 dark:text-gray-500">
              Detectors
            </h3>
          </div>
          <div className="space-y-1">
            {categories.map((category) => {
              return (
                <Link
                  key={category.key}
                  to={`/scan/${category.key}`}
                  onClick={handleNavClick}
                  className={`${compactNavItemBase} ${
                    isActive(`/scan/${category.key}`)
                      ? 'bg-primary text-white'
                      : compactNavItemInactive
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-base lg:text-lg">
                      {getDetectorCategoryIcon(category.key, { size: 18 })}
                    </span>
                    <span className="hidden sm:inline">{category.name}</span>
                  </div>
                </Link>
              );
            })}
          </div>
        </div>

        {/* Results & Analytics */}
        <div className="px-4 mb-6">
          <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">
            Analysis
          </h3>
          <div className="space-y-1">
            <Link
              to="/results"
              className={`block px-4 py-3 rounded-lg transition font-medium ${
                isActive('/results')
                  ? 'bg-primary text-white'
                  : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-800 dark:hover:text-white'
              }`}
            >
              All Results
            </Link>
            <Link
              to="/analytics"
              className={`block px-4 py-3 rounded-lg transition font-medium ${
                isActive('/analytics')
                  ? 'bg-primary text-white'
                  : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-800 dark:hover:text-white'
              }`}
            >
              Analytics
            </Link>
          </div>
        </div>

        {/* User Section */}
        <div className="px-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-2 text-gray-400 dark:text-gray-500">
            Account
          </h3>
          <div className="space-y-1">
            {donateUrl && (
              <a
                href={donateUrl}
                target="_blank"
                rel="noreferrer"
                onClick={handleNavClick}
                className={`block px-4 py-3 rounded-lg transition font-medium text-gray-700 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-800 dark:hover:text-white`}
              >
                Donate
              </a>
            )}
            <Link
              to="/profile"
              className={`block px-4 py-3 rounded-lg transition font-medium ${
                isActive('/profile')
                  ? 'bg-primary text-white'
                  : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-800 dark:hover:text-white'
              }`}
            >
              Profile
            </Link>
            <Link
              to="/team"
              className={`flex items-center justify-between px-4 py-3 rounded-lg transition font-medium ${
                isActive('/team')
                  ? 'bg-primary text-white'
                  : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-800 dark:hover:text-white'
              }`}
            >
              <span>Team</span>
            </Link>
            <Link
              to="/integrations"
              className={`flex items-center justify-between px-4 py-3 rounded-lg transition font-medium ${
                isActive('/integrations')
                  ? 'bg-primary text-white'
                  : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-800 dark:hover:text-white'
              }`}
            >
              <span>Integrations</span>
            </Link>
          </div>
        </div>
      </nav>
    </div>
  );
};

export default Sidebar;
