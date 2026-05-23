import React, { useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import DonationModal, { isDonationSnoozed } from './components/DonationModal';
import { QueryClient, QueryClientProvider } from 'react-query';
import { ThemeProvider } from './contexts/ThemeContext';
import { ToastProvider } from './contexts/ToastContext';
import LandingPage from './pages/LandingPage';
import Dashboard from './pages/Dashboard';
import ScanDetails from './pages/ScanDetails';
import DetectorCategoryScan from './pages/DetectorCategoryScan';
import AllResults from './pages/AllResults';
import Analytics from './pages/Analytics';
import Profile from './pages/Profile';
import SupportProject from './pages/SupportProject';
import Login from './pages/Login';
import Register from './pages/Register';
import VerifyEmail from './pages/VerifyEmail';
import ResetPassword from './pages/ResetPassword';
import ForgotPassword from './pages/ForgotPassword';
import TeamManagement from './pages/TeamManagement';
import Integrations from './pages/Integrations';
import VerifiedDomains from './pages/VerifiedDomains';
import Terms from './pages/Terms';
import Privacy from './pages/Privacy';
import Disclaimer from './pages/Disclaimer';
import AcceptableUsePolicy from './pages/AcceptableUsePolicy';
import Contact from './pages/Contact';
import Footer from './components/Footer';
import CookieConsent from './components/CookieConsent';
import './index.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

// Protected route wrapper
const PrivateRoute = ({ children }) => {
  const token = localStorage.getItem('token');
  return token ? children : <Navigate to="/login" />;
};

// Show donation modal when rate limit (429) is hit
const RateLimitDonation = () => {
  const [show, setShow] = useState(false);
  useEffect(() => {
    const handle = () => {
      if (!isDonationSnoozed()) setShow(true);
    };
    window.addEventListener('rateLimitHit', handle);
    return () => window.removeEventListener('rateLimitHit', handle);
  }, []);
  if (!show) return null;
  return <DonationModal reason="rateLimit" onClose={() => setShow(false)} />;
};

// Footer only on public pages (dashboard pages have it inside DashboardLayout)
const DASHBOARD_PREFIXES = ['/dashboard', '/scan/', '/results', '/analytics', '/profile', '/team', '/integrations', '/domain-verify'];
const ConditionalFooter = () => {
  const location = useLocation();
  if (DASHBOARD_PREFIXES.some(p => location.pathname.startsWith(p))) return null;
  return <Footer />;
};

function App() {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <Router>
            <RateLimitDonation />
            <div className="flex flex-col min-h-screen">
              <div className="flex-grow">
                <Routes>
                <Route path="/" element={<LandingPage />} />
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="/forgot-password" element={<ForgotPassword />} />
                <Route path="/verify-email/:uid/:token" element={<VerifyEmail />} />
                <Route path="/reset-password/:uid/:token" element={<ResetPassword />} />
                <Route path="/support" element={<SupportProject />} />
                <Route path="/terms" element={<Terms />} />
                <Route path="/privacy" element={<Privacy />} />
                <Route path="/disclaimer" element={<Disclaimer />} />
                <Route path="/aup" element={<AcceptableUsePolicy />} />
                <Route path="/contact" element={<Contact />} />
              <Route
            path="/dashboard"
            element={
              <PrivateRoute>
                <Dashboard />
              </PrivateRoute>
            }
          />
          <Route
            path="/scan/details/:id"
            element={
              <PrivateRoute>
                <ScanDetails />
              </PrivateRoute>
            }
          />
          <Route
            path="/scan/:categoryId"
            element={
              <PrivateRoute>
                <DetectorCategoryScan />
              </PrivateRoute>
            }
          />
          <Route
            path="/results"
            element={
              <PrivateRoute>
                <AllResults />
              </PrivateRoute>
            }
          />
          <Route
            path="/results/:id"
            element={
              <PrivateRoute>
                <ScanDetails />
              </PrivateRoute>
            }
          />
          <Route
            path="/analytics"
            element={
              <PrivateRoute>
                <Analytics />
              </PrivateRoute>
            }
          />
          <Route
            path="/profile"
            element={
              <PrivateRoute>
                <Profile />
              </PrivateRoute>
            }
          />
          <Route
            path="/team"
            element={
              <PrivateRoute>
                <TeamManagement />
              </PrivateRoute>
            }
          />
          <Route
            path="/integrations"
            element={
              <PrivateRoute>
                <Integrations />
              </PrivateRoute>
            }
          />
          <Route
            path="/domain-verify"
            element={
              <PrivateRoute>
                <VerifiedDomains />
              </PrivateRoute>
            }
          />
          </Routes>
            </div>
            <ConditionalFooter />
            <CookieConsent />
          </div>
        </Router>
      </ToastProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}

export default App;
