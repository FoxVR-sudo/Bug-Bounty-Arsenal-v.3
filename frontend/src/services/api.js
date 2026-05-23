import axios from 'axios';
import API_URL from '../config/api';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

const clearAuthStorage = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
};

const isAuthRoute = (pathname) => {
  const p = String(pathname || '');
  return (
    p === '/' ||
    p.startsWith('/login') ||
    p.startsWith('/register') ||
    p.startsWith('/forgot-password') ||
    p.startsWith('/reset-password') ||
    p.startsWith('/verify-email')
  );
};

// Add token to requests
api.interceptors.request.use(
  (config) => {
    // Don't add Authorization header for public endpoints
    const publicEndpoints = [
      '/auth/login/',
      '/auth/signup/',
      '/auth/signup/start/',
      '/auth/signup/confirm-phone/',
      '/auth/signup/resend-phone/',
      '/auth/signup-enterprise/start/',
      '/auth/signup-enterprise/confirm-phone/',
      '/auth/signup-enterprise/resend-phone/',
      '/auth/request-reset/',
      '/auth/reset-password/',
      '/auth/verify-email/',
      '/plans/',
    ];
    const isPublicEndpoint = publicEndpoints.some(endpoint => config.url?.includes(endpoint));
    
    if (!isPublicEndpoint) {
      const token = localStorage.getItem('token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
    }
    return config;
  },
  (error) => Promise.reject(error)
);

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status;
    const url = error?.config?.url || '';
    const isAuthEndpoint = String(url).includes('/auth/login/') || String(url).includes('/auth/signup/');

    if (status === 401 && !isAuthEndpoint) {
      clearAuthStorage();

      try {
        window.dispatchEvent(new CustomEvent('auth:logout', { detail: { reason: 'unauthorized' } }));
      } catch (_) {
        // no-op
      }

      if (!isAuthRoute(window.location?.pathname)) {
        window.location.assign('/login?reason=session_expired');
      }
    }

    if (status === 429) {
      try {
        window.dispatchEvent(new CustomEvent('rateLimitHit'));
      } catch (_) {
        // no-op
      }
    }

    return Promise.reject(error);
  }
);

// Auth services
export const authService = {
  login: (email, password, otp, captchaToken) => api.post('/auth/login/', { email, password, otp, captcha_token: captchaToken || '' }),
  register: (userData) => api.post('/auth/signup/', userData),
  registerStart: (userData) => api.post('/auth/signup/start/', userData),
  signupConfirmPhone: (signup_token, code) => api.post('/auth/signup/confirm-phone/', { signup_token, code }),
  signupResendPhone: (signup_token) => api.post('/auth/signup/resend-phone/', { signup_token }),
  enterpriseRegisterStart: (userData) => api.post('/auth/signup-enterprise/start/', userData),
  enterpriseConfirmPhone: (payload) => api.post('/auth/signup-enterprise/confirm-phone/', payload),
  enterpriseResendPhone: (signup_token) => api.post('/auth/signup-enterprise/resend-phone/', { signup_token }),
  logout: () => {
    clearAuthStorage();
  },
};

// Two-factor authentication services
export const twoFactorService = {
  status: () => api.get('/auth/2fa/status/'),
  setup: () => api.post('/auth/2fa/setup/'),
  confirm: (code) => api.post('/auth/2fa/confirm/', { code }),
  disable: (password, code) => api.post('/auth/2fa/disable/', { password, code }),
  regenerateBackupCodes: (password, code) => api.post('/auth/2fa/backup-codes/regenerate/', { password, code }),
};

// User services
export const userService = {
  getMe: () => api.get('/auth/me/'),
  updateMe: (data) => api.patch('/auth/me/', data),
};

// Scan services
export const scanService = {
  getAll: (params) => api.get('/scans/', { params }),
  getById: (id) => api.get(`/scans/${id}/`),
  create: (data) => api.post('/scans/start/', data),
  cancel: (id) => api.post(`/scans/stop/${id}/`),
  getVulnerabilities: (id, params) => api.get(`/scans/${id}/vulnerabilities/`, { params }),
  downloadPDF: (id) => api.get(`/scans/${id}/pdf/`, { responseType: 'blob' }),
  downloadJSON: (id) => api.get(`/scans/${id}/json/`, { responseType: 'blob' }),
  downloadCSV: (id) => api.get(`/scans/${id}/csv/`, { responseType: 'blob' }),
};

// Mobile scanner service
export const mobileScanService = {
  start: (formData) =>
    api.post('/mobile/scan/', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),
  getStatus: (id) => api.get(`/mobile/scan/${id}/`),
};

// Vulnerability services
export const vulnerabilityService = {
  getAll: (params) => api.get('/vulnerabilities/', { params }),
  verify: (id) => api.post(`/vulnerabilities/${id}/verify/`),
  patch: (id, data) => api.patch(`/vulnerabilities/${id}/`, data),
};

// Stats services
export const statsService = {
  getOverview: () => api.get('/scans/stats/'),
};

// Subscription services
export const subscriptionService = {
  getCurrent: () => api.get('/subscriptions/current/'),
};

// Domain ownership verification services
export const domainVerifyService = {
  list: () => api.get('/domain-verify/'),
  initiate: (domain) => api.post('/domain-verify/initiate/', { domain }),
  check: (domain) => api.post('/domain-verify/check/', { domain }),
  remove: (domain) => api.delete(`/domain-verify/${domain}/`),
};

export default api;

export { clearAuthStorage };
