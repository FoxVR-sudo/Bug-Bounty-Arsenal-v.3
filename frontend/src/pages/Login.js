import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { authService } from '../services/api';
import { FiMail, FiLock, FiShield } from 'react-icons/fi';
import FieldError from '../components/forms/FieldError';
import { isEmail, isNonEmpty } from '../lib/validation';
import TurnstileWidget, { isTurnstileEnabled } from '../components/security/TurnstileWidget';

const Login = () => {
  const captchaRequired = isTurnstileEnabled();
  const [searchParams] = useSearchParams();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [otpRequired, setOtpRequired] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(false);
  const [touched, setTouched] = useState({});
  const [captchaToken, setCaptchaToken] = useState('');
  const [captchaError, setCaptchaError] = useState('');
  const navigate = useNavigate();
  const otpInputRef = useRef(null);

  const fieldErrors = useMemo(() => {
    const next = {};
    if (!isEmail(email)) next.email = 'Please enter a valid email.';
    if (!isNonEmpty(password)) next.password = 'Password is required.';
    if (otpRequired && !isNonEmpty(otp)) next.otp = 'Please enter your 2FA code.';
    return next;
  }, [email, password, otp, otpRequired]);

  const hasErrors = Object.values(fieldErrors).some(Boolean);

  useEffect(() => {
    if (otpRequired) {
      otpInputRef.current?.focus?.();
    }
  }, [otpRequired]);

  useEffect(() => {
    const reason = searchParams.get('reason');
    if (reason === 'session_expired') {
      setNotice('Your session has expired. Please sign in again.');
    } else {
      setNotice('');
    }
  }, [searchParams]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setTouched({ email: true, password: true, otp: true });
    if (hasErrors) {
      setError('Please fix the highlighted fields.');
      return;
    }

    if (captchaRequired && !captchaToken) {
      setCaptchaError('Please complete the CAPTCHA.');
      return;
    }
    setCaptchaError('');

    setError('');
    setLoading(true);

    try {
      const response = await authService.login(email, password, otpRequired ? otp : undefined, captchaToken);
      localStorage.setItem('token', response.data.access);
      localStorage.setItem('user', email);
      window.dispatchEvent(new CustomEvent('userLoggedIn'));
      navigate('/dashboard');
    } catch (err) {
      const data = err.response?.data;
      if (data?.two_factor_required) {
        setOtpRequired(true);
        setError(data?.detail || 'Two-factor code required.');
      } else {
        setError(data?.detail || data?.error || 'Login failed. Please check your credentials.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center px-4">
      <div className="max-w-md w-full">
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center gap-2 text-3xl font-bold text-white mb-4">
            <FiShield className="text-primary" />
            BugBounty Arsenal
          </Link>
          <h2 className="text-2xl font-bold text-white">Welcome Back</h2>
          <p className="text-gray-400 mt-2">Sign in to your account</p>
        </div>

        <div className="ui-card p-8 bg-white/90 dark:bg-gray-900/60 backdrop-blur-xl border border-gray-200/50 dark:border-gray-700/60 hover:bg-white/95 transition-all duration-300">
          {notice && (
            <div className="ui-alert ui-alert-warning mb-4">
              {notice}
            </div>
          )}
          {error && (
            <div className="ui-alert ui-alert-error mb-4">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} noValidate>
            <div className="mb-4">
              <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">Email</label>
              <div className="relative">
                <FiMail className="absolute left-3 top-3 text-gray-400" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  onBlur={() => setTouched((t) => ({ ...t, email: true }))}
                  className={`ui-input pl-10 ${touched.email && fieldErrors.email ? 'ui-input-error' : ''}`}
                  placeholder="your@email.com"
                  aria-invalid={touched.email && !!fieldErrors.email}
                  aria-describedby={touched.email && fieldErrors.email ? 'login-email-error' : undefined}
                />
              </div>
              <FieldError id="login-email-error" message={touched.email ? fieldErrors.email : null} />
            </div>

            <div className="mb-6">
              <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">Password</label>
              <div className="relative">
                <FiLock className="absolute left-3 top-3 text-gray-400" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onBlur={() => setTouched((t) => ({ ...t, password: true }))}
                  className={`ui-input pl-10 ${touched.password && fieldErrors.password ? 'ui-input-error' : ''}`}
                  placeholder="••••••••"
                  aria-invalid={touched.password && !!fieldErrors.password}
                  aria-describedby={touched.password && fieldErrors.password ? 'login-password-error' : undefined}
                />
              </div>
              <FieldError id="login-password-error" message={touched.password ? fieldErrors.password : null} />
              <div className="text-right mt-2">
                <Link to="/forgot-password" className="text-sm text-primary hover:text-primary-600">
                  Forgot password?
                </Link>
              </div>
            </div>

            {otpRequired && (
              <div className="mb-6">
                <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">
                  Two-Factor Code
                </label>
                <div className="relative">
                  <FiShield className="absolute left-3 top-3 text-gray-400" />
                  <input
                    type="text"
                    value={otp}
                    onChange={(e) => setOtp(e.target.value)}
                    onBlur={() => setTouched((t) => ({ ...t, otp: true }))}
                    className={`ui-input pl-10 ${touched.otp && fieldErrors.otp ? 'ui-input-error' : ''}`}
                    placeholder="123456 or backup code"
                    ref={otpInputRef}
                    aria-invalid={touched.otp && !!fieldErrors.otp}
                    aria-describedby={touched.otp && fieldErrors.otp ? 'login-otp-error' : undefined}
                  />
                </div>
                <FieldError id="login-otp-error" message={touched.otp ? fieldErrors.otp : null} />
                <p className="text-xs text-gray-500 dark:text-gray-300 mt-2">
                  Use your authenticator app code or a backup code.
                </p>
              </div>
            )}

            {captchaRequired && (
              <div className="mb-4">
                <TurnstileWidget
                  onToken={setCaptchaToken}
                  onError={() => { setCaptchaToken(''); setCaptchaError('CAPTCHA failed. Please try again.'); }}
                  onExpire={() => { setCaptchaToken(''); setCaptchaError('CAPTCHA expired. Please try again.'); }}
                  action="login"
                />
                {captchaError && (
                  <p className="text-red-500 text-sm mt-1">{captchaError}</p>
                )}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || hasErrors}
              className="ui-btn ui-btn-primary w-full justify-center disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Signing in...' : (otpRequired ? 'Verify & Sign In' : 'Sign In')}
            </button>
          </form>

          <div className="mt-6 text-center text-sm">
            <span className="text-gray-600 dark:text-gray-300">Don't have an account? </span>
            <Link to="/register" className="text-primary font-semibold hover:text-primary-600">
              Sign up
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
