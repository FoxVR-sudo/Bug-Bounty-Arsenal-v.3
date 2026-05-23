import React, { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { FiMail, FiShield, FiArrowLeft } from 'react-icons/fi';
import FieldError from '../components/forms/FieldError';
import { isEmail } from '../lib/validation';
import api from '../services/api';

const ForgotPassword = () => {
  const [email, setEmail] = useState('');
  const [status, setStatus] = useState('idle'); // 'idle', 'loading', 'success', 'error'
  const [message, setMessage] = useState('');
  const [touched, setTouched] = useState({});
  const navigate = useNavigate();

  const fieldErrors = useMemo(() => {
    const next = {};
    if (!isEmail(email)) next.email = 'Please enter a valid email.';
    return next;
  }, [email]);

  const hasErrors = Object.values(fieldErrors).some(Boolean);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setTouched({ email: true });
    if (hasErrors) {
      setStatus('error');
      setMessage('Please fix the highlighted field.');
      return;
    }
    setStatus('loading');
    setMessage('');

    try {
      const response = await api.post('/auth/request-reset/', { email });

      setStatus('success');
      setMessage(response.data.message || 'Password reset link sent! Please check your email.');
    } catch (error) {
      setStatus('error');
      setMessage(
        error.response?.data?.error || 
        'Failed to send reset link. Please try again.'
      );
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
          <h2 className="text-2xl font-bold text-white">Forgot Password?</h2>
          <p className="text-gray-400 mt-2">Enter your email to receive a reset link</p>
        </div>

        <div className="ui-card p-8 bg-white/90 dark:bg-gray-900/60 backdrop-blur-xl border border-gray-200/50 dark:border-gray-700/60 hover:bg-white/95 transition-all duration-300">
          {status === 'success' ? (
            <div className="text-center">
              <div className="bg-green-100 rounded-full h-16 w-16 flex items-center justify-center mx-auto mb-4">
                <svg className="h-10 w-10 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                </svg>
              </div>
              <h3 className="text-xl font-bold text-gray-800 dark:text-white mb-2">Check Your Email</h3>
              <p className="text-gray-600 dark:text-gray-300 mb-6">{message}</p>
              <button
                onClick={() => navigate('/login')}
                className="text-primary font-semibold hover:text-primary-600"
              >
                Back to Login
              </button>
            </div>
          ) : (
            <>
              {status === 'error' && (
                <div className="ui-alert ui-alert-error mb-4">
                  {message}
                </div>
              )}

              <form onSubmit={handleSubmit} noValidate>
                <div className="mb-6">
                  <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">Email Address</label>
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
                      aria-describedby={touched.email && fieldErrors.email ? 'forgot-email-error' : undefined}
                    />
                  </div>
                  <FieldError id="forgot-email-error" message={touched.email ? fieldErrors.email : null} />
                  <p className="text-sm text-gray-500 mt-2">
                    We'll send you a password reset link to this email address.
                  </p>
                </div>

                <button
                  type="submit"
                  disabled={status === 'loading' || hasErrors}
                  className="ui-btn ui-btn-primary w-full justify-center disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {status === 'loading' ? (
                    <span className="flex items-center justify-center">
                      <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Sending...
                    </span>
                  ) : (
                    'Send Reset Link'
                  )}
                </button>
              </form>

              <div className="mt-6 text-center">
                <Link to="/login" className="inline-flex items-center gap-2 text-primary font-semibold hover:text-primary-600">
                  <FiArrowLeft />
                  Back to Login
                </Link>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default ForgotPassword;
