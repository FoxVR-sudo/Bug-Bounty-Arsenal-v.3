import React, { useMemo, useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import FieldError from '../components/forms/FieldError';
import { isNonEmpty, minLength } from '../lib/validation';
import api from '../services/api';

const ResetPassword = () => {
  const { uid, token } = useParams();
  const navigate = useNavigate();
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [status, setStatus] = useState('idle'); // 'idle', 'loading', 'success', 'error'
  const [message, setMessage] = useState('');
  const [touched, setTouched] = useState({});

  const redirectTimerRef = useRef(null);

  useEffect(() => {
    return () => {
      if (redirectTimerRef.current) clearTimeout(redirectTimerRef.current);
    };
  }, []);

  const fieldErrors = useMemo(() => {
    const next = {};
    if (!minLength(password, 8)) next.password = 'Password must be at least 8 characters.';
    if (!isNonEmpty(confirmPassword)) next.confirmPassword = 'Please confirm your password.';
    if (isNonEmpty(password) && isNonEmpty(confirmPassword) && password !== confirmPassword) {
      next.confirmPassword = 'Passwords do not match.';
    }
    return next;
  }, [password, confirmPassword]);

  const hasErrors = Object.values(fieldErrors).some(Boolean);

  const handleSubmit = async (e) => {
    e.preventDefault();

    setTouched({ password: true, confirmPassword: true });
    if (hasErrors) {
      setStatus('error');
      setMessage('Please fix the highlighted fields.');
      return;
    }

    setStatus('loading');

    try {
      const response = await api.post('/auth/reset-password/', {
        uid: uid,
        token: token,
        new_password: password,
      });

      setStatus('success');
      setMessage(response.data.message || 'Password reset successfully!');
      
      // Redirect to login after 3 seconds
      redirectTimerRef.current = setTimeout(() => {
        navigate('/login');
      }, 3000);

    } catch (error) {
      setStatus('error');
      setMessage(
        error.response?.data?.error || 
        'Password reset failed. The link may be expired or invalid.'
      );
    }
  };

  if (!uid || !token) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-purple-800 to-indigo-900">
        <div className="max-w-md w-full mx-4">
          <div className="ui-card p-8 bg-white/90 dark:bg-gray-900/60 backdrop-blur-xl">
            <div className="text-center">
              <div className="bg-red-100 rounded-full h-16 w-16 flex items-center justify-center mx-auto mb-4">
                <svg className="h-10 w-10 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
                </svg>
              </div>
              <h2 className="text-2xl font-bold text-gray-800 dark:text-white mb-2">Invalid Link</h2>
              <p className="text-gray-600 dark:text-gray-300 mb-6">This password reset link is invalid.</p>
              <button
                onClick={() => navigate('/login')}
                className="ui-btn ui-btn-primary"
              >
                Go to Login
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-purple-800 to-indigo-900">
      <div className="max-w-md w-full mx-4">
        <div className="ui-card p-8 bg-white/90 dark:bg-gray-900/60 backdrop-blur-xl">
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-gray-800 dark:text-white mb-2">Reset Password</h1>
            <p className="text-gray-600 dark:text-gray-300">Enter your new password below</p>
          </div>

          {status === 'success' ? (
            <div className="text-center">
              <div className="bg-green-100 rounded-full h-16 w-16 flex items-center justify-center mx-auto mb-4">
                <svg className="h-10 w-10 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                </svg>
              </div>
              <h2 className="text-2xl font-bold text-gray-800 dark:text-white mb-2">Password Reset!</h2>
              <p className="text-gray-600 dark:text-gray-300 mb-4">{message}</p>
              <p className="text-sm text-gray-500 dark:text-gray-400">Redirecting to login page...</p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-6" noValidate>
              {status === 'error' && (
                <div className="ui-alert ui-alert-error">
                  {message}
                </div>
              )}

              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-200 mb-2">
                  New Password
                </label>
                <input
                  type="password"
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onBlur={() => setTouched((t) => ({ ...t, password: true }))}
                  className={`ui-input ${touched.password && fieldErrors.password ? 'ui-input-error' : ''}`}
                  placeholder="Enter new password"
                  aria-invalid={touched.password && !!fieldErrors.password}
                  aria-describedby={touched.password && fieldErrors.password ? 'reset-password-error' : undefined}
                />
                <FieldError id="reset-password-error" message={touched.password ? fieldErrors.password : null} />
              </div>

              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-200 mb-2">
                  Confirm Password
                </label>
                <input
                  type="password"
                  id="confirmPassword"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  onBlur={() => setTouched((t) => ({ ...t, confirmPassword: true }))}
                  className={`ui-input ${touched.confirmPassword && fieldErrors.confirmPassword ? 'ui-input-error' : ''}`}
                  placeholder="Confirm new password"
                  aria-invalid={touched.confirmPassword && !!fieldErrors.confirmPassword}
                  aria-describedby={touched.confirmPassword && fieldErrors.confirmPassword ? 'reset-confirm-password-error' : undefined}
                />
                <FieldError
                  id="reset-confirm-password-error"
                  message={touched.confirmPassword ? fieldErrors.confirmPassword : null}
                />
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
                    Resetting...
                  </span>
                ) : (
                  'Reset Password'
                )}
              </button>

              <div className="text-center">
                <button
                  type="button"
                  onClick={() => navigate('/login')}
                  className="text-primary hover:text-primary-600 text-sm font-medium"
                >
                  Back to Login
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

export default ResetPassword;
