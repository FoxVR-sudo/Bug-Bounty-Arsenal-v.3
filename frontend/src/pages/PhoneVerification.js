import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { FiMail, FiCheck, FiAlertCircle, FiRefreshCw } from 'react-icons/fi';
import api, { authService } from '../services/api';

const PhoneVerification = () => {
  const [code, setCode] = useState(['', '', '', '', '', '']);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [resendTimer, setResendTimer] = useState(0);
  const [codeSent, setCodeSent] = useState(false);
  const [devCodeAvailable, setDevCodeAvailable] = useState(false);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const signupToken = (searchParams.get('token') || '').trim();
  const mode = (searchParams.get('mode') || '').trim().toLowerCase();
  const isEnterprise = mode === 'enterprise';
  const isStrictSignup = !!signupToken;
  const hasSentCode = useRef(false); // Prevent double send in React StrictMode

  useEffect(() => {
    // Strict signup: code is already sent during /auth/signup/start/
    if (isStrictSignup) {
      setCodeSent(true);
      setDevCodeAvailable(false);
      return;
    }

    // Legacy flow requires an authenticated user.
    if (!localStorage.getItem('token')) {
      navigate('/login');
      return;
    }

    // Legacy flow (existing logged-in users): auto-send verification code on mount (only once)
    if (!hasSentCode.current) {
      hasSentCode.current = true;
      sendVerificationCode();
    }
  }, [isStrictSignup, navigate]);

  useEffect(() => {
    // Countdown timer for resend button
    if (resendTimer > 0) {
      const timer = setTimeout(() => setResendTimer(resendTimer - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [resendTimer]);

  const sendVerificationCode = async () => {
    setLoading(true);
    setError('');
    
    try {
      const response = await api.post('/users/verify-phone/send/', {});
      
      setCodeSent(true);
      setResendTimer(60); // 1 minute cooldown
      
      // Show code in console for development (will be removed in production)
      if (response.data.code) {
        setDevCodeAvailable(true);
        console.log('🔐 Verification code:', response.data.code);
      } else {
        setDevCodeAvailable(false);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to send verification code');
    } finally {
      setLoading(false);
    }
  };

  const handleCodeChange = (index, value) => {
    // Only allow digits
    if (value && !/^\d$/.test(value)) return;

    const newCode = [...code];
    newCode[index] = value;
    setCode(newCode);

    // Auto-focus next input
    if (value && index < 5) {
      document.getElementById(`code-${index + 1}`).focus();
    }

    // Auto-verify when all 6 digits are entered
    if (index === 5 && value) {
      const fullCode = newCode.join('');
      if (fullCode.length === 6) {
        verifyCode(fullCode);
      }
    }
  };

  const handleKeyDown = (index, e) => {
    // Handle backspace
    if (e.key === 'Backspace' && !code[index] && index > 0) {
      document.getElementById(`code-${index - 1}`).focus();
    }
  };

  const handlePaste = (e) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').slice(0, 6);
    
    if (/^\d+$/.test(pastedData)) {
      const newCode = pastedData.split('').concat(Array(6).fill('')).slice(0, 6);
      setCode(newCode);
      
      // Focus last filled input
      const lastIndex = Math.min(pastedData.length, 5);
      document.getElementById(`code-${lastIndex}`).focus();
      
      // Auto-verify if complete
      if (pastedData.length === 6) {
        verifyCode(pastedData);
      }
    }
  };

  const verifyCode = async (verificationCode = null) => {
    const fullCode = verificationCode || code.join('');
    
    if (fullCode.length !== 6) {
      setError('Please enter all 6 digits');
      return;
    }

    setLoading(true);
    setError('');

    try {
      if (isStrictSignup) {
        let resp;

        if (isEnterprise) {
          let enterprisePayload = {};
          try {
            enterprisePayload = JSON.parse(sessionStorage.getItem('pending_enterprise_signup') || '{}') || {};
          } catch (_) {
            enterprisePayload = {};
          }

          resp = await authService.enterpriseConfirmPhone({
            signup_token: signupToken,
            code: fullCode,
            ...enterprisePayload,
          });
        } else {
          resp = await authService.signupConfirmPhone(signupToken, fullCode);
        }

        localStorage.setItem('token', resp.data.access);
        localStorage.setItem('user', resp.data?.user?.email || '');
        window.dispatchEvent(new CustomEvent('userLoggedIn'));

        // Enterprise: redirect to checkout if present
        const checkoutUrl = resp.data?.checkout_url;
        if (isEnterprise && checkoutUrl) {
          setSuccess(true);
          setTimeout(() => {
            try {
              sessionStorage.removeItem('pending_enterprise_signup');
            } catch (_) {
              // no-op
            }
            window.location.assign(checkoutUrl);
          }, 1500);
          return;
        }
      } else {
        await api.post('/users/verify-phone/confirm/', { code: fullCode });
      }

      setSuccess(true);
      
      // Redirect to dashboard after 2 seconds
      setTimeout(() => {
        navigate('/dashboard');
      }, 2000);
    } catch (err) {
      setError(err.response?.data?.error || 'Invalid verification code');
      setCode(['', '', '', '', '', '']);
      document.getElementById('code-0').focus();
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    if (resendTimer > 0) return;
    
    setCode(['', '', '', '', '', '']);
    setError('');

    if (isStrictSignup) {
      setLoading(true);
      try {
        if (isEnterprise) {
          await authService.enterpriseResendPhone(signupToken);
        } else {
          await authService.signupResendPhone(signupToken);
        }
        setCodeSent(true);
        setResendTimer(60);
      } catch (err) {
        setError(err.response?.data?.error || 'Failed to resend verification code');
      } finally {
        setLoading(false);
      }
    } else {
      await sendVerificationCode();
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center px-4">
      <div className="max-w-md w-full">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-primary rounded-full mb-4">
            <FiMail className="text-white" size={32} />
          </div>
          <h2 className="text-2xl font-bold text-white">Verify Your Email</h2>
          <p className="text-gray-400 mt-2">
            {codeSent 
              ? "We've sent a 6-digit code to your email address"
              : "Sending verification code to your email..."}
          </p>
        </div>

        <div className="ui-card p-8 bg-white/90 dark:bg-gray-900/60 backdrop-blur-xl">
          {success ? (
            <div className="text-center py-8">
              <div className="inline-flex items-center justify-center w-16 h-16 bg-green-100 rounded-full mb-4">
                <FiCheck className="text-green-600" size={32} />
              </div>
              <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">Verified!</h3>
              <p className="text-gray-600 dark:text-gray-300">Redirecting to dashboard...</p>
            </div>
          ) : (
            <>
              {error && (
                <div className="ui-alert ui-alert-error mb-6 flex items-start gap-3">
                  <FiAlertCircle className="text-red-600 mt-0.5 flex-shrink-0" />
                  <p className="text-sm">{error}</p>
                </div>
              )}

              <div className="mb-6">
                <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-4 text-center">
                  Enter Verification Code
                </label>
                <div className="flex justify-center gap-2">
                  {code.map((digit, index) => (
                    <input
                      key={index}
                      id={`code-${index}`}
                      type="text"
                      maxLength="1"
                      value={digit}
                      onChange={(e) => handleCodeChange(index, e.target.value)}
                      onKeyDown={(e) => handleKeyDown(index, e)}
                      onPaste={index === 0 ? handlePaste : undefined}
                      className="w-12 h-14 text-center text-2xl font-bold border-2 border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white rounded-lg focus:border-primary focus:ring-2 focus:ring-primary focus:outline-none transition"
                      disabled={loading || success}
                    />
                  ))}
                </div>
              </div>

              <button
                onClick={() => verifyCode()}
                disabled={loading || code.join('').length !== 6}
                className="ui-btn ui-btn-primary w-full justify-center disabled:opacity-50 disabled:cursor-not-allowed mb-4"
              >
                {loading ? 'Verifying...' : 'Verify Code'}
              </button>

              <div className="flex items-center justify-between text-sm">
                <button
                  onClick={handleResend}
                  disabled={resendTimer > 0 || loading}
                  className="text-primary hover:text-primary-600 font-semibold disabled:text-gray-400 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  <FiRefreshCw size={16} />
                  {resendTimer > 0 ? `Resend in ${resendTimer}s` : 'Resend Code'}
                </button>
              </div>

              <div className="mt-6 p-4 bg-blue-50 border border-blue-200 dark:bg-blue-900/20 dark:border-blue-700 rounded-lg">
                {devCodeAvailable ? (
                  <p className="text-xs text-blue-800 dark:text-blue-200">
                    <strong>Development:</strong> The code is printed in the browser console.
                  </p>
                ) : (
                  <p className="text-xs text-blue-800 dark:text-blue-200">
                    Check your inbox (and spam folder) for the 6-digit code.
                  </p>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default PhoneVerification;
