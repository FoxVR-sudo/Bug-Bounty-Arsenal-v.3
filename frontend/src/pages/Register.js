import React, { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { authService } from '../services/api';
import { FiMail, FiLock, FiShield, FiUser, FiPhone, FiMapPin } from 'react-icons/fi';
import FieldError from '../components/forms/FieldError';
import { isEmail, isNonEmpty, minLength } from '../lib/validation';
import TurnstileWidget, { isTurnstileEnabled } from '../components/security/TurnstileWidget';
import { useToast } from '../contexts/ToastContext';

const initialFormData = {
  first_name: '',
  middle_name: '',
  last_name: '',
  email: '',
  phone: '',
  address: '',
  password: '',
  confirmPassword: '',
  acceptTerms: false,
};

const Register = () => {
  const captchaRequired = isTurnstileEnabled();
  const toast = useToast();
  const [formData, setFormData] = useState(initialFormData);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [submittedEmail, setSubmittedEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [touched, setTouched] = useState({});
  const [captchaToken, setCaptchaToken] = useState('');
  const [captchaError, setCaptchaError] = useState('');

  const fieldErrors = useMemo(() => {
    const next = {};
    if (!isNonEmpty(formData.first_name)) next.first_name = 'First name is required.';
    if (!isNonEmpty(formData.last_name)) next.last_name = 'Last name is required.';
    if (!isEmail(formData.email)) next.email = 'Please enter a valid email.';
    if (isNonEmpty(formData.phone) && !/^\+\d{10,15}$/.test(String(formData.phone).trim())) {
      next.phone = 'Phone must start with "+" and contain 10–15 digits.';
    }
    if (!minLength(formData.password, 8)) next.password = 'Password must be at least 8 characters.';
    if (!isNonEmpty(formData.confirmPassword)) next.confirmPassword = 'Please confirm your password.';
    if (isNonEmpty(formData.password) && isNonEmpty(formData.confirmPassword) && formData.password !== formData.confirmPassword) {
      next.confirmPassword = 'Passwords do not match.';
    }
    if (!formData.acceptTerms) next.acceptTerms = 'You must accept Terms, Privacy, Disclaimer and AUP.';
    return next;
  }, [formData]);

  const hasErrors = Object.values(fieldErrors).some(Boolean);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (captchaRequired && !captchaToken) {
      setError('Please complete the CAPTCHA.');
      return;
    }

    setTouched({
      first_name: true,
      middle_name: true,
      last_name: true,
      email: true,
      phone: true,
      address: true,
      password: true,
      confirmPassword: true,
      acceptTerms: true,
    });

    if (hasErrors) {
      setError('Please fix the highlighted fields.');
      return;
    }

    setLoading(true);

    try {
      const registrationData = {
        email: formData.email,
        password: formData.password,
        password_confirm: formData.confirmPassword,
        first_name: formData.first_name,
        middle_name: formData.middle_name,
        last_name: formData.last_name,
        phone: formData.phone,
        address: formData.address,
        captcha_token: captchaToken,
        accept_terms: !!formData.acceptTerms,
        accept_privacy: !!formData.acceptTerms,
        accept_disclaimer: !!formData.acceptTerms,
        accept_aup: !!formData.acceptTerms,
      };

      const response = await authService.register(registrationData);
      const successMessage = response?.data?.message || 'Verification email sent. Please check your inbox to activate your account.';
      setSuccess(successMessage);
      setSubmittedEmail(registrationData.email);
      toast.success(successMessage, { durationMs: 10000 });
      setFormData({ ...initialFormData });
      setCaptchaToken('');
      setTouched({});
      if (typeof window !== 'undefined') {
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
    } catch (err) {
      console.error('Registration error:', err.response?.data);
      const errorMsg = err.response?.data?.errors 
        ? Object.entries(err.response.data.errors).map(([field, msgs]) => `${field}: ${msgs.join(', ')}`).join(' | ')
        : (err.response?.data?.detail || err.response?.data?.error || 'Registration failed. Please try again.');
      setError(errorMsg);
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
          <h2 className="text-2xl font-bold text-white">Create Free Account</h2>
          <p className="text-gray-400 mt-2">Verify your email to unlock dangerous scanners</p>
        </div>

        <div className="ui-card p-8 bg-white/90 dark:bg-gray-900/60 backdrop-blur-xl border border-gray-200/50 dark:border-gray-700/60 hover:bg-white/95 transition-all duration-300">
          {error && (
            <div className="ui-alert ui-alert-error mb-4">
              {error}
            </div>
          )}
          {success ? (
            <div className="space-y-6 text-center" role="status" aria-live="polite">
              <div className="ui-alert ui-alert-success mb-0">
                {success}
              </div>

              {submittedEmail && (
                <p className="text-sm text-gray-600 dark:text-gray-300">
                  We sent the verification link to <span className="font-semibold">{submittedEmail}</span>.
                </p>
              )}

              <p className="text-sm text-gray-600 dark:text-gray-300">
                After you verify your email, you can sign in and start using your workspace.
              </p>

              <div className="flex justify-center">
                <Link to="/login" className="ui-btn ui-btn-ghost justify-center">
                  Go to sign in
                </Link>
              </div>
            </div>
          ) : (
          <>
          <form onSubmit={handleSubmit} noValidate>

            {/* V3.0: Three names required */}
            <div className="grid grid-cols-3 gap-4 mb-4">
              <div>
                <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2 text-sm">First Name *</label>
                <div className="relative">
                  <FiUser className="absolute left-3 top-3 text-gray-400" size={16} />
                  <input
                    type="text"
                    name="first_name"
                    value={formData.first_name}
                    onChange={handleChange}
                    onBlur={() => setTouched((t) => ({ ...t, first_name: true }))}
                    className={`ui-input pl-10 ${touched.first_name && fieldErrors.first_name ? 'ui-input-error' : ''}`}
                    placeholder="John"
                    aria-invalid={touched.first_name && !!fieldErrors.first_name}
                    aria-describedby={touched.first_name && fieldErrors.first_name ? 'register-first-name-error' : undefined}
                  />
                </div>
                <FieldError id="register-first-name-error" message={touched.first_name ? fieldErrors.first_name : null} />
              </div>
              <div>
                <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2 text-sm">Middle Name</label>
                <input
                  type="text"
                  name="middle_name"
                  value={formData.middle_name}
                  onChange={handleChange}
                  className="ui-input"
                  placeholder="M."
                />
              </div>
              <div>
                <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2 text-sm">Last Name *</label>
                <input
                  type="text"
                  name="last_name"
                  value={formData.last_name}
                  onChange={handleChange}
                  onBlur={() => setTouched((t) => ({ ...t, last_name: true }))}
                  className={`ui-input ${touched.last_name && fieldErrors.last_name ? 'ui-input-error' : ''}`}
                  placeholder="Doe"
                  aria-invalid={touched.last_name && !!fieldErrors.last_name}
                  aria-describedby={touched.last_name && fieldErrors.last_name ? 'register-last-name-error' : undefined}
                />
                <FieldError id="register-last-name-error" message={touched.last_name ? fieldErrors.last_name : null} />
              </div>
            </div>

            {/* Email */}
            <div className="mb-4">
              <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">Email *</label>
              <div className="relative">
                <FiMail className="absolute left-3 top-3 text-gray-400" />
                <input
                  type="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  onBlur={() => setTouched((t) => ({ ...t, email: true }))}
                  className={`ui-input pl-10 ${touched.email && fieldErrors.email ? 'ui-input-error' : ''}`}
                  placeholder="your@email.com"
                  aria-invalid={touched.email && !!fieldErrors.email}
                  aria-describedby={touched.email && fieldErrors.email ? 'register-email-error' : undefined}
                />
              </div>
              <FieldError id="register-email-error" message={touched.email ? fieldErrors.email : null} />
            </div>

            {/* Phone */}
            <div className="mb-4">
              <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">Phone</label>
              <div className="relative">
                <FiPhone className="absolute left-3 top-3 text-gray-400" />
                <input
                  type="tel"
                  name="phone"
                  value={formData.phone}
                  onChange={handleChange}
                  onBlur={() => setTouched((t) => ({ ...t, phone: true }))}
                  className={`ui-input pl-10 ${touched.phone && fieldErrors.phone ? 'ui-input-error' : ''}`}
                  placeholder="Phone number"
                  aria-invalid={touched.phone && !!fieldErrors.phone}
                  aria-describedby={touched.phone && fieldErrors.phone ? 'register-phone-error' : undefined}
                />
              </div>
              <FieldError id="register-phone-error" message={touched.phone ? fieldErrors.phone : null} />
            </div>

            {/* Address */}
            <div className="mb-4">
              <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">Address</label>
              <div className="relative">
                <FiMapPin className="absolute left-3 top-3 text-gray-400" />
                <input
                  type="text"
                  name="address"
                  value={formData.address}
                  onChange={handleChange}
                  onBlur={() => setTouched((t) => ({ ...t, address: true }))}
                  className={`ui-input pl-10 ${touched.address && fieldErrors.address ? 'ui-input-error' : ''}`}
                  placeholder="Street, City, Country"
                  aria-invalid={touched.address && !!fieldErrors.address}
                  aria-describedby={touched.address && fieldErrors.address ? 'register-address-error' : undefined}
                />
              </div>
              <FieldError id="register-address-error" message={touched.address ? fieldErrors.address : null} />
            </div>

            {/* Password */}
            <div className="mb-4">
              <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">Password *</label>
              <div className="relative">
                <FiLock className="absolute left-3 top-3 text-gray-400" />
                <input
                  type="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  onBlur={() => setTouched((t) => ({ ...t, password: true }))}
                  className={`ui-input pl-10 ${touched.password && fieldErrors.password ? 'ui-input-error' : ''}`}
                  placeholder="••••••••"
                  aria-invalid={touched.password && !!fieldErrors.password}
                  aria-describedby={touched.password && fieldErrors.password ? 'register-password-error' : undefined}
                />
              </div>
              <FieldError id="register-password-error" message={touched.password ? fieldErrors.password : null} />
            </div>

            {/* Confirm Password */}
            <div className="mb-6">
              <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">Confirm Password *</label>
              <div className="relative">
                <FiLock className="absolute left-3 top-3 text-gray-400" />
                <input
                  type="password"
                  name="confirmPassword"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  onBlur={() => setTouched((t) => ({ ...t, confirmPassword: true }))}
                  className={`ui-input pl-10 ${touched.confirmPassword && fieldErrors.confirmPassword ? 'ui-input-error' : ''}`}
                  placeholder="••••••••"
                  aria-invalid={touched.confirmPassword && !!fieldErrors.confirmPassword}
                  aria-describedby={touched.confirmPassword && fieldErrors.confirmPassword ? 'register-confirm-password-error' : undefined}
                />
              </div>
              <FieldError
                id="register-confirm-password-error"
                message={touched.confirmPassword ? fieldErrors.confirmPassword : null}
              />
            </div>

            {/* Terms and Conditions */}
            <div className="mb-6">
              <label className="flex items-start gap-2">
                <input
                  type="checkbox"
                  name="acceptTerms"
                  checked={formData.acceptTerms}
                  onChange={(e) => setFormData({ ...formData, acceptTerms: e.target.checked })}
                  onBlur={() => setTouched((t) => ({ ...t, acceptTerms: true }))}
                  className="mt-1 w-4 h-4 text-primary border-gray-300 rounded focus:ring-primary"
                  required
                />
                <span className="text-sm text-gray-700 dark:text-gray-200">
                  I accept the{' '}
                  <Link to="/terms" target="_blank" className="text-primary hover:underline font-semibold">
                    Terms of Service
                  </Link>
                  ,{' '}
                  <Link to="/privacy" target="_blank" className="text-primary hover:underline font-semibold">
                    Privacy Policy
                  </Link>
                  ,{' '}
                  <Link to="/disclaimer" target="_blank" className="text-primary hover:underline font-semibold">
                    Disclaimer
                  </Link>
                  {' '}and{' '}
                  <Link to="/aup" target="_blank" className="text-primary hover:underline font-semibold">
                    Acceptable Use Policy
                  </Link>
                  . I confirm that I will use BugBounty Arsenal for legal purposes only. *
                </span>
              </label>
              <FieldError id="register-accept-terms-error" message={touched.acceptTerms ? fieldErrors.acceptTerms : null} />
            </div>

            <TurnstileWidget
              className="mt-4"
              action="signup"
              onToken={(t) => {
                setCaptchaToken(String(t || ''));
                setCaptchaError('');
              }}
              onExpire={() => {
                setCaptchaToken('');
                setCaptchaError('CAPTCHA expired. Please try again.');
              }}
              onError={() => {
                setCaptchaToken('');
                setCaptchaError(
                  'CAPTCHA failed to load. Please disable ad blockers and verify the Turnstile site key and allowed domains for this hostname.'
                );
              }}
            />

            {captchaRequired && captchaError && (
              <div className="text-sm text-red-600 dark:text-red-400 mt-2">
                {captchaError}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || hasErrors || (captchaRequired && !captchaToken)}
              className="ui-btn ui-btn-primary w-full justify-center disabled:opacity-50 disabled:cursor-not-allowed mt-4"
            >
              {loading ? 'Creating account...' : 'Create Free Account'}
            </button>

            <p className="mt-4 text-center text-sm text-gray-600 dark:text-gray-300">
              Dangerous scanners require a verified email.
            </p>
          </form>

          <div className="mt-6 text-center text-sm">
            <span className="text-gray-600 dark:text-gray-300">Already have an account? </span>
            <Link to="/login" className="text-primary font-semibold hover:text-primary-600">
              Sign in
            </Link>
          </div>
          </>
          )}
        </div>
      </div>
    </div>
  );
};

export default Register;
