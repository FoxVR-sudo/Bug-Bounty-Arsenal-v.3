import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { FiMail, FiLock, FiShield, FiUser, FiPhone, FiMapPin, FiBriefcase, FiFileText } from 'react-icons/fi';
import EnterprisePaymentForm from '../components/EnterprisePaymentForm';
import api, { authService } from '../services/api';
import TurnstileWidget, { isTurnstileEnabled } from '../components/security/TurnstileWidget';

const RegisterEnterprise = () => {
  const captchaRequired = isTurnstileEnabled();
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [showPaymentForm, setShowPaymentForm] = useState(false);
  const [clientSecret, setClientSecret] = useState('');
  const [captchaToken, setCaptchaToken] = useState('');
  const [captchaError, setCaptchaError] = useState('');
  const [formData, setFormData] = useState({
    // Personal/Account Info
    email: '',
    password: '',
    confirmPassword: '',
    first_name: '',
    middle_name: '',
    last_name: '',
    phone: '',
    
    // Company Info
    company_name: '',
    vat_number: '',
    registration_number: '',
    
    // Billing Address
    billing_address: '',
    billing_city: '',
    billing_country: 'Bulgaria',
    billing_zip: '',
    
    // Billing Contacts
    billing_email: '',
    billing_phone: '',
    accounting_contact_name: '',
    accounting_contact_email: '',
    
    // Payment Terms
    payment_terms: 'net_30',

    // Legal acceptance (required for new registrations)
    acceptTerms: false,
  });
  
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  // Check if user is logged in
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      // Fetch current user data
      api.get('/auth/me/')
      .then(response => {
        setIsLoggedIn(true);
        setCurrentUser(response.data);
        // Pre-fill form with user data
        setFormData(prev => ({
          ...prev,
          email: response.data.email,
          first_name: response.data.first_name || '',
          middle_name: response.data.middle_name || '',
          last_name: response.data.last_name || '',
          phone: response.data.phone || '',
        }));
      })
      .catch(err => {
        console.error('Failed to fetch user:', err);
        setIsLoggedIn(false);
      });
    }
  }, []);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handlePaymentSuccess = () => {
    // Payment completed successfully
    setShowPaymentForm(false);
    navigate('/subscription?payment=success');
  };

  const handlePaymentError = (error) => {
    // Payment failed
    console.error('Payment error:', error);
    setError(error.message || 'Payment failed. Please try again.');
    setShowPaymentForm(false);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!isLoggedIn && captchaRequired && !captchaToken) {
      setError('Please complete the CAPTCHA.');
      return;
    }

    // Validation for new registration only
    if (!isLoggedIn) {
      if (formData.password !== formData.confirmPassword) {
        setError('Passwords do not match');
        return;
      }

      if (formData.password.length < 8) {
        setError('Password must be at least 8 characters');
        return;
      }

      if (!formData.first_name || !formData.last_name) {
        setError('First name and last name are required');
        return;
      }

      if (!/^\+\d{10,15}$/.test(String(formData.phone || '').trim())) {
        setError('Phone must start with "+" and contain 10–15 digits');
        return;
      }

      if (!formData.acceptTerms) {
        setError('You must accept Terms, Privacy, Disclaimer and AUP');
        return;
      }
    }

    if (!formData.company_name) {
      setError('Company name is required');
      return;
    }

    if (!formData.billing_address || !formData.billing_city) {
      setError('Billing address and city are required');
      return;
    }

    setLoading(true);

    try {
      if (isLoggedIn) {
        // UPGRADE MODE: Add enterprise data to existing user
        const response = await api.post('/subscriptions/upgrade-to-enterprise/', {
          // Company info
          company_name: formData.company_name,
          vat_number: formData.vat_number,
          registration_number: formData.registration_number,

          // Billing address
          billing_address: formData.billing_address,
          billing_city: formData.billing_city,
          billing_country: formData.billing_country,
          billing_zip: formData.billing_zip,

          // Billing contacts
          billing_email: formData.billing_email || formData.email,
          billing_phone: formData.billing_phone || formData.phone,
          accounting_contact_name: formData.accounting_contact_name,
          accounting_contact_email: formData.accounting_contact_email,

          // Payment terms
          payment_terms: formData.payment_terms,
        });

        // Check if payment is required (embedded payment)
        if (response.data.requires_payment && response.data.client_secret) {
          setClientSecret(response.data.client_secret);
          setShowPaymentForm(true);
        } else if (response.data.checkout_url) {
          window.location.href = response.data.checkout_url;
        } else {
          navigate('/subscription?upgraded=true');
        }
      } else {
        // NEW REGISTRATION MODE: strict phone verification before account creation
        const startPayload = {
          // Account credentials
          email: formData.email,
          password: formData.password,
          password_confirm: formData.confirmPassword,

          // Personal info
          first_name: formData.first_name,
          middle_name: formData.middle_name,
          last_name: formData.last_name,
          phone: formData.phone,

          // Map billing address to user address for strict flow
          address: formData.billing_address,

          // CAPTCHA
          captcha_token: captchaToken,

          // Legal acceptance
          accept_terms: !!formData.acceptTerms,
          accept_privacy: !!formData.acceptTerms,
          accept_disclaimer: !!formData.acceptTerms,
          accept_aup: !!formData.acceptTerms,

          // Enterprise details (sent again at confirm-phone)
          company_name: formData.company_name,
          vat_number: formData.vat_number,
          registration_number: formData.registration_number,
          billing_address: formData.billing_address,
          billing_city: formData.billing_city,
          billing_country: formData.billing_country,
          billing_zip: formData.billing_zip,
          billing_email: formData.billing_email || formData.email,
          billing_phone: formData.billing_phone || formData.phone,
          accounting_contact_name: formData.accounting_contact_name,
          accounting_contact_email: formData.accounting_contact_email,
          payment_terms: formData.payment_terms,
        };

        const startResponse = await authService.enterpriseRegisterStart(startPayload);
        const token = startResponse.data?.signup_token;

        try {
          sessionStorage.setItem('pending_enterprise_signup', JSON.stringify(startPayload));
        } catch (_) {
          // no-op
        }

        navigate(`/verify-phone?token=${encodeURIComponent(token || '')}&mode=enterprise`);
      }
    } catch (err) {
      setError(err.response?.data?.detail || err.response?.data?.error || 'Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center px-4 py-8">
      <div className="max-w-4xl w-full">
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center gap-2 text-3xl font-bold text-white mb-4">
            <FiShield className="text-primary" />
            BugBounty Arsenal
          </Link>
          <h2 className="text-2xl font-bold text-white">
            {showPaymentForm 
              ? 'Complete Payment'
              : (isLoggedIn ? 'Upgrade to Enterprise' : 'Enterprise Registration')}
          </h2>
          <p className="text-gray-400 mt-2">
            {showPaymentForm
              ? 'Enter your payment details to activate Enterprise plan'
              : (isLoggedIn 
                ? 'Add your company details to upgrade to Enterprise plan'
                : 'Register your company for advanced bug bounty scanning')}
          </p>
        </div>

        <div className="ui-card p-8 bg-white/95 dark:bg-gray-900/60 backdrop-blur-xl border border-gray-200/50 dark:border-gray-700/50 shadow-2xl">
          {error && (
            <div className="ui-alert ui-alert-error mb-4">
              {error}
            </div>
          )}

          {showPaymentForm && clientSecret ? (
            // Show payment form
            <div className="payment-section">
              <h3 className="text-lg font-bold text-gray-900 mb-4">Payment Information</h3>
              <EnterprisePaymentForm
                clientSecret={clientSecret}
                onSuccess={handlePaymentSuccess}
                onError={handlePaymentError}
              />
            </div>
          ) : (
            // Show company registration form
            <>
              {isLoggedIn && currentUser && (
                <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                  <p className="text-sm text-blue-800">
                    <strong>Upgrading as:</strong> {currentUser.email}
                  </p>
                </div>
              )}

              <form onSubmit={handleSubmit}>
            {/* Account Information - Only show for new registrations */}
            {!isLoggedIn && (
            <div className="mb-6">
              <h3 className="text-lg font-bold text-gray-900 mb-4 flex items-center gap-2">
                <FiUser className="text-primary" />
                Account Information
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-gray-700 font-semibold mb-2 text-sm">Email *</label>
                  <div className="relative">
                    <FiMail className="absolute left-3 top-3 text-gray-400" size={16} />
                    <input
                      type="email"
                      name="email"
                      value={formData.email}
                      onChange={handleChange}
                      className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                      placeholder="your@company.com"
                      required
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-gray-700 font-semibold mb-2 text-sm">Phone *</label>
                  <div className="relative">
                    <FiPhone className="absolute left-3 top-3 text-gray-400" size={16} />
                    <input
                      type="tel"
                      name="phone"
                      value={formData.phone}
                      onChange={handleChange}
                      className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                      placeholder="Phone number"
                      required
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-gray-700 font-semibold mb-2 text-sm">First Name *</label>
                  <input
                    type="text"
                    name="first_name"
                    value={formData.first_name}
                    onChange={handleChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    placeholder="John"
                    required
                  />
                </div>

                <div>
                  <label className="block text-gray-700 font-semibold mb-2 text-sm">Last Name *</label>
                  <input
                    type="text"
                    name="last_name"
                    value={formData.last_name}
                    onChange={handleChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    placeholder="Doe"
                    required
                  />
                </div>

                <div>
                  <label className="block text-gray-700 font-semibold mb-2 text-sm">Password *</label>
                  <div className="relative">
                    <FiLock className="absolute left-3 top-3 text-gray-400" size={16} />
                    <input
                      type="password"
                      name="password"
                      value={formData.password}
                      onChange={handleChange}
                      className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                      placeholder="••••••••"
                      required
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-gray-700 font-semibold mb-2 text-sm">Confirm Password *</label>
                  <div className="relative">
                    <FiLock className="absolute left-3 top-3 text-gray-400" size={16} />
                    <input
                      type="password"
                      name="confirmPassword"
                      value={formData.confirmPassword}
                      onChange={handleChange}
                      className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                      placeholder="••••••••"
                      required
                    />
                  </div>
                </div>
              </div>
            </div>
            )}

            {/* Company Information */}
            <div className="mb-6 pt-6 border-t">
              <h3 className="text-lg font-bold text-gray-900 mb-4 flex items-center gap-2">
                <FiBriefcase className="text-primary" />
                Company Information
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="md:col-span-2">
                  <label className="block text-gray-700 font-semibold mb-2 text-sm">Company Name *</label>
                  <input
                    type="text"
                    name="company_name"
                    value={formData.company_name}
                    onChange={handleChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    placeholder="Your Company Ltd."
                    required
                  />
                </div>

                <div>
                  <label className="block text-gray-700 font-semibold mb-2 text-sm">VAT Number</label>
                  <div className="relative">
                    <FiFileText className="absolute left-3 top-3 text-gray-400" size={16} />
                    <input
                      type="text"
                      name="vat_number"
                      value={formData.vat_number}
                      onChange={handleChange}
                      className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                      placeholder="BG123456789"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-gray-700 font-semibold mb-2 text-sm">Registration Number (UIC)</label>
                  <input
                    type="text"
                    name="registration_number"
                    value={formData.registration_number}
                    onChange={handleChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    placeholder="123456789"
                  />
                </div>
              </div>
            </div>

            {/* Billing Address */}
            <div className="mb-6 pt-6 border-t">
              <h3 className="text-lg font-bold text-gray-900 mb-4 flex items-center gap-2">
                <FiMapPin className="text-primary" />
                Billing Address
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="md:col-span-2">
                  <label className="block text-gray-700 font-semibold mb-2 text-sm">Street Address *</label>
                  <input
                    type="text"
                    name="billing_address"
                    value={formData.billing_address}
                    onChange={handleChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    placeholder="123 Main Street"
                    required
                  />
                </div>

                <div>
                  <label className="block text-gray-700 font-semibold mb-2 text-sm">City *</label>
                  <input
                    type="text"
                    name="billing_city"
                    value={formData.billing_city}
                    onChange={handleChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    placeholder="Sofia"
                    required
                  />
                </div>

                <div>
                  <label className="block text-gray-700 font-semibold mb-2 text-sm">ZIP Code</label>
                  <input
                    type="text"
                    name="billing_zip"
                    value={formData.billing_zip}
                    onChange={handleChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    placeholder="1000"
                  />
                </div>

                <div>
                  <label className="block text-gray-700 font-semibold mb-2 text-sm">Country *</label>
                  <input
                    type="text"
                    name="billing_country"
                    value={formData.billing_country}
                    onChange={handleChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    placeholder="Bulgaria"
                    required
                  />
                </div>

                <div>
                  <label className="block text-gray-700 font-semibold mb-2 text-sm">Billing Email</label>
                  <input
                    type="email"
                    name="billing_email"
                    value={formData.billing_email}
                    onChange={handleChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    placeholder="billing@company.com (optional)"
                  />
                  <p className="text-xs text-gray-500 mt-1">If different from account email</p>
                </div>
              </div>
            </div>

            {/* Payment Terms */}
            <div className="mb-6 pt-6 border-t">
              <h3 className="text-lg font-bold text-gray-900 mb-4">Payment Terms</h3>
              <div>
                <label className="block text-gray-700 font-semibold mb-2 text-sm">Payment Terms *</label>
                <select
                  name="payment_terms"
                  value={formData.payment_terms}
                  onChange={handleChange}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                  required
                >
                  <option value="net_15">Net 15 days</option>
                  <option value="net_30">Net 30 days</option>
                  <option value="net_60">Net 60 days</option>
                  <option value="prepaid">Prepaid</option>
                </select>
              </div>
            </div>

            {!isLoggedIn && (
              <div className="mb-6 pt-6 border-t">
                <label className="flex items-start gap-2">
                  <input
                    type="checkbox"
                    name="acceptTerms"
                    checked={formData.acceptTerms}
                    onChange={(e) => setFormData({ ...formData, acceptTerms: e.target.checked })}
                    className="mt-1 w-4 h-4 text-primary border-gray-300 rounded focus:ring-primary"
                    required
                  />
                  <span className="text-sm text-gray-700">
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
                    . I confirm I will only scan systems I own or have explicit permission to test. *
                  </span>
                </label>
              </div>
            )}

            {!isLoggedIn && (
              <TurnstileWidget
                className="mt-4"
                action="signup_enterprise"
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
            )}

            {!isLoggedIn && captchaRequired && captchaError && (
              <div className="text-sm text-red-600 mt-2">
                {captchaError}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || (!isLoggedIn && captchaRequired && !captchaToken)}
              className="w-full px-6 py-3 bg-primary text-white rounded-lg font-semibold hover:bg-primary-600 transition disabled:opacity-50 disabled:cursor-not-allowed mt-4"
            >
              {loading ? 'Creating enterprise account...' : 'Register Enterprise Account'}
            </button>
          </form>

          <div className="mt-6 text-center text-sm">
            <span className="text-gray-600">Individual account? </span>
            <Link to="/register" className="text-primary font-semibold hover:text-primary-600">
              Register as individual
            </Link>
            <span className="text-gray-600 mx-2">|</span>
            <span className="text-gray-600">Already have an account? </span>
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

export default RegisterEnterprise;
