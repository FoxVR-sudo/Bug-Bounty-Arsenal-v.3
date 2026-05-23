import React, { useMemo, useState } from 'react';
import { FiMail, FiUser, FiMessageSquare, FiSend, FiArrowLeft } from 'react-icons/fi';
import { Link } from 'react-router-dom';
import FieldError from '../components/forms/FieldError';
import { isEmail, isNonEmpty } from '../lib/validation';

const Contact = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    subject: '',
    message: ''
  });
  const [status, setStatus] = useState('');
  const [loading, setLoading] = useState(false);
  const [touched, setTouched] = useState({});

  const fieldErrors = useMemo(() => {
    const next = {};
    if (!isNonEmpty(formData.name)) next.name = 'Name is required.';
    if (!isEmail(formData.email)) next.email = 'Please enter a valid email.';
    if (!isNonEmpty(formData.subject)) next.subject = 'Subject is required.';
    if (!isNonEmpty(formData.message)) next.message = 'Message is required.';
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
    setTouched({ name: true, email: true, subject: true, message: true });
    if (hasErrors) {
      setStatus('error');
      return;
    }
    setLoading(true);
    setStatus('');

    try {
      // TODO: Implement actual email sending via backend API
      // For now, just simulate success
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setStatus('success');
      setFormData({ name: '', email: '', subject: '', message: '' });
    } catch (error) {
      setStatus('error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-950 dark:to-gray-900 py-12 px-4">
      <div className="max-w-5xl mx-auto">
        {/* Back Link */}
        <Link
          to="/"
          className="inline-flex items-center gap-2 text-primary hover:text-primary-600 dark:text-primary-300 dark:hover:text-primary-200 mb-6 transition"
        >
          <FiArrowLeft />
          Back to Home
        </Link>

        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="ui-title text-4xl mb-4">Contact Us</h1>
          <p className="text-lg text-gray-600 dark:text-gray-300">
            Have a question or feedback? We'd love to hear from you.
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-8">
          {/* Contact Form */}
          <div className="ui-card p-8 bg-white/90 dark:bg-gray-900/60 backdrop-blur-xl border border-gray-200/50 dark:border-gray-700/60 shadow-2xl">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">Send us a message</h2>
            
            <form onSubmit={handleSubmit} className="space-y-6" noValidate>
              {/* Name */}
              <div>
                <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">
                  Name *
                </label>
                <div className="relative">
                  <FiUser className="absolute left-3 top-3 text-gray-400" />
                  <input
                    type="text"
                    name="name"
                    value={formData.name}
                    onChange={handleChange}
                    onBlur={() => setTouched((t) => ({ ...t, name: true }))}
                    className={`ui-input pl-10 ${touched.name && fieldErrors.name ? 'ui-input-error' : ''}`}
                    placeholder="John Doe"
                    aria-invalid={touched.name && !!fieldErrors.name}
                    aria-describedby={touched.name && fieldErrors.name ? 'contact-name-error' : undefined}
                  />
                </div>
                <FieldError id="contact-name-error" message={touched.name ? fieldErrors.name : null} />
              </div>

              {/* Email */}
              <div>
                <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">
                  Email *
                </label>
                <div className="relative">
                  <FiMail className="absolute left-3 top-3 text-gray-400" />
                  <input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    onBlur={() => setTouched((t) => ({ ...t, email: true }))}
                    className={`ui-input pl-10 ${touched.email && fieldErrors.email ? 'ui-input-error' : ''}`}
                    placeholder="john@example.com"
                    aria-invalid={touched.email && !!fieldErrors.email}
                    aria-describedby={touched.email && fieldErrors.email ? 'contact-email-error' : undefined}
                  />
                </div>
                <FieldError id="contact-email-error" message={touched.email ? fieldErrors.email : null} />
              </div>

              {/* Subject */}
              <div>
                <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">
                  Subject *
                </label>
                <input
                  type="text"
                  name="subject"
                  value={formData.subject}
                  onChange={handleChange}
                  onBlur={() => setTouched((t) => ({ ...t, subject: true }))}
                  className={`ui-input ${touched.subject && fieldErrors.subject ? 'ui-input-error' : ''}`}
                  placeholder="What's this about?"
                  aria-invalid={touched.subject && !!fieldErrors.subject}
                  aria-describedby={touched.subject && fieldErrors.subject ? 'contact-subject-error' : undefined}
                />
                <FieldError id="contact-subject-error" message={touched.subject ? fieldErrors.subject : null} />
              </div>

              {/* Message */}
              <div>
                <label className="block text-gray-700 dark:text-gray-200 font-semibold mb-2">
                  Message *
                </label>
                <div className="relative">
                  <FiMessageSquare className="absolute left-3 top-3 text-gray-400" />
                  <textarea
                    name="message"
                    value={formData.message}
                    onChange={handleChange}
                    rows="6"
                    onBlur={() => setTouched((t) => ({ ...t, message: true }))}
                    className={`ui-input pl-10 resize-none ${touched.message && fieldErrors.message ? 'ui-input-error' : ''}`}
                    placeholder="Tell us more..."
                    aria-invalid={touched.message && !!fieldErrors.message}
                    aria-describedby={touched.message && fieldErrors.message ? 'contact-message-error' : undefined}
                  />
                </div>
                <FieldError id="contact-message-error" message={touched.message ? fieldErrors.message : null} />
              </div>

              {/* Status Messages */}
              {status === 'success' && (
                <div className="ui-alert ui-alert-success">
                  Message sent successfully! We'll get back to you soon.
                </div>
              )}
              {status === 'error' && (
                <div className="ui-alert ui-alert-error">
                  {hasErrors ? 'Please fix the highlighted fields.' : 'Failed to send message. Please try again later.'}
                </div>
              )}

              {/* Submit Button */}
              <button
                type="submit"
                disabled={loading || hasErrors}
                className="ui-btn ui-btn-primary w-full justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>Sending...</>
                ) : (
                  <>
                    <FiSend />
                    Send Message
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Contact Information */}
          <div className="space-y-6">
            <div className="ui-card p-8 bg-white/90 dark:bg-gray-900/60 backdrop-blur-xl border border-gray-200/50 dark:border-gray-700/60 shadow-2xl hover:shadow-3xl transition-all duration-300">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">Get in Touch</h2>
              
              <div className="space-y-4">
                <div className="flex items-start gap-4">
                  <div className="bg-primary bg-opacity-10 p-3 rounded-lg">
                    <FiMail className="text-primary text-xl" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-900 dark:text-white mb-1">Email</h3>
                    <a 
                      href="mailto:support@bugbounty-arsenal.com"
                      className="text-gray-600 dark:text-gray-300 hover:text-primary dark:hover:text-primary-200 transition"
                    >
                      support@bugbounty-arsenal.com
                    </a>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="bg-primary bg-opacity-10 p-3 rounded-lg">
                    <FiMessageSquare className="text-primary text-xl" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-900 dark:text-white mb-1">Support</h3>
                    <p className="text-gray-600 dark:text-gray-300">
                      We typically respond within 24 hours
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-br from-primary to-primary-600 rounded-xl shadow-lg p-8 text-white">
              <h3 className="text-xl font-bold mb-3">Looking for support?</h3>
              <p className="text-primary-100 mb-4">
                Check out our documentation and FAQ for quick answers to common questions.
              </p>
              <Link 
                to="/dashboard"
                className="ui-btn bg-white text-primary hover:bg-gray-100"
              >
                Go to Dashboard
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Contact;
