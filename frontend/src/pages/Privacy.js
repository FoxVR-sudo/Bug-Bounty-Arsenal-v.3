import React from 'react';
import { Link } from 'react-router-dom';
import { FiArrowLeft, FiLock } from 'react-icons/fi';

const Privacy = () => {
  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-800 to-gray-900">
      {/* Header */}
      <div className="bg-gray-900 border-b border-gray-800">
        <div className="max-w-4xl mx-auto px-4 py-6">
          <Link 
            to="/" 
            className="inline-flex items-center gap-2 text-primary hover:text-primary-600 transition mb-4"
          >
            <FiArrowLeft />
            Back to Home
          </Link>
          <div className="flex items-center gap-3">
            <FiLock className="text-primary text-3xl" />
            <h1 className="text-3xl font-bold text-white">Privacy Policy</h1>
          </div>
          <p className="text-gray-400 mt-2">Last Updated: January 18, 2026</p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-4xl mx-auto px-4 py-12">
        <div className="ui-card ui-card-lg p-8 ui-prose prose-lg">
          
          <h2>1. Introduction</h2>
          <p>
            BugBounty Arsenal ("we", "us", "our") is committed to protecting your privacy. This Privacy Policy 
            explains how we collect, use, disclose, and safeguard your information when you use our Service.
          </p>

          <h2>2. Information We Collect</h2>
          
          <h3>2.1 Registration Information</h3>
          <ul>
            <li><strong>Email address:</strong> For account creation and communication</li>
            <li><strong>Password:</strong> Stored using industry-standard one-way password hashing</li>
            <li><strong>Name:</strong> For personalization</li>
            <li><strong>Phone number:</strong> For SMS verification (optional; only if enabled)</li>
            <li><strong>Address:</strong> For account or organization details when you choose to provide it</li>
          </ul>

          <h3>2.2 Usage Information</h3>
          <ul>
            <li><strong>IP address:</strong> For security, abuse prevention, and service reliability</li>
            <li><strong>Browser information:</strong> Basic client metadata where necessary for security/troubleshooting</li>
            <li><strong>Scan history:</strong> Targets, detectors used, options, and results associated with your account</li>
            <li><strong>Activity logs:</strong> Authentication events and actions performed in the Service</li>
            <li><strong>Cookies:</strong> For session management and analytics</li>
          </ul>

          <h3>2.3 Donation Information</h3>
          <ul>
            <li><strong>Donations:</strong> If you choose to donate, payment data is handled by PayPal (we do not store your card details)</li>
            <li><strong>We DO NOT store:</strong> Credit card numbers or CVV codes</li>
          </ul>

          <h2>3. How We Use Your Information</h2>
          <ul>
            <li>Provide and maintain the Service</li>
            <li>Process donations (if you choose to donate)</li>
            <li>Send SMS verification codes (via Twilio, only if enabled)</li>
            <li>Improve Service quality and features</li>
            <li>Detect and prevent fraud or abuse</li>
            <li>Send important updates and notifications</li>
            <li>Comply with legal obligations</li>
          </ul>

          <h2>4. Data Sharing and Disclosure</h2>
          <p>We share your information with:</p>
          
          <h3>4.1 Service Providers</h3>
          <ul>
            <li><strong>PayPal:</strong> Donations</li>
            <li><strong>Twilio:</strong> SMS verification (only if enabled)</li>
            <li><strong>Cloud providers:</strong> Hosting infrastructure</li>
          </ul>

          <h3>4.2 Legal Requirements</h3>
          <p>We may disclose information if required by law, court order, or government request.</p>

          <h3>4.3 What We DO NOT Do</h3>
          <ul>
            <li>We DO NOT sell your personal information</li>
            <li>We DO NOT rent your data to third parties</li>
            <li>We DO NOT share data for marketing purposes</li>
          </ul>

          <h2>5. Data Retention</h2>
          <ul>
            <li><strong>Scan data:</strong> Retained according to the active retention settings and our data safety policies</li>
            <li><strong>Deleted accounts:</strong> We may retain limited records as required for security, fraud prevention, and legal compliance</li>
            <li><strong>Donation records:</strong> Retained as required by applicable law and payment processor requirements</li>
            <li><strong>Security logs:</strong> Retained for a limited period for incident response and abuse prevention</li>
          </ul>

          <h2>6. Data Security</h2>
          <p>We implement industry-standard security measures:</p>
          <ul>
            <li><strong>Encryption:</strong> SSL/TLS for data in transit</li>
            <li><strong>Password hashing:</strong> bcrypt with salt</li>
            <li><strong>Authentication:</strong> JWT tokens with expiration</li>
            <li><strong>Rate limiting:</strong> Protection against brute force attacks</li>
            <li><strong>Backups:</strong> Encrypted and regularly tested</li>
          </ul>

          <h2>7. Your Rights (GDPR)</h2>
          <p>Under GDPR, you have the right to:</p>
          <ul>
            <li><strong>Access:</strong> Request a copy of your personal data</li>
            <li><strong>Correction:</strong> Update inaccurate or incomplete data</li>
            <li><strong>Deletion:</strong> Request deletion of your data ("right to be forgotten")</li>
            <li><strong>Restriction:</strong> Limit how we process your data</li>
            <li><strong>Portability:</strong> Receive your data in machine-readable format</li>
            <li><strong>Objection:</strong> Object to certain types of processing</li>
            <li><strong>Withdraw consent:</strong> Opt out of optional data processing</li>
          </ul>
          <p>
            To exercise these rights, contact:{' '}
            <a href="mailto:privacy@bugbounty-arsenal.com" className="text-primary hover:underline">
              privacy@bugbounty-arsenal.com
            </a>
          </p>

          <h2>8. Cookies</h2>
          <p>We use the following types of cookies:</p>
          <ul>
            <li><strong>Essential cookies:</strong> Required for Service functionality</li>
            <li><strong>Functional cookies:</strong> Remember your preferences</li>
            <li><strong>Analytical cookies:</strong> Anonymized usage statistics</li>
          </ul>
          <p>You can manage cookies through your browser settings.</p>

          <h2>9. Children's Privacy</h2>
          <p>
            The Service is not intended for users under 18 years old. We do not knowingly collect data 
            from children. If we discover such data, we will delete it immediately.
          </p>

          <h2>10. International Data Transfers</h2>
          <p>
            Your data may be transferred to and processed in countries outside the EU. We ensure adequate 
            protection through Standard Contractual Clauses (SCCs) approved by the European Commission.
          </p>

          <h2>11. Changes to This Policy</h2>
          <p>
            We may update this Privacy Policy periodically. We will notify you of significant changes via 
            email or Service notification.
          </p>

          <h2>12. Contact Us</h2>
          <p>For privacy-related questions or concerns:</p>
          <ul>
            <li>
              <strong>Email:</strong>{' '}
              <a href="mailto:privacy@bugbounty-arsenal.com" className="text-primary hover:underline">
                privacy@bugbounty-arsenal.com
              </a>
            </li>
            <li><strong>Data Protection Officer:</strong> Available upon request</li>
          </ul>

          <div className="bg-blue-50 border-l-4 border-blue-400 p-4 my-6">
            <p className="text-sm text-blue-700">
              <strong>GDPR Compliance:</strong> This Privacy Policy complies with the General Data Protection 
              Regulation (EU) 2016/679 and Bulgarian Personal Data Protection Act.
            </p>
          </div>

          <div className="bg-gray-100 border-l-4 border-gray-400 p-4 my-6">
            <p className="text-sm text-gray-700">
              <strong>Version:</strong> 1.0<br />
              <strong>Effective Date:</strong> January 18, 2026<br />
              <strong>Last Revision:</strong> January 18, 2026
            </p>
          </div>

        </div>
      </div>
    </div>
  );
};

export default Privacy;

